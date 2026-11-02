import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import db
from engine.matcher import (RuleError, detect_bursts, load_rules, matches_regex,
                            parse_duration, run_detection, validate_rule)

BASE = datetime(2026, 11, 1, 10, 0, 0)


def make_events(offsets, user="root", ip="203.0.113.50"):
    """Build fake events `offsets` seconds after BASE (plain dicts work like DB rows)."""
    return [
        {"timestamp": (BASE + timedelta(seconds=s)).isoformat(),
         "user": user, "src_ip": ip}
        for s in offsets
    ]


def valid_rule(**overrides):
    rule = {"id": "T-1", "name": "t", "severity": "high",
            "mitre": {"id": "T1110.001", "name": "Brute Force", "tactic": "Credential Access"},
            "match": {"event_type": "ssh_failed_login"},
            "group_by": ["src_ip"], "threshold": 5, "window": "1m"}
    rule.update(overrides)
    return rule


class TestParseDuration(unittest.TestCase):
    def test_units(self):
        self.assertEqual(parse_duration("30s"), 30)
        self.assertEqual(parse_duration("5m"), 300)
        self.assertEqual(parse_duration("2h"), 7200)
        self.assertEqual(parse_duration("1d"), 86400)

    def test_bad_values(self):
        for bad in ("5", "m5", "five minutes", "", "-5m"):
            with self.assertRaises(RuleError):
                parse_duration(bad)


class TestDetectBursts(unittest.TestCase):
    def test_below_threshold(self):
        self.assertEqual(detect_bursts(make_events([0, 1, 2, 3]), 60, 5), [])

    def test_exactly_threshold(self):
        bursts = detect_bursts(make_events([0, 1, 2, 3, 4]), 60, 5)
        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0]["metric"], 5)

    def test_events_spread_outside_window(self):
        # 5 events but 100s apart: never 5 inside one 60s window
        self.assertEqual(detect_bursts(make_events([0, 100, 200, 300, 400]), 60, 5), [])

    def test_one_alert_per_attack_not_per_event(self):
        bursts = detect_bursts(make_events(range(0, 200, 2)), 10, 5)   # 100 events
        self.assertEqual(len(bursts), 1)
        self.assertEqual(len(bursts[0]["events"]), 100)

    def test_two_separate_attacks(self):
        offsets = list(range(0, 10)) + list(range(1000, 1010))
        self.assertEqual(len(detect_bursts(make_events(offsets), 60, 5)), 2)

    def test_distinct_counts_unique_values(self):
        spray = make_events(range(5))
        for i, e in enumerate(spray):
            e["user"] = f"user{i}"
        self.assertEqual(len(detect_bursts(spray, 60, 5, distinct="user")), 1)

    def test_distinct_ignores_repeats_of_same_value(self):
        same_user = make_events(range(10))          # 10 events, but 1 distinct user
        self.assertEqual(detect_bursts(same_user, 60, 5, distinct="user"), [])


class TestValidation(unittest.TestCase):
    def test_valid_rule_gets_window_seconds(self):
        self.assertEqual(validate_rule(valid_rule(), "t.yaml")["window_seconds"], 60)

    def test_group_by_string_becomes_list(self):
        self.assertEqual(validate_rule(valid_rule(group_by="src_ip"), "t.yaml")["group_by"], ["src_ip"])

    def test_missing_field(self):
        rule = valid_rule()
        del rule["threshold"]
        with self.assertRaises(RuleError):
            validate_rule(rule, "t.yaml")

    def test_bad_severity(self):
        with self.assertRaises(RuleError):
            validate_rule(valid_rule(severity="urgent"), "t.yaml")

    def test_unknown_column_is_rejected(self):
        # protects the SQL built from rule files
        with self.assertRaises(RuleError):
            validate_rule(valid_rule(match={"1=1; DROP TABLE events; --": "x"}), "t.yaml")

    def test_bad_threshold(self):
        with self.assertRaises(RuleError):
            validate_rule(valid_rule(threshold=0), "t.yaml")


class TestMitreAndRegexValidation(unittest.TestCase):
    def test_mitre_is_required(self):
        rule = valid_rule()
        del rule["mitre"]
        with self.assertRaises(RuleError):
            validate_rule(rule, "t.yaml")

    def test_mitre_needs_all_three_parts(self):
        with self.assertRaises(RuleError):
            validate_rule(valid_rule(mitre={"id": "T1110"}), "t.yaml")

    def test_mitre_id_format(self):
        for bad in ("1110", "T11", "T1110.1", "ATT&CK"):
            with self.assertRaises(RuleError):
                validate_rule(valid_rule(mitre={"id": bad, "name": "x", "tactic": "y"}), "t.yaml")

    def test_bad_regex_is_rejected_at_load_time(self):
        with self.assertRaises(RuleError):
            validate_rule(valid_rule(regex={"path": ["(unclosed"]}), "t.yaml")

    def test_regex_unknown_field_rejected(self):
        with self.assertRaises(RuleError):
            validate_rule(valid_rule(regex={"nonsense": ["x"]}), "t.yaml")


class TestMatchesRegex(unittest.TestCase):
    def compiled(self, **regex):
        return validate_rule(valid_rule(regex=regex), "t.yaml")["compiled_regex"]

    def test_no_regex_means_everything_passes(self):
        self.assertTrue(matches_regex({"path": "/anything"}, {}))

    def test_any_pattern_in_a_field_matches(self):          # OR within a field
        c = self.compiled(path=["union", "sleep"])
        self.assertTrue(matches_regex({"path": "/x?id=sleep(5)"}, c))
        self.assertFalse(matches_regex({"path": "/about"}, c))

    def test_all_fields_must_match(self):                    # AND across fields
        c = self.compiled(path=["admin"], user_agent=["sqlmap"])
        self.assertTrue(matches_regex({"path": "/admin", "user_agent": "sqlmap/1.7"}, c))
        self.assertFalse(matches_regex({"path": "/admin", "user_agent": "Firefox"}, c))

    def test_case_insensitive(self):
        c = self.compiled(path=["union select"])
        self.assertTrue(matches_regex({"path": "1 UnIoN SeLeCt 1"}, c))

    def test_null_field_never_matches(self):
        c = self.compiled(user_agent=["curl"])
        self.assertFalse(matches_regex({"user_agent": None}, c))


class TestEndToEnd(unittest.TestCase):
    def test_full_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            rules_dir = Path(tmp) / "rules"
            rules_dir.mkdir()
            (rules_dir / "r.yaml").write_text(
                "id: T-1\nname: Test brute force\nseverity: high\n"
                "mitre: {id: T1110.001, name: Brute Force, tactic: Credential Access}\n"
                "match: {event_type: ssh_failed_login}\n"
                "group_by: [src_ip, user]\nthreshold: 20\nwindow: 1m\n"
            )
            db.init_db(db_path)

            def ev(sec, ip):
                return {"timestamp": (BASE + timedelta(seconds=sec)).isoformat(),
                        "source": "auth.log", "host": "h", "user": "root", "src_ip": ip,
                        "event_type": "ssh_failed_login", "raw": f"line {sec}"}

            events = [ev(s, "203.0.113.50") for s in range(25)]       # attacker
            events += [ev(s, "192.168.1.20") for s in range(3)]       # a typo-prone admin
            db.insert_events(events, db_path)

            rules, alerts = run_detection(db_path, rules_dir)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]["src_ip"], "203.0.113.50")
            self.assertEqual(alerts[0]["event_count"], 25)
            self.assertEqual(alerts[0]["mitre_id"], "T1110.001")

            conn = db.get_connection(db_path)
            evidence = conn.execute("SELECT COUNT(*) AS n FROM alert_events").fetchone()["n"]
            conn.close()
            self.assertEqual(evidence, 25)

            # Running detection again must replace alerts, not duplicate them
            _, again = run_detection(db_path, rules_dir)
            conn = db.get_connection(db_path)
            total = conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]
            conn.close()
            self.assertEqual(total, 1)

    def test_duplicate_rule_ids_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("a.yaml", "b.yaml"):
                (Path(tmp) / name).write_text(
                    "id: DUP\nname: x\nseverity: low\nmitre: {id: T1110, name: x, tactic: y}\n"
                    "match: {event_type: x}\n"
                    "group_by: [src_ip]\nthreshold: 1\nwindow: 1m\n")
            with self.assertRaises(RuleError):
                load_rules(tmp)


if __name__ == "__main__":
    unittest.main()