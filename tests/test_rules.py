"""Tests for the REAL rule files in rules/. This is detection engineering:
every rule gets known-bad inputs (must match) and known-good inputs (must not)."""
import tempfile
import unittest
from pathlib import Path

import db
from engine.matcher import load_rules, matches_regex, run_detection
from parsers import auth, web

ROOT = Path(__file__).resolve().parent.parent
GEN_AUTH = ROOT / "samples" / "gen_auth.log"
GEN_WEB = ROOT / "samples" / "gen_access.log"

RULES = {r["id"]: r for r in load_rules()}

SQLI_PAYLOADS = [
    "/products?id=1' OR '1'='1",
    "/products?id=1 UNION SELECT username,password FROM users--",
    "/products?id=1; DROP TABLE users--",
    "/products?id=1' AND SLEEP(5)--",
    "/products?id=' OR 1=1--",
    "/products?id=1 UNION ALL SELECT NULL,NULL,NULL--",
    "/products?id=1' ORDER BY 10--",
    "/products?id=admin'--",
    "/products?id=1 AND (SELECT COUNT(*) FROM information_schema.tables)>0",
]
XSS_PAYLOADS = [
    "/search?q=<script>alert(1)</script>",
    '/search?q="><img src=x onerror=alert(1)>',
    "/search?q=<svg onload=alert(1)>",
    "/search?q=javascript:alert(document.cookie)",
    "/search?q=<iframe src=javascript:alert(1)>",
]
BENIGN_PATHS = [
    "/", "/index.html", "/about", "/products", "/products?id=1", "/products?id=3",
    "/login", "/contact", "/static/app.js", "/api/items", "/search?q=laptop",
    "/search?q=phone", "/search?q=laptop and phone", "/search?q=select a phone",
    "/search?q=union station", "/blog/how-to-order-by-mail", "/search?q=it's here",
]


def hits(rule_id, path):
    return matches_regex({"path": path}, RULES[rule_id]["compiled_regex"])


class TestSqliRule(unittest.TestCase):
    def test_every_known_payload_matches(self):
        for p in SQLI_PAYLOADS:
            self.assertTrue(hits("WEB-002", p), f"missed: {p}")

    def test_benign_paths_do_not_match(self):
        for p in BENIGN_PATHS:
            self.assertFalse(hits("WEB-002", p), f"false positive: {p}")


class TestXssRule(unittest.TestCase):
    def test_every_known_payload_matches(self):
        for p in XSS_PAYLOADS:
            self.assertTrue(hits("WEB-003", p), f"missed: {p}")

    def test_benign_paths_do_not_match(self):
        for p in BENIGN_PATHS:
            self.assertFalse(hits("WEB-003", p), f"false positive: {p}")

    def test_rules_do_not_cross_fire(self):
        for p in SQLI_PAYLOADS:
            self.assertFalse(hits("WEB-003", p), f"XSS rule fired on SQLi: {p}")
        for p in XSS_PAYLOADS:
            self.assertFalse(hits("WEB-002", p), f"SQLi rule fired on XSS: {p}")


class TestAllRulesAreTagged(unittest.TestCase):
    def test_every_rule_has_mitre(self):
        self.assertEqual(len(RULES), 5)
        for rule in RULES.values():
            self.assertTrue(rule["mitre"]["id"].startswith("T"), rule["id"])


class TestRealRulesOnSampleData(unittest.TestCase):
    """Run ALL real rules over the generated logs: exactly the 5 planted attackers
    must alert, and nothing else (the false-positive check)."""

    @unittest.skipUnless(GEN_AUTH.exists() and GEN_WEB.exists(),
                         "run `python samples/generate_logs.py` first")
    def test_only_planted_attacks_alert(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "t.db"
            db.init_db(db_path)
            db.insert_events(auth.parse_file(GEN_AUTH, 2026)[0], db_path)
            db.insert_events(web.parse_file(GEN_WEB)[0], db_path)
            _, alerts = run_detection(db_path)
            found = {(a["rule_id"], a["src_ip"]) for a in alerts}
            self.assertEqual(found, {
                ("SSH-001", "203.0.113.50"),
                ("SSH-002", "198.51.100.7"),
                ("WEB-001", "192.0.2.66"),
                ("WEB-002", "203.0.113.99"),
                ("WEB-003", "198.51.100.200"),
            })


if __name__ == "__main__":
    unittest.main()