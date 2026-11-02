"""Detection engine: loads YAML rules, finds bursts of matching events, stores alerts.

Run from the project root:
    python -m engine.matcher
"""
import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

import yaml

import db

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
SEVERITIES = ("low", "medium", "high", "critical")
REQUIRED_KEYS = ("id", "name", "severity", "match", "group_by", "threshold", "window")
DURATION_RE = re.compile(r"^(\d+)\s*([smhd])$")
UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class RuleError(Exception):
    """Raised when a YAML rule file is invalid. The message says what to fix."""


# --------------------------------------------------------------------------
# 1. Loading and validating rules
# --------------------------------------------------------------------------
def parse_duration(text):
    """'30s' -> 30, '5m' -> 300, '2h' -> 7200, '1d' -> 86400."""
    m = DURATION_RE.match(str(text).strip())
    if not m:
        raise RuleError(f"bad duration {text!r} (use a number plus s/m/h/d, e.g. '5m')")
    return int(m.group(1)) * UNIT_SECONDS[m.group(2)]


def validate_rule(rule, filename):
    """Check a rule dict and add helper fields. Raises RuleError on any problem."""
    if not isinstance(rule, dict):
        raise RuleError(f"{filename}: file must contain a YAML mapping (key: value pairs)")

    missing = [k for k in REQUIRED_KEYS if k not in rule]
    if missing:
        raise RuleError(f"{filename}: missing required field(s): {', '.join(missing)}")

    if rule["severity"] not in SEVERITIES:
        raise RuleError(f"{filename}: severity must be one of {SEVERITIES}, got {rule['severity']!r}")

    if not isinstance(rule["threshold"], int) or rule["threshold"] < 1:
        raise RuleError(f"{filename}: threshold must be a whole number >= 1")

    if isinstance(rule["group_by"], str):
        rule["group_by"] = [rule["group_by"]]

    # SECURITY: column names get pasted into SQL (they can't use ? placeholders),
    # so we only allow names from our own whitelist, never arbitrary text from YAML.
    allowed = set(db.COLUMNS)
    if not isinstance(rule["match"], dict) or not rule["match"]:
        raise RuleError(f"{filename}: 'match' must be a non-empty mapping")
    columns_used = list(rule["match"]) + list(rule["group_by"])
    if rule.get("distinct"):
        columns_used.append(rule["distinct"])
    for col in columns_used:
        if col not in allowed:
            raise RuleError(f"{filename}: unknown field {col!r}. Valid fields: {', '.join(db.COLUMNS)}")

    rule["window_seconds"] = parse_duration(rule["window"])
    rule.setdefault("mitre", {})
    rule.setdefault("description", "")
    return rule


def load_rules(rules_dir=RULES_DIR):
    """Read every *.yaml file in the folder. Returns a list of validated rule dicts."""
    rules, seen_ids = [], set()
    for path in sorted(Path(rules_dir).glob("*.yaml")):
        with open(path) as f:
            data = yaml.safe_load(f)      # safe_load: never yaml.load (it can run code)
        rule = validate_rule(data, path.name)
        if rule["id"] in seen_ids:
            raise RuleError(f"{path.name}: duplicate rule id {rule['id']!r}")
        seen_ids.add(rule["id"])
        rules.append(rule)
    return rules


# --------------------------------------------------------------------------
# 2. Finding bursts
# --------------------------------------------------------------------------
def fetch_events(conn, rule):
    """Get all events matching the rule's `match` section, oldest first."""
    clauses, params = [], []
    for column, wanted in rule["match"].items():
        values = wanted if isinstance(wanted, list) else [wanted]
        # `column` is safe (whitelisted in validate_rule); `values` go through ?.
        clauses.append(f"{column} IN ({', '.join('?' for _ in values)})")
        params.extend(values)
    sql = "SELECT * FROM events WHERE " + " AND ".join(clauses) + " ORDER BY timestamp, id"
    return conn.execute(sql, params).fetchall()


def group_events(events, group_by):
    """Split events into groups, e.g. one group per (src_ip, user) pair."""
    groups = {}
    for event in events:
        key = tuple(event[col] for col in group_by)
        if any(part is None for part in key):    # can't group on a missing field
            continue
        groups.setdefault(key, []).append(event)
    return groups


def count_metric(events, distinct=None):
    """What we compare against the threshold: event count, or distinct values of a field."""
    if distinct:
        return len({e[distinct] for e in events if e[distinct] is not None})
    return len(events)


def detect_bursts(events, window_seconds, threshold, distinct=None):
    """Sliding-window detection on ONE group of time-sorted events.

    Returns a list of bursts: {"events": [...], "metric": number}.
    A burst starts when the metric inside any `window_seconds` span reaches
    `threshold`, and keeps growing while events keep arriving within one window
    of each other. That gives ONE alert per attack instead of one per event.
    """
    times = [datetime.fromisoformat(e["timestamp"]) for e in events]
    n = len(events)
    bursts = []
    left = right = 0

    while right < n:
        # Move `left` forward until everything in [left..right] fits inside the window.
        while (times[right] - times[left]).total_seconds() > window_seconds:
            left += 1

        if count_metric(events[left:right + 1], distinct) >= threshold:
            # Threshold reached: extend the burst while the attack continues.
            end = right + 1
            while end < n and (times[end] - times[end - 1]).total_seconds() <= window_seconds:
                end += 1
            burst_events = events[left:end]
            bursts.append({"events": burst_events, "metric": count_metric(burst_events, distinct)})
            left = right = end          # start fresh after this burst
        else:
            right += 1
    return bursts


# --------------------------------------------------------------------------
# 3. Turning bursts into alerts
# --------------------------------------------------------------------------
def build_alert(rule, key, burst):
    events = burst["events"]
    group_key = ", ".join(f"{col}={val}" for col, val in zip(rule["group_by"], key))
    unit = f"distinct {rule['distinct']} values" if rule.get("distinct") else "events"
    mitre = rule["mitre"]
    return {
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "severity": rule["severity"],
        "mitre_id": mitre.get("id"),
        "mitre_name": mitre.get("name"),
        "mitre_tactic": mitre.get("tactic"),
        "src_ip": events[0]["src_ip"],
        "group_key": group_key,
        "first_seen": events[0]["timestamp"],
        "last_seen": events[-1]["timestamp"],
        "event_count": len(events),
        "summary": (f"{burst['metric']} {unit} for {group_key} "
                    f"(threshold {rule['threshold']} within {rule['window']})"),
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }


def run_detection(db_path=db.DB_PATH, rules_dir=RULES_DIR):
    """Run every rule over every event. Replaces all stored alerts. Returns the alerts."""
    rules = load_rules(rules_dir)
    conn = db.get_connection(db_path)
    db.reset_alerts(conn)

    all_alerts = []
    for rule in rules:
        events = fetch_events(conn, rule)
        for key, group in group_events(events, rule["group_by"]).items():
            for burst in detect_bursts(group, rule["window_seconds"],
                                       rule["threshold"], rule.get("distinct")):
                alert = build_alert(rule, key, burst)
                alert["id"] = db.insert_alert(conn, alert, [e["id"] for e in burst["events"]])
                all_alerts.append(alert)

    conn.commit()
    conn.close()
    return rules, all_alerts


def main():
    parser = argparse.ArgumentParser(description="Run MiniSIEM detection rules")
    parser.add_argument("--rules", default=str(RULES_DIR), help="folder with *.yaml rules")
    args = parser.parse_args()

    db.init_db()
    try:
        rules, alerts = run_detection(rules_dir=args.rules)
    except RuleError as err:
        print(f"Rule error: {err}")
        sys.exit(1)

    print(f"Loaded {len(rules)} rules: {', '.join(r['id'] for r in rules)}")
    print(f"Generated {len(alerts)} alerts\n")
    print(f"{'ID':<4} {'RULE':<9} {'SEV':<7} {'SRC IP':<16} {'EVENTS':<7} {'FIRST SEEN':<20} GROUP")
    for a in alerts:
        print(f"{a['id']:<4} {a['rule_id']:<9} {a['severity']:<7} {a['src_ip']:<16} "
              f"{a['event_count']:<7} {a['first_seen']:<20} {a['group_key']}")


if __name__ == "__main__":
    main()