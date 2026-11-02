"""CLI: parse log files and load normalized events into SQLite.

Usage:
    python load_logs.py --auth samples/gen_auth.log --web samples/gen_access.log --year 2026 --reset
"""
import argparse

import db
from parsers import auth, web


def print_summary():
    conn = db.get_connection()

    total = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
    print(f"\nTotal events in database: {total}")

    print("\nEvents by source:")
    for row in conn.execute(
        "SELECT source, COUNT(*) AS n FROM events GROUP BY source ORDER BY n DESC"
    ):
        print(f"  {row['source']:<20} {row['n']}")

    print("\nEvents by type:")
    for row in conn.execute(
        "SELECT event_type, COUNT(*) AS n FROM events GROUP BY event_type ORDER BY n DESC"
    ):
        print(f"  {row['event_type']:<20} {row['n']}")

    print("\nTop source IPs:")
    for row in conn.execute(
        "SELECT src_ip, COUNT(*) AS n FROM events GROUP BY src_ip ORDER BY n DESC, src_ip LIMIT 6"
    ):
        print(f"  {row['src_ip']:<18} {row['n']}")

    print("\nWeb status codes:")
    for row in conn.execute(
        "SELECT status, COUNT(*) AS n FROM events WHERE source = 'web' "
        "GROUP BY status ORDER BY n DESC"
    ):
        print(f"  {row['status']:<20} {row['n']}")

    print("\nSuccess AFTER 5+ failures within 10 min (possible compromise):")
    rows = conn.execute(
        """
        SELECT s.timestamp, s.src_ip, s.user, COUNT(f.id) AS prior_failures
        FROM events AS s
        JOIN events AS f
          ON f.src_ip = s.src_ip
         AND f.event_type = 'ssh_failed_login'
         AND f.timestamp < s.timestamp
         AND f.timestamp >= strftime('%Y-%m-%dT%H:%M:%S', s.timestamp, '-10 minutes')
        WHERE s.event_type = 'ssh_success_login'
        GROUP BY s.id
        HAVING COUNT(f.id) >= 5
        ORDER BY s.timestamp
        """
    ).fetchall()
    if not rows:
        print("  (none)")
    for row in rows:
        print(f"  {row['timestamp']}  {row['src_ip']:<16} user={row['user']:<10} "
              f"prior_failures={row['prior_failures']}")

    conn.close()


def main():
    parser = argparse.ArgumentParser(description="Load logs into MiniSIEM")
    parser.add_argument("--auth", help="path to an auth.log file")
    parser.add_argument("--web", help="path to an nginx/Apache access log")
    parser.add_argument("--host", default="web-server", help="host name to tag web events with")
    parser.add_argument("--year", type=int, help="year for auth.log (default: current)")
    parser.add_argument("--reset", action="store_true", help="delete existing events first")
    args = parser.parse_args()

    db.init_db()
    if args.reset:
        db.reset_events()
        print("Existing events cleared.")

    if args.auth:
        events, total = auth.parse_file(args.auth, args.year)
        inserted = db.insert_events(events)
        print(f"auth.log: read {total} lines, inserted {inserted} events "
              f"({total - inserted} ignored).")

    if args.web:
        events, total = web.parse_file(args.web, args.host)
        inserted = db.insert_events(events)
        print(f"web log:  read {total} lines, inserted {inserted} events "
              f"({total - inserted} ignored).")

    print_summary()


if __name__ == "__main__":
    main()