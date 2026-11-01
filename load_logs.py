"""CLI: parse log files and load normalized events into SQLite.

Usage:
    python load_logs.py --auth samples/auth.log --reset
"""
import argparse

import db
from parsers import auth


def print_summary():
    conn = db.get_connection()
    print("\nEvents by type:")
    for row in conn.execute(
        "SELECT event_type, COUNT(*) AS n FROM events GROUP BY event_type ORDER BY n DESC"
    ):
        print(f"  {row['event_type']:<20} {row['n']}")
    print("\nTop source IPs:")
    for row in conn.execute(
        "SELECT src_ip, COUNT(*) AS n FROM events GROUP BY src_ip ORDER BY n DESC LIMIT 5"
    ):
        print(f"  {row['src_ip']:<18} {row['n']}")
    conn.close()


def main():
    parser = argparse.ArgumentParser(description="Load logs into MiniSIEM")
    parser.add_argument("--auth", help="path to an auth.log file")
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

    print_summary()


if __name__ == "__main__":
    main()