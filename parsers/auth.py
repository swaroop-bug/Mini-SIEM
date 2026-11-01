"""Parser for Linux auth.log (SSH events) -> normalized event dicts."""
import re
from datetime import datetime

# Matches the syslog prefix:  Nov  1 10:15:32 ubuntu-vm sshd[1234]: <message>
SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

# The three SSH message types we care about
FAILED_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port \d+"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)
INVALID_RE = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)")


def parse_line(line, year):
    """Turn one auth.log line into an event dict, or None if we don't care about it."""
    match = SYSLOG_RE.match(line.strip())
    if not match:
        return None

    parts = match.groupdict()
    if parts["proc"] != "sshd":      # ignore sudo, CRON, etc.
        return None

    msg = parts["msg"]
    if (m := FAILED_RE.search(msg)):
        event_type = "ssh_failed_login"
    elif (m := ACCEPTED_RE.search(msg)):
        event_type = "ssh_success_login"
    elif (m := INVALID_RE.search(msg)):
        event_type = "ssh_invalid_user"
    else:
        return None

    # auth.log has no year, so we supply one.
    ts = datetime.strptime(
        f"{year} {parts['month']} {parts['day']} {parts['time']}",
        "%Y %b %d %H:%M:%S",
    )

    return {
        "timestamp": ts.isoformat(),
        "source": "auth.log",
        "host": parts["host"],
        "user": m.group("user"),
        "src_ip": m.group("ip"),
        "event_type": event_type,
        "raw": line.strip(),
    }


def parse_file(path, year=None):
    """Parse a whole file. Returns (events, total_lines_read)."""
    year = year or datetime.now().year
    events = []
    total = 0
    with open(path, "r", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            total += 1
            event = parse_line(line, year)
            if event:
                events.append(event)
    return events, total