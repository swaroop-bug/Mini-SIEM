"""Parser for Apache/nginx access logs (combined format) -> normalized event dicts."""
import re
from datetime import datetime
from urllib.parse import unquote_plus

# Combined log format:
# 203.0.113.5 - alice [01/Nov/2026:10:15:32 +0530] "GET /a?b=1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"
LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>.+?) HTTP/[\d.]+" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
)


def parse_line(line, host="web-server"):
    """Turn one access-log line into an event dict, or None if it doesn't match."""
    m = LOG_RE.match(line.strip())
    if not m:
        return None

    # "01/Nov/2026:10:15:32 +0530" -> datetime. We drop the timezone so web events
    # use the same "local time as written" style as auth.log (limitation: assumes
    # both logs come from the same timezone).
    ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)

    user = m["user"] if m["user"] != "-" else None
    ua = m["ua"] if m["ua"] not in (None, "-") else None

    return {
        "timestamp": ts.isoformat(),
        "source": "web",
        "host": host,
        "user": user,
        "src_ip": m["ip"],
        "event_type": "web_request",
        "raw": line.strip(),
        "method": m["method"],
        # Attackers URL-encode payloads (%27 = '), so we decode for detection.
        # The original, still-encoded request stays in `raw`.
        "path": unquote_plus(m["path"]),
        "status": int(m["status"]),
        "user_agent": ua,
    }


def parse_file(path, host="web-server"):
    """Parse a whole file. Returns (events, total_lines_read)."""
    events = []
    total = 0
    with open(path, "r", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            total += 1
            event = parse_line(line, host)
            if event:
                events.append(event)
    return events, total                