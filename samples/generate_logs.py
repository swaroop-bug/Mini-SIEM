"""Generate fake-but-realistic logs for testing MiniSIEM.

Creates samples/gen_auth.log and samples/gen_access.log containing normal
traffic plus 5 planted attacks. random.seed makes the output identical on
every run, so your detection results are reproducible.

Usage:  python samples/generate_logs.py
"""
import random
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote

random.seed(42)

OUT_DIR = Path(__file__).parent
START = datetime(2026, 11, 1, 0, 0, 0)   # logs cover Nov 1, 2026
HOST = "ubuntu-vm"
VALID_USERS = {"root", "swaroop", "deploy", "ubuntu"}  # accounts that really exist


def at(hour, minute=0, second=0):
    """Shortcut: a datetime on the log day."""
    return START + timedelta(hours=hour, minutes=minute, seconds=second)


def rand_time():
    """A random moment during the day."""
    return START + timedelta(seconds=random.randint(0, 86399))


# --------------------------------------------------------------------------
# auth.log generation. Every function returns a list of (datetime, line).
# --------------------------------------------------------------------------
def syslog_ts(dt):
    return f"{dt:%b} {dt.day:>2} {dt:%H:%M:%S}"      # "Nov  1 10:15:32"


def sshd(dt, msg, pid):
    return (dt, f"{syslog_ts(dt)} {HOST} sshd[{pid}]: {msg}")


def failed_attempt(dt, user, ip):
    """One failed SSH attempt, the way sshd logs it."""
    pid, port = random.randint(1000, 30000), random.randint(30000, 65000)
    lines = []
    if user in VALID_USERS:
        lines.append(sshd(dt, f"Failed password for {user} from {ip} port {port} ssh2", pid))
    else:   # unknown account: sshd logs an extra "Invalid user" line first
        lines.append(sshd(dt, f"Invalid user {user} from {ip} port {port}", pid))
        lines.append(sshd(dt + timedelta(seconds=1),
                          f"Failed password for invalid user {user} from {ip} port {port} ssh2", pid))
    return lines


def accepted(dt, user, ip):
    pid, port = random.randint(1000, 30000), random.randint(30000, 65000)
    return [sshd(dt, f"Accepted password for {user} from {ip} port {port} ssh2", pid)]


def normal_auth():
    """Legit admins logging in, sometimes with a typo first, plus cron/sudo noise."""
    out = []
    for _ in range(40):
        dt = rand_time()
        user = random.choice(["swaroop", "deploy"])
        ip = random.choice(["192.168.1.20", "192.168.1.21", "10.0.0.5"])
        if random.random() < 0.15:                       # fat-fingered password
            out += failed_attempt(dt - timedelta(seconds=6), user, ip)
        out += accepted(dt, user, ip)
        out.append(sshd(dt + timedelta(minutes=random.randint(5, 90)),
                        f"Connection closed by {ip} port 50000", random.randint(1000, 30000)))
    for hour in range(24):                               # hourly cron
        dt = at(hour, 0, 1)
        out.append((dt, f"{syslog_ts(dt)} {HOST} CRON[{random.randint(1000, 30000)}]: "
                        f"pam_unix(cron:session): session opened for user root"))
    for _ in range(10):                                  # sudo usage
        dt = rand_time()
        out.append((dt, f"{syslog_ts(dt)} {HOST} sudo:  swaroop : TTY=pts/0 ; "
                        f"PWD=/home/swaroop ; USER=root ; COMMAND=/bin/ls"))
    return out


def brute_force(start, ip, attempts=150):
    """Attack 1: one IP hammers a few accounts every 2 seconds, then gets in."""
    out = []
    for i in range(attempts):
        user = random.choice(["root", "root", "root", "admin", "ubuntu"])
        out += failed_attempt(start + timedelta(seconds=2 * i), user, ip)
    out += accepted(start + timedelta(seconds=2 * attempts + 1), "root", ip)
    return out


def password_spray(start, ip):
    """Attack 2: one IP, MANY usernames, only 2 tries each (stays under per-user limits)."""
    users = ["admin", "test", "oracle", "postgres", "mysql", "ftp", "guest", "user",
             "ubuntu", "deploy", "git", "jenkins", "www-data", "support", "info", "pi",
             "ansible", "backup", "dev", "demo", "nagios", "tomcat", "vagrant", "swaroop", "root"]
    out = []
    for i, user in enumerate(users):
        for attempt in range(2):
            out += failed_attempt(start + timedelta(seconds=50 * i + 20 * attempt), user, ip)
    return out


def background_noise():
    """Random internet scanners: 1-2 attempts each. Must NOT trigger alerts."""
    out = []
    ips = {f"198.18.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(15)}
    for ip in ips:
        for _ in range(random.randint(1, 2)):
            out += failed_attempt(rand_time(), random.choice(["admin", "test", "user", "root"]), ip)
    return out


# --------------------------------------------------------------------------
# access log generation (nginx/Apache combined format)
# --------------------------------------------------------------------------
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]
PAGES = ["/", "/index.html", "/about", "/products", "/products?id=1", "/products?id=2",
         "/products?id=3", "/login", "/contact", "/static/app.js", "/static/style.css",
         "/api/items", "/search?q=laptop", "/search?q=phone"]


def web(dt, ip, method, path, status, ua, size=None):
    size = size if size is not None else (196 if status == 404 else random.randint(300, 20000))
    stamp = f"{dt:%d/%b/%Y:%H:%M:%S} +0530"
    return (dt, f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"')


def normal_web(requests=500):
    """Regular visitors: mostly 200s, rare 404s."""
    ips = [f"192.0.2.{n}" for n in range(10, 30)]
    out = []
    for _ in range(requests):
        status = random.choices([200, 304, 404, 500], weights=[90, 6, 3, 1])[0]
        out.append(web(rand_time(), random.choice(ips), "GET", random.choice(PAGES),
                       status, random.choice(BROWSERS)))
    return out


def web_scanner(start, ip, count=120):
    """Attack 3: a Nikto-style scanner guessing hidden paths -> a wall of 404s."""
    words = ["admin", "administrator", ".env", ".git/config", "wp-login", "wp-admin",
             "phpmyadmin", "backup", "config", "server-status", "console", "login",
             "test", "old", "db", "robots", "cgi-bin/test", "upload", "shell", ".htaccess",
             "setup", "install", "dump", "api/v1/users", "manager/html"]
    paths = [f"/{w}{s}" for w in words for s in ("", ".php", ".bak", ".old", "/")]
    random.shuffle(paths)
    out = []
    for i, path in enumerate(paths[:count]):
        status = 404 if random.random() < 0.95 else 403
        out.append(web(start + timedelta(seconds=i), ip, "GET", path, status, "Nikto/2.5.0"))
    return out


def sqli_attack(start, ip, count=30):
    """Attack 4: sqlmap-style injection attempts, some URL-encoded, some raw."""
    payloads = ["1' OR '1'='1", "1 UNION SELECT username,password FROM users--",
                "1; DROP TABLE users--", "1' AND SLEEP(5)--", "' OR 1=1--",
                "1 UNION ALL SELECT NULL,NULL,NULL--", "1' ORDER BY 10--", "admin'--",
                "1 AND (SELECT COUNT(*) FROM information_schema.tables)>0"]
    out = []
    for i in range(count):
        p = random.choice(payloads)
        encoded = quote(p) if random.random() < 0.6 else p.replace(" ", "+")
        status = random.choices([200, 500], weights=[75, 25])[0]
        out.append(web(start + timedelta(seconds=3 * i), ip, "GET",
                       f"/products?id={encoded}", status,
                       "sqlmap/1.7.11#stable (https://sqlmap.org)"))
    return out


def xss_attack(start, ip, count=12):
    """Attack 5: reflected XSS probes sent with a normal-looking browser UA."""
    payloads = ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>',
                "<svg onload=alert(1)>", "javascript:alert(document.cookie)",
                "<iframe src=javascript:alert(1)>"]
    ua = BROWSERS[0]
    return [web(start + timedelta(seconds=7 * i), ip, "GET",
                f"/search?q={quote(random.choice(payloads))}", 200, ua)
            for i in range(count)]


def write_sorted(entries, filename):
    entries.sort(key=lambda pair: pair[0])      # chronological, like a real log
    path = OUT_DIR / filename
    path.write_text("\n".join(line for _, line in entries) + "\n")
    print(f"wrote {path.name}: {len(entries)} lines")


if __name__ == "__main__":
    auth = normal_auth() + background_noise()
    auth += brute_force(at(3, 12), "203.0.113.50")
    auth += password_spray(at(9, 40), "198.51.100.7")
    write_sorted(auth, "gen_auth.log")

    access = normal_web()
    access += web_scanner(at(14, 20), "192.0.2.66")
    access += sqli_attack(at(16, 5), "203.0.113.99")
    access += xss_attack(at(18, 30), "198.51.100.200")
    write_sorted(access, "gen_access.log")