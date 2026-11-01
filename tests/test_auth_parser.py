import unittest

from parsers.auth import parse_line

YEAR = 2026


class TestAuthParser(unittest.TestCase):
    def test_failed_password_valid_user(self):
        line = "Nov  1 10:15:35 ubuntu-vm sshd[2413]: Failed password for root from 203.0.113.50 port 41024 ssh2"
        e = parse_line(line, YEAR)
        self.assertEqual(e["event_type"], "ssh_failed_login")
        self.assertEqual(e["user"], "root")
        self.assertEqual(e["src_ip"], "203.0.113.50")
        self.assertEqual(e["timestamp"], "2026-11-01T10:15:35")
        self.assertEqual(e["host"], "ubuntu-vm")

    def test_failed_password_invalid_user(self):
        line = "Nov  1 10:15:33 ubuntu-vm sshd[2411]: Failed password for invalid user admin from 203.0.113.50 port 41022 ssh2"
        e = parse_line(line, YEAR)
        self.assertEqual(e["event_type"], "ssh_failed_login")
        self.assertEqual(e["user"], "admin")

    def test_accepted_login(self):
        line = "Nov  1 10:02:15 ubuntu-vm sshd[2310]: Accepted password for swaroop from 192.168.1.20 port 51234 ssh2"
        e = parse_line(line, YEAR)
        self.assertEqual(e["event_type"], "ssh_success_login")
        self.assertEqual(e["user"], "swaroop")

    def test_invalid_user_line(self):
        line = "Nov  1 10:15:32 ubuntu-vm sshd[2411]: Invalid user admin from 203.0.113.50 port 41022"
        e = parse_line(line, YEAR)
        self.assertEqual(e["event_type"], "ssh_invalid_user")

    def test_non_sshd_lines_are_ignored(self):
        line = "Nov  1 10:00:01 ubuntu-vm CRON[2201]: pam_unix(cron:session): session opened for user root"
        self.assertIsNone(parse_line(line, YEAR))

    def test_garbage_is_ignored(self):
        self.assertIsNone(parse_line("this is not a log line", YEAR))


if __name__ == "__main__":
    unittest.main()