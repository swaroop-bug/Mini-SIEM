import unittest

from parsers.web import parse_line

NORMAL = ('192.0.2.15 - - [01/Nov/2026:10:15:32 +0530] "GET /products?id=2 HTTP/1.1" '
          '200 5123 "-" "Mozilla/5.0 (X11; Linux x86_64) Firefox/132.0"')
NOT_FOUND = ('192.0.2.66 - - [01/Nov/2026:14:20:05 +0530] "GET /.env HTTP/1.1" '
             '404 196 "-" "Nikto/2.5.0"')
SQLI = ('203.0.113.99 - - [01/Nov/2026:16:05:03 +0530] '
        '"GET /products?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1" 500 310 "-" '
        '"sqlmap/1.7.11#stable (https://sqlmap.org)"')
SQLI_PLUS = ('203.0.113.99 - - [01/Nov/2026:16:05:06 +0530] '
             '"GET /products?id=1+UNION+SELECT+username,password+FROM+users-- HTTP/1.1" '
             '200 310 "-" "sqlmap/1.7.11"')
LOGGED_IN = ('10.0.0.5 - alice [01/Nov/2026:09:00:00 +0530] "POST /login HTTP/1.1" '
             '302 0 "https://example.com/login" "Mozilla/5.0"')
COMMON_FORMAT = '10.0.0.9 - - [01/Nov/2026:09:00:00 +0530] "GET / HTTP/1.1" 200 512'


class TestWebParser(unittest.TestCase):
    def test_normal_request(self):
        e = parse_line(NORMAL)
        self.assertEqual(e["source"], "web")
        self.assertEqual(e["event_type"], "web_request")
        self.assertEqual(e["src_ip"], "192.0.2.15")
        self.assertEqual(e["method"], "GET")
        self.assertEqual(e["path"], "/products?id=2")
        self.assertEqual(e["status"], 200)
        self.assertIn("Firefox", e["user_agent"])
        self.assertIsNone(e["user"])               # "-" becomes None

    def test_timestamp_drops_timezone(self):
        self.assertEqual(parse_line(NORMAL)["timestamp"], "2026-11-01T10:15:32")

    def test_404(self):
        e = parse_line(NOT_FOUND)
        self.assertEqual(e["status"], 404)
        self.assertEqual(e["path"], "/.env")
        self.assertEqual(e["user_agent"], "Nikto/2.5.0")

    def test_url_encoded_payload_is_decoded(self):
        e = parse_line(SQLI)
        self.assertEqual(e["path"], "/products?id=1' OR '1'='1")
        self.assertIn("%27", e["raw"])             # raw keeps the original encoding

    def test_plus_becomes_space(self):
        e = parse_line(SQLI_PLUS)
        self.assertIn("UNION SELECT", e["path"])

    def test_authenticated_user(self):
        self.assertEqual(parse_line(LOGGED_IN)["user"], "alice")

    def test_common_format_without_user_agent(self):
        e = parse_line(COMMON_FORMAT)
        self.assertEqual(e["status"], 200)
        self.assertIsNone(e["user_agent"])

    def test_host_is_configurable(self):
        self.assertEqual(parse_line(NORMAL, host="web01")["host"], "web01")

    def test_garbage_is_ignored(self):
        self.assertIsNone(parse_line("this is not an access log line"))


if __name__ == "__main__":
    unittest.main()