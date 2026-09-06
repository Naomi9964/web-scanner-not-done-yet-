"""End-to-end tests: real local HTTP requests, actual proxy and backend."""
from http.client import HTTPConnection
import json
import socket
import threading
import time
import unittest
from urllib.parse import urlencode

from app import DemoHandler, MAX_BODY, make_servers


class ObservedBackend(DemoHandler):
    def observe(self):
        self.server.received.append({"path": self.path, "headers": dict(self.headers)})
        self.handle_demo()

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = observe


class WAFTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = make_servers(0, 0, 0, ":memory:")
        cls.backend, cls.proxy, cls.dashboard = cls.servers
        cls.backend.RequestHandlerClass = ObservedBackend
        cls.backend.received = []
        cls.threads = []
        for server in cls.servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cls.threads.append(thread)

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join(timeout=2)
        cls.backend.store.close()

    def wait_record(self, before):
        deadline = time.monotonic() + 1
        while self.proxy.state.snapshot()["totals"]["total"] == before and time.monotonic() < deadline:
            time.sleep(.005)
        self.assertGreater(self.proxy.state.snapshot()["totals"]["total"], before)

    def request(self, path, method="GET", body=None, headers=None, dashboard=False):
        server = self.dashboard if dashboard else self.proxy
        before = self.proxy.state.snapshot()["totals"]["total"]
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=7)
        try:
            connection.request(method, path, body, headers or {})
            response = connection.getresponse()
            result = response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()
        if not dashboard:
            self.wait_record(before)
        return result

    def assert_blocked(self, path, rule, **kwargs):
        before = len(self.backend.received)
        status, headers, body = self.request(path, **kwargs)
        self.assertEqual(status, 403)
        self.assertEqual(headers["X-Mini-WAF"], "blocked")
        self.assertEqual(json.loads(body)["rule"], rule)
        self.assertEqual(len(self.backend.received), before, "Blocked request reached backend")

    def raw_request(self, extra_headers, body=b""):
        before = self.proxy.state.snapshot()["totals"]["total"]
        with socket.create_connection(("127.0.0.1", self.proxy.server_port), timeout=3) as connection:
            request = (f"POST /echo HTTP/1.1\r\nHost: 127.0.0.1:{self.proxy.server_port}\r\n"
                       + extra_headers + "\r\n").encode() + body
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        self.wait_record(before)
        return b"".join(chunks)

    def test_normal_search_preserves_query(self):
        target = "/search?" + urlencode({"q": "hello 台灣", "page": "2"})
        status, headers, body = self.request(target)
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Mini-WAF"], "allowed")
        self.assertEqual(json.loads(body)["query"]["q"], ["hello 台灣"])
        self.assertEqual(self.backend.received[-1]["path"], target)

    def test_ordinary_apostrophe_is_allowed(self):
        self.assertEqual(self.request("/search?" + urlencode({"q": "O'Reilly books"}))[0], 200)

    def test_normal_post_preserves_body(self):
        value = json.dumps({"text": "你好", "count": 5}, ensure_ascii=False).encode()
        status, _, body = self.request("/echo", "POST", value, {"Content-Type": "application/json"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["body"], value.decode())

    def test_sql_injection_variants(self):
        for value in ("' UNION SELECT 1,2 --", "' OR 1=1 --", "' OR 'a'='a'", "UNION/**/SELECT 1", "UN/**/ION SELECT 1"):
            with self.subTest(value=value):
                self.assert_blocked("/search?" + urlencode({"q": value}), "SQLI-001")

    def test_xss_query(self):
        self.assert_blocked("/search?" + urlencode({"q": "<script>alert(1)</script>"}), "XSS-001")

    def test_nested_json_unicode_escape(self):
        body = b'{"profile":{"bio":"\\u003cscript\\u003ealert(1)"}}'
        self.assert_blocked("/echo", "XSS-001", method="POST", body=body,
                            headers={"Content-Type": "application/json"})

    def test_form_body(self):
        self.assert_blocked("/echo", "SQLI-001", method="POST",
                            body=urlencode({"q": "' UNION SELECT 1"}),
                            headers={"Content-Type": "application/x-www-form-urlencoded"})

    def test_traversal_url_and_double_encoding(self):
        for path in ("/search?file=../../demo.txt", "/%2e%2e/demo.txt", "/search?file=%252e%252e%252fdemo.txt"):
            with self.subTest(path=path):
                self.assert_blocked(path, "PATH-001")

    def test_command_injection(self):
        self.assert_blocked("/search?" + urlencode({"q": "hello; whoami"}), "CMD-001")

    def test_selected_header_inspection(self):
        self.assert_blocked("/health", "XSS-001", headers={"User-Agent": "<script>demo"})

    def test_invalid_json_is_rejected(self):
        status, _, body = self.request("/echo", "POST", b'{"bad":', {"Content-Type": "application/json"})
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["rule"], "PAYLOAD")

    def test_body_limit(self):
        response = self.raw_request(f"Content-Length: {MAX_BODY + 1}\r\n")
        self.assertIn(b" 413 ", response.split(b"\r\n")[0])

    def test_ambiguous_framing_never_reaches_backend(self):
        for headers in ("Content-Length: 0\r\nContent-Length: 0\r\n",
                        "Transfer-Encoding: chunked\r\n",
                        "Content-Length: -1\r\n",
                        "Content-Length: 5\r\nContent-Type: text/plain\r\n",
                        "Content-Length: 0\r\nX-Test: folded\r\n continuation\r\n"):
            with self.subTest(headers=headers):
                before = len(self.backend.received)
                response = self.raw_request(headers)
                self.assertIn(b" 400 ", response.split(b"\r\n")[0])
                self.assertEqual(len(self.backend.received), before)

    def test_unsupported_body_types_and_encoding(self):
        self.assertEqual(self.request("/echo", "POST", b"hi", {"Content-Type": "application/octet-stream"})[0], 415)
        self.assertEqual(self.request("/echo", "POST", b"hi", {"Content-Type": "text/plain", "Content-Encoding": "gzip"})[0], 415)

    def test_head_preserves_representation_length(self):
        get_status, get_headers, get_body = self.request("/health")
        head_status, head_headers, head_body = self.request("/health", "HEAD")
        self.assertEqual((get_status, head_status), (200, 200))
        self.assertEqual(head_body, b"")
        self.assertEqual(head_headers["Content-Length"], get_headers["Content-Length"])
        self.assertEqual(int(head_headers["Content-Length"]), len(get_body))

    def test_backend_404_is_allowed(self):
        status, headers, _ = self.request("/missing")
        self.assertEqual(status, 404)
        self.assertEqual(headers["X-Mini-WAF"], "allowed")

    def test_hop_headers_and_forwarded_ip(self):
        self.request("/health", headers={"Connection": "X-Remove", "X-Remove": "private", "X-Forwarded-For": "203.0.113.9"})
        received = {k.lower(): v for k, v in self.backend.received[-1]["headers"].items()}
        self.assertNotIn("x-remove", received)
        self.assertEqual(received["x-forwarded-for"], "127.0.0.1")

    def test_fixed_upstream_and_method_rejection(self):
        before = len(self.backend.received)
        self.assertEqual(self.request("http://example.invalid/")[0], 400)
        self.assertEqual(self.request("/", "CONNECT")[0], 405)
        self.assertEqual(len(self.backend.received), before)

    def test_dashboard_is_separate_and_host_checked(self):
        self.assertEqual(self.request("/api/stats")[0], 404)
        self.assertEqual(self.request("/api/stats", dashboard=True)[0], 200)
        self.assertEqual(self.request("/api/stats", headers={"Host": "example.invalid"}, dashboard=True)[0], 403)
        self.assertEqual(self.request("/", dashboard=True)[0], 200)

    def test_home_and_scanner_routes_are_english_and_linked(self):
        status, _, home = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn(b'href="/scanner"', home)
        self.assertIn(b"See the signals", home)
        status, _, scanner = self.request("/scanner")
        self.assertEqual(status, 200)
        self.assertIn(b"Run website check", scanner)
        self.assertIn(b"CATEGORY SCORES", scanner)
        self.assertIn(b'href="/"', scanner)
        status, _, inspector = self.request("/inspector")
        self.assertEqual(status, 200)
        self.assertIn(b"Broken Link Checker", inspector)
        self.assertIn(b'href="/inspector"', home)
        status, _, security = self.request("/security-analysis")
        self.assertEqual(status, 200)
        self.assertIn(b"CSP Policy Analyzer", security)
        self.assertIn(b'href="/security-analysis"', home)
        for page in (home, scanner, inspector, security):
            self.assertIsNone(__import__("re").search(rb"[\xe4-\xe9][\x80-\xbf]{2}", page))

    def test_history_report_and_json_export(self):
        report = {"ok": True, "checked_at": "2026-01-02T03:04:05+00:00",
                  "final_url": "https://example.com/", "score": 88, "risk": "low"}
        scan_id = self.backend.store.save(report)
        status, _, history = self.request("/api/history")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(history)["scans"][0]["id"], scan_id)
        status, headers, saved = self.request(f"/api/report/{scan_id}?download=1")
        self.assertEqual(status, 200)
        self.assertIn("attachment", headers["Content-Disposition"])
        self.assertEqual(json.loads(saved)["score"], 88)
        self.assertEqual(self.request("/history")[0], 200)

    def test_scanner_rejects_private_target(self):
        body = json.dumps({"url": "http://127.0.0.1/health"}).encode()
        status, headers, result = self.request("/api/scan", "POST", body,
                                                {"Content-Type": "application/json"})
        self.assertEqual(status, 400)
        self.assertEqual(headers["X-Mini-WAF"], "allowed")
        self.assertFalse(json.loads(result)["ok"])
        status, headers, result = self.request("/api/security-scan", "POST", body,
                                               {"Content-Type": "application/json"})
        self.assertEqual(status, 400)
        self.assertEqual(headers["X-Mini-WAF"], "allowed")
        self.assertFalse(json.loads(result)["ok"])

    def test_logs_do_not_store_query_body_or_secrets(self):
        self.request("/echo?token=private-query-value", "POST", b'private-body-value',
                     {"Content-Type": "text/plain", "Authorization": "Bearer private-auth-value", "Cookie": "session=private-cookie-value"})
        data = self.request("/api/stats", dashboard=True)[2].decode()
        for secret in ("private-query-value", "private-body-value", "private-auth-value", "private-cookie-value"):
            self.assertNotIn(secret, data)

    def test_upstream_failure_is_error_not_allowed(self):
        original = self.proxy.backend_port
        # Reserve an unlistened port to obtain a predictable connection refusal.
        with socket.socket() as unused:
            unused.bind(("127.0.0.1", 0))
            self.proxy.backend_port = unused.getsockname()[1]
            try:
                self.assertEqual(self.request("/health")[0], 502)
                self.assertEqual(self.proxy.state.snapshot()["events"][0]["action"], "error")
            finally:
                self.proxy.backend_port = original

    def test_stats_consistency(self):
        self.request("/health")
        data = json.loads(self.request("/api/stats", dashboard=True)[2])
        totals = data["totals"]
        self.assertEqual(totals["total"], totals["allowed"] + totals["blocked"] + totals["error"])
        self.assertEqual(sum(data["categories"].values()), totals["blocked"])
        self.assertEqual(len(data["traffic"]), 60)


if __name__ == "__main__":
    unittest.main(verbosity=2)
