from email.message import Message
import socket
import unittest

from sitelens.url_scan import (ScanError, accessibility_score, analyze_csp,
                               analyze_response, detect_technologies,
                               dns_email_security, page_quality, performance_score,
                               scan_url, seo_audit, third_party_supply_chain,
                               tls_domain_score, validate_target)


def resolver_for(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return lambda host, port, **kwargs: [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))]


def headers(**values):
    message = Message()
    for key, value in values.items():
        message[key.replace("_", "-")] = value
    return message


class URLValidationTests(unittest.TestCase):
    def test_adds_https_and_normalizes_fragment(self):
        result = validate_target("Example.COM/docs?q=1#private", resolver_for("93.184.216.34"))
        self.assertEqual(result[0], "https://example.com/docs?q=1")

    def test_only_http_https(self):
        for value in ("file:///etc/passwd", "ftp://example.com/file", "javascript:alert(1)"):
            with self.subTest(value=value), self.assertRaises(ScanError):
                validate_target(value, resolver_for("93.184.216.34"))

    def test_rejects_credentials_and_nonstandard_ports(self):
        for value in ("https://user:pass@example.com", "https://example.com:8443"):
            with self.subTest(value=value), self.assertRaises(ScanError):
                validate_target(value, resolver_for("93.184.216.34"))

    def test_rejects_every_non_public_dns_answer(self):
        addresses = ["127.0.0.1", "10.1.2.3", "192.168.1.2", "169.254.1.1",
                     "0.0.0.0", "224.0.0.1", "::1", "fc00::1", "fe80::1"]
        for address in addresses:
            with self.subTest(address=address), self.assertRaises(ScanError):
                validate_target("https://example.test", resolver_for(address))

    def test_dns_rebinding_mix_is_rejected(self):
        def resolver(host, port, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        with self.assertRaises(ScanError):
            validate_target("https://example.test", resolver)


class ResponseAnalysisTests(unittest.TestCase):
    def test_page_quality_extracts_accessibility_and_navigation_signals(self):
        body = b'<html lang="en"><head><title>Demo</title><meta name="viewport" content="width=device-width"><meta name="description" content="Demo page"></head><body><a href="/about">About</a><img src="x.png"><img src="y.png" alt=""></body></html>'
        result = page_quality(body, "text/html")
        self.assertEqual(result["score"], 80)
        self.assertEqual(result["links"], ["/about"])
        self.assertEqual(result["checks"][-1]["state"], "warn")

    def test_strong_headers_score_high(self):
        values = headers(
            Content_Type="text/html", Strict_Transport_Security="max-age=31536000",
            Content_Security_Policy="default-src 'self'; frame-ancestors 'none'",
            X_Content_Type_Options="nosniff", Referrer_Policy="strict-origin-when-cross-origin",
            Permissions_Policy="camera=(), microphone=()")
        result = analyze_response("https://example.com/", "https://example.com/", 200,
                                  values, b"<h1>Safe</h1>", False, {}, [], 12.5)
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["risk"], "low")
        self.assertGreaterEqual(result["summary"]["passed"], 7)
        self.assertEqual(set(result["categories"]),
                         {"security", "page_quality", "accessibility", "performance"})

    def test_accessibility_checks_language_alt_labels_and_headings(self):
        body = (b'<html lang="en"><body><h1>Account</h1><h2>Details</h2>'
                b'<img src="avatar.png" alt="Profile"><label for="email">Email</label>'
                b'<input id="email"></body></html>')
        result = accessibility_score(body, "text/html")
        self.assertEqual(result["score"], 100)
        self.assertTrue(all(item["state"] == "pass" for item in result["checks"]))

    def test_performance_score_uses_time_size_and_redirects(self):
        fast = performance_score(900, 50 * 1024, False, [])
        slow = performance_score(6000, 385 * 1024, True, [{}, {}, {}])
        self.assertEqual(fast["score"], 100)
        self.assertEqual(slow["score"], 0)

    def test_tls_domain_score_combines_https_certificate_and_dns(self):
        result = tls_domain_score("https://example.com/", {"days_remaining": 60},
                                  ["93.184.216.34"])
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["status"], "good")

    def test_seo_audit_reviews_metadata_headings_and_social_preview(self):
        body = (b'<html><head><title>A useful page title</title>'
                b'<meta name="description" content="A detailed description that gives search users a useful preview of this example page.">'
                b'<meta property="og:title" content="Title"><meta property="og:description" content="Description">'
                b'<meta property="og:image" content="image.jpg"><link rel="canonical" href="https://example.com/">'
                b'</head><body><h1>Example</h1></body></html>')
        result = seo_audit(body, "text/html")
        self.assertEqual(result["score"], 100)

    def test_detects_common_public_technology_fingerprints(self):
        values = headers(Content_Type="text/html", Server="cloudflare")
        body = b'<script src="/_next/app.js"></script><link href="bootstrap.min.css">'
        result = detect_technologies(values, body, "text/html")
        names = {item["name"] for item in result["detected"]}
        self.assertTrue({"Next.js", "Bootstrap", "Cloudflare"}.issubset(names))

    def test_csp_analyzer_scores_restrictive_policy(self):
        result = analyze_csp("default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
        self.assertEqual(result["score"], 100)
        self.assertTrue(all(item["state"] == "pass" for item in result["checks"]))

    def test_supply_chain_maps_external_resources_and_controls(self):
        body = (b'<script src="https://cdn.example.net/app.js"></script>'
                b'<link rel="stylesheet" href="http://styles.example.net/site.css">'
                b'<iframe src="https://video.example.net/embed"></iframe>')
        result = third_party_supply_chain(body, "text/html", "https://example.com/")
        self.assertEqual(result["external_count"], 3)
        self.assertEqual(result["without_sri"], 2)
        self.assertEqual(result["insecure_count"], 1)
        self.assertEqual(result["unsandboxed_iframes"], 1)

    def test_dns_email_security_uses_public_policy_records(self):
        def lookup(name, record_type):
            answers = {
                ("example.com", "TXT"): ["v=spf1 -all"],
                ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
                ("example.com", "MX"): ["10 mail.example.com."],
                ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"],
                ("_mta-sts.example.com", "TXT"): ["v=STSv1; id=1"],
                ("_smtp._tls.example.com", "TXT"): ["v=TLSRPTv1; rua=mailto:reports@example.com"],
            }.get((name, record_type), [])
            return {"status": 0, "authenticated": name == "example.com", "answers": answers}
        result = dns_email_security("www.example.com", lookup)
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["score"], 100)
        self.assertTrue(result["spf"])
        self.assertTrue(result["dmarc"])

    def test_missing_headers_and_http_lower_score(self):
        result = analyze_response("http://example.com/", "http://example.com/", 200,
                                  headers(Content_Type="text/html", Server="Demo/1.0"),
                                  b"<html></html>", False, None, [], 3)
        self.assertLess(result["score"], 55)
        self.assertEqual(result["risk"], "high")

    def test_cookie_and_mixed_content_warnings(self):
        values = headers(Content_Type="text/html", Strict_Transport_Security="max-age=1",
                         Content_Security_Policy="frame-ancestors 'none'",
                         X_Content_Type_Options="nosniff", Referrer_Policy="no-referrer",
                         Permissions_Policy="camera=()")
        values.add_header("Set-Cookie", "session=abc")
        result = analyze_response("https://example.com/", "https://example.com/", 200,
                                  values, b'<img src="http://cdn.example/a.png">', False,
                                  {}, [], 2)
        by_key = {item["key"]: item for item in result["checks"]}
        self.assertEqual(by_key["cookies"]["state"], "warn")
        self.assertEqual(by_key["mixed"]["state"], "warn")

    def test_redirect_to_private_target_is_never_requested(self):
        calls = []
        def resolver(host, port, **kwargs):
            address = "127.0.0.1" if host == "127.0.0.1" else "93.184.216.34"
            return resolver_for(address)(host, port, **kwargs)
        def requester(url, host, port, addresses):
            calls.append(url)
            return 302, headers(Location="http://127.0.0.1/admin"), b"", False, {}
        with self.assertRaises(ScanError):
            scan_url("https://example.test", resolver, requester)
        self.assertEqual(calls, ["https://example.test/"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
