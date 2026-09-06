"""Bounded, SSRF-resistant checks for a public website's HTTP security posture."""

from datetime import datetime, timezone
from email.message import Message
from http.client import HTTPConnection, HTTPSConnection, HTTPException
from html.parser import HTMLParser
import ipaddress
import json
import re
import socket
import ssl
import time
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

MAX_URL = 2048
MAX_DOWNLOAD = 384 * 1024
MAX_REDIRECTS = 5
TIMEOUT = 7


class ScanError(ValueError):
    pass


def _public_addresses(host, port, resolver=socket.getaddrinfo):
    try:
        records = resolver(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ScanError("The domain could not be resolved. Check the URL or DNS configuration.") from exc
    addresses = []
    for family, _, _, _, sockaddr in records:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        address = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
        # Reject the whole target if any DNS answer could reach a non-public network.
        if (not address.is_global or address.is_multicast or address.is_unspecified
                or address.is_reserved or address.is_private or address.is_loopback
                or address.is_link_local):
            raise ScanError("Safety restriction: local, private, reserved, and special-use IP addresses are blocked.")
        if str(address) not in addresses:
            addresses.append(str(address))
    if not addresses:
        raise ScanError("The domain has no usable public IP address.")
    # Trying at most two addresses keeps the scan time bounded.
    return addresses[:2]


def validate_target(raw_url, resolver=socket.getaddrinfo):
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ScanError("Enter a URL to scan.")
    value = raw_url.strip()
    if "://" not in value:
        value = "https://" + value
    if len(value) > MAX_URL or any(ord(char) < 32 for char in value):
        raise ScanError("The URL is invalid or longer than 2,048 characters.")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise ScanError("The URL contains an invalid host or port.") from exc
    if parts.scheme.lower() not in {"http", "https"}:
        raise ScanError("Only http:// and https:// URLs are supported.")
    if parts.username is not None or parts.password is not None:
        raise ScanError("The URL must not contain a username or password.")
    if not parts.hostname:
        raise ScanError("The URL is missing a domain name.")
    expected_port = 443 if parts.scheme.lower() == "https" else 80
    if port not in (None, expected_port):
        raise ScanError("Safety restriction: only HTTP port 80 and HTTPS port 443 are allowed.")
    host = parts.hostname.rstrip(".").lower()
    if not host or len(host) > 253:
        raise ScanError("The domain name is invalid.")
    try:
        host.encode("idna")
    except UnicodeError as exc:
        raise ScanError("The domain name is invalid.") from exc
    addresses = _public_addresses(host, expected_port, resolver)
    display_host = f"[{host}]" if ":" in host else host
    netloc = display_host
    path = parts.path or "/"
    normalized = urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))
    return normalized, host, expected_port, addresses


class PinnedHTTPConnection(HTTPConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port, timeout=timeout)
        self.address = address

    def connect(self):
        self.sock = socket.create_connection((self.address, self.port), self.timeout,
                                             self.source_address)


class PinnedHTTPSConnection(HTTPSConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        raw_socket = socket.create_connection((self.address, self.port), self.timeout,
                                              self.source_address)
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)


def _request(url, host, port, addresses):
    parts = urlsplit(url)
    target = urlunsplit(("", "", parts.path or "/", parts.query, ""))
    last_error = None
    for address in addresses:
        connection_class = PinnedHTTPSConnection if parts.scheme == "https" else PinnedHTTPConnection
        connection = connection_class(host, port, address, TIMEOUT)
        try:
            connection.request("GET", target, headers={
                "Host": host,
                "User-Agent": "Mini-WAF-Risk-Checker/1.0",
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.2",
                "Accept-Encoding": "identity",
                "Connection": "close",
            })
            certificate = connection.sock.getpeercert() if parts.scheme == "https" and connection.sock else None
            response = connection.getresponse()
            body = response.read(MAX_DOWNLOAD + 1)
            return response.status, response.headers, body[:MAX_DOWNLOAD], len(body) > MAX_DOWNLOAD, certificate
        except (OSError, ssl.SSLError, HTTPException) as exc:
            last_error = exc
        finally:
            connection.close()
    if isinstance(last_error, ssl.SSLError):
        raise ScanError("TLS certificate validation failed or a secure connection could not be established.") from last_error
    raise ScanError("The target could not be reached. It may have timed out, refused the connection, or returned an unsupported response.") from last_error


def _header(headers, name):
    return headers.get(name, "").strip()


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.in_title = False
        self.lang = ""
        self.description = ""
        self.robots = ""
        self.viewport = ""
        self.open_graph = set()
        self.links = []
        self.images = 0
        self.images_without_alt = 0
        self.canonical = ""
        self.labels_for = set()
        self.controls = []
        self.heading_levels = []
        self.h1_count = 0
        self.resources = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "html": self.lang = values.get("lang", "")
        if tag == "title": self.in_title = True
        if tag == "meta" and values.get("name", "").lower() == "description": self.description = values.get("content", "")
        if tag == "meta" and values.get("name", "").lower() == "robots": self.robots = values.get("content", "")
        if tag == "meta" and values.get("property", "").lower().startswith("og:"): self.open_graph.add(values.get("property", "").lower())
        if tag == "meta" and values.get("name", "").lower() == "viewport": self.viewport = values.get("content", "")
        if tag == "link" and "canonical" in values.get("rel", "").lower().split(): self.canonical = values.get("href", "")
        if tag == "a" and values.get("href") and len(self.links) < 100: self.links.append(values["href"])
        resource_url = ""
        resource_type = tag
        if tag in {"script", "iframe"}: resource_url = values.get("src", "")
        if tag == "link" and "stylesheet" in values.get("rel", "").lower().split(): resource_url = values.get("href", "")
        if resource_url and len(self.resources) < 100:
            self.resources.append({"type": resource_type, "url": resource_url,
                                   "integrity": bool(values.get("integrity")),
                                   "sandbox": "sandbox" in values})
        if tag == "label" and values.get("for"): self.labels_for.add(values["for"])
        if tag in {"input", "select", "textarea"} and values.get("type", "").lower() != "hidden":
            self.controls.append((values.get("id", ""), bool(values.get("aria-label") or values.get("aria-labelledby") or values.get("title"))))
        if re.fullmatch(r"h[1-6]", tag):
            self.heading_levels.append(int(tag[1]))
            if tag == "h1": self.h1_count += 1
        if tag == "img":
            self.images += 1
            if "alt" not in values: self.images_without_alt += 1

    def handle_endtag(self, tag):
        if tag == "title": self.in_title = False

    def handle_data(self, data):
        if self.in_title and len(self.title) < 300: self.title += data


def page_quality(body, content_type):
    if "html" not in content_type.lower():
        return {"available": False, "score": None, "checks": [], "links": []}
    parser = PageParser()
    parser.feed(body.decode("utf-8", errors="ignore"))
    items = [
        ("Page title", bool(parser.title.strip()), "A descriptive title helps users and search engines identify the page."),
        ("Meta description", bool(parser.description.strip()), "Add a concise meta description for search previews."),
        ("Language declaration", bool(parser.lang.strip()), "Declare the document language on the html element."),
        ("Mobile viewport", bool(parser.viewport.strip()), "Add a viewport meta tag for responsive layouts."),
        ("Canonical URL", bool(parser.canonical.strip()), "Declare a canonical URL when duplicate page URLs are possible."),
    ]
    checks = [{"title": title, "state": "pass" if passed else "warn", "detail": detail}
              for title, passed, detail in items]
    return {"available": True, "score": round(sum(item[1] for item in items) / len(items) * 100),
            "checks": checks, "links": parser.links}


def seo_audit(body, content_type):
    if "html" not in content_type.lower():
        return {"available": False, "score": None, "checks": []}
    parser = PageParser()
    parser.feed(body.decode("utf-8", errors="ignore"))
    title_length = len(parser.title.strip())
    description_length = len(parser.description.strip())
    robots = parser.robots.lower()
    social_fields = {"og:title", "og:description", "og:image"}
    items = [
        ("Search title", 10 <= title_length <= 60,
         f"The title contains {title_length} characters; a useful target is 10–60."),
        ("Meta description", 50 <= description_length <= 160,
         f"The description contains {description_length} characters; a useful target is 50–160."),
        ("Primary heading", parser.h1_count == 1,
         f"The page contains {parser.h1_count} h1 element(s); use one clear primary heading."),
        ("Canonical URL", bool(parser.canonical.strip()),
         "A canonical link helps search engines identify the preferred page URL."),
        ("Indexability", "noindex" not in robots,
         "The page does not declare noindex." if "noindex" not in robots else "The robots meta tag asks search engines not to index this page."),
        ("Social preview", social_fields.issubset(parser.open_graph),
         f"Found {len(social_fields & parser.open_graph)} of 3 core Open Graph fields."),
    ]
    checks = [{"title": title, "state": "pass" if passed else "warn", "detail": detail}
              for title, passed, detail in items]
    return {"available": True, "score": round(sum(item[1] for item in items) / len(items) * 100),
            "checks": checks}


def detect_technologies(headers, body, content_type):
    if "html" not in content_type.lower():
        return {"available": False, "detected": []}
    html = body.decode("utf-8", errors="ignore")
    lower = html.lower()
    detected = []

    def add(name, evidence):
        if not any(item["name"].casefold() == name.casefold() for item in detected):
            detected.append({"name": name, "evidence": evidence})

    signatures = [
        ("WordPress", ("wp-content/", "wp-includes/"), "WordPress asset path"),
        ("Next.js", ("__next_data__", "/_next/"), "Next.js page marker"),
        ("React", ("data-reactroot", "react-dom"), "React page marker"),
        ("Vue.js", ("data-v-", "vue.js", "vue.min.js"), "Vue page marker"),
        ("Angular", ("ng-version", "ng-app"), "Angular page marker"),
        ("Bootstrap", ("bootstrap.css", "bootstrap.min.css", "bootstrap.bundle"), "Bootstrap asset"),
        ("jQuery", ("jquery.js", "jquery.min.js", "jquery-"), "jQuery asset"),
    ]
    for name, needles, evidence in signatures:
        if any(needle in lower for needle in needles):
            add(name, evidence)
    server = _header(headers, "Server")
    powered = _header(headers, "X-Powered-By")
    if server:
        server_name = server.split("/", 1)[0].strip() or "Web server"
        if server_name.casefold() == "cloudflare":
            server_name = "Cloudflare"
        add(server_name, f"Server header: {server[:100]}")
    if powered:
        add(powered.split("/", 1)[0].strip() or "Application platform",
            f"X-Powered-By header: {powered[:100]}")
    if _header(headers, "CF-Ray") or "cloudflare" in server.lower():
        add("Cloudflare", "Cloudflare response header")
    return {"available": True, "detected": detected,
            "note": "Technology detection uses public response fingerprints and may not identify every framework."}


def analyze_csp(policy):
    directives = {}
    for part in policy.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]
    script = directives.get("script-src", directives.get("default-src", []))
    items = [
        ("CSP header", bool(policy), "A Content-Security-Policy response header is present."
         if policy else "No Content-Security-Policy response header was found."),
        ("Default source policy", "default-src" in directives,
         "Use default-src as a fallback for resource types."),
        ("Inline script restriction", bool(script) and "'unsafe-inline'" not in script,
         "Avoid 'unsafe-inline' in script sources; use nonces or hashes instead."),
        ("Dynamic code restriction", bool(script) and "'unsafe-eval'" not in script,
         "Avoid 'unsafe-eval' because it permits string-to-code execution."),
        ("Plugin restriction", directives.get("object-src") in (["'none'"], ["none"]),
         "Set object-src 'none' unless browser plugins are explicitly required."),
        ("Base URL restriction", "base-uri" in directives,
         "Set base-uri 'none' or 'self' to prevent base-tag injection."),
        ("Frame embedding restriction", "frame-ancestors" in directives,
         "Use frame-ancestors to control which sites may embed this page."),
    ]
    checks = [{"title": title, "state": "pass" if passed else "warn", "detail": detail}
              for title, passed, detail in items]
    score = round(sum(item[1] for item in items) / len(items) * 100)
    return {"available": bool(policy), "score": score, "policy": policy,
            "directives": directives, "checks": checks}


def third_party_supply_chain(body, content_type, final_url):
    if "html" not in content_type.lower():
        return {"available": False, "score": None, "resources": [], "origins": [], "checks": []}
    parser = PageParser()
    parser.feed(body.decode("utf-8", errors="ignore"))
    page_host = (urlsplit(final_url).hostname or "").lower()
    resources = []
    seen = set()
    for item in parser.resources:
        absolute = urljoin(final_url, item["url"])
        parts = urlsplit(absolute)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            continue
        key = (item["type"], absolute)
        if key in seen:
            continue
        seen.add(key)
        resources.append({**item, "url": absolute, "host": parts.hostname.lower(),
                          "third_party": parts.hostname.lower() != page_host,
                          "insecure": parts.scheme == "http"})
    external = [item for item in resources if item["third_party"]]
    origins = sorted({item["host"] for item in external})
    sri_candidates = [item for item in external if item["type"] in {"script", "link"}]
    without_sri = [item for item in sri_candidates if not item["integrity"]]
    insecure = [item for item in external if item["insecure"]]
    unsandboxed_frames = [item for item in external if item["type"] == "iframe" and not item["sandbox"]]
    score = max(0, 100 - min(50, len(without_sri) * 10) - min(30, len(insecure) * 15)
                - min(20, len(unsandboxed_frames) * 10))
    checks = [
        {"title": "Third-party origins", "state": "info" if origins else "pass",
         "detail": f"Found {len(origins)} third-party origin(s) across {len(external)} resource(s)."},
        {"title": "Encrypted resources", "state": "pass" if not insecure else "fail",
         "detail": f"{len(insecure)} third-party resource(s) use unencrypted HTTP."},
        {"title": "Subresource Integrity", "state": "pass" if not without_sri else "warn",
         "detail": f"{len(without_sri)} of {len(sri_candidates)} eligible third-party resources have no integrity hash."},
        {"title": "Iframe sandboxing", "state": "pass" if not unsandboxed_frames else "warn",
         "detail": f"{len(unsandboxed_frames)} third-party iframe(s) have no sandbox attribute."},
    ]
    return {"available": True, "score": score, "resources": resources, "origins": origins,
            "external_count": len(external), "without_sri": len(without_sri),
            "insecure_count": len(insecure), "unsandboxed_iframes": len(unsandboxed_frames),
            "checks": checks}


def accessibility_score(body, content_type):
    if "html" not in content_type.lower():
        return {"available": False, "score": None, "checks": []}
    parser = PageParser()
    parser.feed(body.decode("utf-8", errors="ignore"))
    labeled = sum(prelabeled or bool(control_id and control_id in parser.labels_for)
                  for control_id, prelabeled in parser.controls)
    controls_ok = not parser.controls or labeled == len(parser.controls)
    headings_ok = bool(parser.heading_levels and parser.heading_levels[0] == 1 and
                       all(current - previous <= 1 for previous, current in zip(parser.heading_levels, parser.heading_levels[1:])))
    items = [
        ("Document language", bool(parser.lang.strip()), "Set a valid lang attribute on the html element."),
        ("Image text alternatives", parser.images_without_alt == 0,
         f"{parser.images_without_alt} of {parser.images} images are missing an alt attribute."),
        ("Form control names", controls_ok,
         f"{len(parser.controls) - labeled} of {len(parser.controls)} form controls have no detected label."),
        ("Heading structure", headings_ok, "Start with one h1 and avoid skipping heading levels."),
    ]
    checks = [{"title": title, "state": "pass" if passed else "warn", "detail": detail}
              for title, passed, detail in items]
    return {"available": True, "score": round(sum(item[1] for item in items) / len(items) * 100),
            "checks": checks}


def performance_score(elapsed_ms, body_size, truncated, redirects):
    if elapsed_ms <= 1000: time_points = 40
    elif elapsed_ms <= 2500: time_points = 25
    elif elapsed_ms <= 5000: time_points = 10
    else: time_points = 0
    if truncated: size_points = 0
    elif body_size <= 100 * 1024: size_points = 40
    elif body_size <= 300 * 1024: size_points = 25
    else: size_points = 15
    redirect_points = 20 if len(redirects) <= 1 else 10 if len(redirects) == 2 else 0
    return {"available": True, "score": time_points + size_points + redirect_points, "checks": [
        {"title": "Response time", "state": "pass" if time_points == 40 else "warn",
         "detail": f"The initial page completed in {elapsed_ms:.1f} ms."},
        {"title": "HTML response size", "state": "pass" if size_points == 40 else "warn",
         "detail": "The response exceeded the 384 KiB sample limit." if truncated else f"The response body was {body_size / 1024:.1f} KiB."},
        {"title": "Redirect count", "state": "pass" if redirect_points == 20 else "warn",
         "detail": f"The initial request followed {len(redirects)} redirects."},
    ]}


def category(score, checks):
    if score is None: status = "unavailable"
    elif score >= 80: status = "good"
    elif score >= 55: status = "fair"
    else: status = "poor"
    return {"score": score, "status": status, "checks": checks}


def certificate_details(certificate):
    if not certificate:
        return None
    def name(field):
        return ", ".join(f"{key}={value}" for group in certificate.get(field, ()) for key, value in group)
    result = {"subject": name("subject"), "issuer": name("issuer"),
              "serial_number": certificate.get("serialNumber"), "expires_at": None, "days_remaining": None}
    if certificate.get("notAfter"):
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate["notAfter"]), timezone.utc)
        result["expires_at"] = expires.isoformat()
        result["days_remaining"] = max(0, int((expires - datetime.now(timezone.utc)).total_seconds() // 86400))
    return result


def tls_domain_score(final_url, tls, dns_addresses):
    checks = []
    points = 0
    uses_https = urlsplit(final_url).scheme == "https"
    if uses_https:
        points += 30
        checks.append({"title": "HTTPS connection", "state": "pass",
                       "detail": "The final URL uses an encrypted HTTPS connection."})
    else:
        checks.append({"title": "HTTPS connection", "state": "fail",
                       "detail": "The final URL uses unencrypted HTTP."})

    if tls:
        points += 35
        checks.append({"title": "TLS certificate", "state": "pass",
                       "detail": "The certificate chain and hostname were validated."})
        days = tls.get("days_remaining")
        if days is None:
            points += 10
            checks.append({"title": "Certificate lifetime", "state": "info",
                           "detail": "The certificate expiry date was not available."})
        elif days >= 30:
            points += 20
            checks.append({"title": "Certificate lifetime", "state": "pass",
                           "detail": f"The certificate has {days} days remaining."})
        elif days > 0:
            points += 10
            checks.append({"title": "Certificate lifetime", "state": "warn",
                           "detail": f"The certificate expires in {days} days."})
        else:
            checks.append({"title": "Certificate lifetime", "state": "fail",
                           "detail": "The certificate has expired or expires today."})
    else:
        checks.extend([
            {"title": "TLS certificate", "state": "fail" if uses_https else "info",
             "detail": "No certificate details were available."},
            {"title": "Certificate lifetime", "state": "info",
             "detail": "Certificate lifetime is unavailable without certificate details."},
        ])

    if dns_addresses:
        points += 15
        checks.append({"title": "Public DNS", "state": "pass",
                       "detail": f"The domain resolved to {len(dns_addresses)} validated public address(es)."})
    else:
        checks.append({"title": "Public DNS", "state": "fail",
                       "detail": "No validated public DNS address was available."})
    return category(points, checks)


def analyze_response(initial_url, final_url, status, headers, body, truncated, certificate,
                     redirects, elapsed_ms):
    checks = []

    def add(key, title, state, detail, recommendation="", deduction=0):
        checks.append({"key": key, "title": title, "state": state, "detail": detail,
                       "recommendation": recommendation, "deduction": deduction})

    final_https = urlsplit(final_url).scheme == "https"
    if final_https:
        add("https", "HTTPS and certificate", "pass", "The final page uses HTTPS. Its hostname and certificate chain were validated.")
    else:
        add("https", "HTTPS and certificate", "fail", "The final page still uses unencrypted HTTP.",
            "Enable HTTPS and redirect all HTTP traffic to HTTPS.", 30)

    if urlsplit(initial_url).scheme == "http":
        if final_https:
            add("redirect", "HTTP upgrade", "pass", "The HTTP URL redirects to HTTPS.")
        else:
            add("redirect", "HTTP upgrade", "fail", "The HTTP URL does not upgrade to HTTPS.",
                "Configure a permanent redirect to the HTTPS version of the site.", 8)

    hsts = _header(headers, "Strict-Transport-Security")
    if final_https and hsts:
        add("hsts", "HSTS", "pass", f"Strict-Transport-Security is set: {hsts[:160]}")
    elif final_https:
        add("hsts", "HSTS", "warn", "The HTTPS response has no HSTS header.",
            "After confirming the entire site uses HTTPS, add Strict-Transport-Security.", 10)
    else:
        add("hsts", "HSTS", "info", "HSTS only takes effect on HTTPS websites.")

    csp = _header(headers, "Content-Security-Policy")
    if csp:
        add("csp", "Content Security Policy", "pass", f"A CSP is present: {csp[:180]}")
    else:
        add("csp", "Content Security Policy", "warn", "No Content-Security-Policy header was found.",
            "Build a policy for the site's resources. Start with Report-Only before enforcement.", 12)

    xfo = _header(headers, "X-Frame-Options").lower()
    if xfo in {"deny", "sameorigin"} or re.search(r"(?:^|;)\s*frame-ancestors\b", csp, re.I):
        add("framing", "Frame embedding protection", "pass", "X-Frame-Options or CSP frame-ancestors is present.")
    else:
        add("framing", "Frame embedding protection", "warn", "No effective iframe embedding restriction was found.",
            "Use CSP frame-ancestors, with X-Frame-Options for legacy browsers.", 8)

    if _header(headers, "X-Content-Type-Options").lower() == "nosniff":
        add("nosniff", "MIME type protection", "pass", "X-Content-Type-Options is set to nosniff.")
    else:
        add("nosniff", "MIME type protection", "warn", "X-Content-Type-Options: nosniff is missing.",
            "Add X-Content-Type-Options: nosniff to all responses.", 6)

    referrer = _header(headers, "Referrer-Policy")
    if referrer:
        add("referrer", "Referrer Policy", "pass", f"Policy found: {referrer[:120]}")
    else:
        add("referrer", "Referrer Policy", "warn", "No explicit Referrer-Policy was found.",
            "Use strict-origin-when-cross-origin or a stricter policy as appropriate.", 4)

    permissions = _header(headers, "Permissions-Policy")
    if permissions:
        add("permissions", "Permissions Policy", "pass", "Browser feature permissions are explicitly limited.")
    else:
        add("permissions", "Permissions Policy", "warn", "No Permissions-Policy header was found.",
            "Disable browser features the site does not need, such as camera, microphone, and geolocation.", 3)

    cookies = headers.get_all("Set-Cookie", []) if isinstance(headers, Message) else []
    if cookies:
        missing_secure = sum("; secure" not in "; " + value.lower() for value in cookies)
        missing_http = sum("; httponly" not in "; " + value.lower() for value in cookies)
        missing_same = sum("; samesite=" not in "; " + value.lower() for value in cookies)
        flaws = []
        deduction = 0
        if final_https and missing_secure:
            flaws.append(f"{missing_secure} without Secure"); deduction += 7
        if missing_http:
            flaws.append(f"{missing_http} without HttpOnly"); deduction += 5
        if missing_same:
            flaws.append(f"{missing_same} without SameSite"); deduction += 3
        if flaws:
            add("cookies", "Cookie attributes", "warn", "; ".join(flaws) + ".",
                "Set Secure, HttpOnly, and an appropriate SameSite value for each cookie's purpose.", deduction)
        else:
            add("cookies", "Cookie attributes", "pass", f"All {len(cookies)} cookies set by this response have the common security attributes.")
    else:
        add("cookies", "Cookie attributes", "info", "This response does not set a cookie.")

    allow_origin = _header(headers, "Access-Control-Allow-Origin")
    credentials = _header(headers, "Access-Control-Allow-Credentials").lower()
    if allow_origin == "*" and credentials == "true":
        add("cors", "CORS", "fail", "The response combines a wildcard origin with credentials, which is a conflicting configuration.",
            "Use an explicit origin allowlist and verify whether cross-origin credentials are required.", 10)
    elif allow_origin == "*":
        add("cors", "CORS", "info", "Any origin may read this public response. Confirm that its data is intended to be public.")
    else:
        add("cors", "CORS", "pass", "No wildcard-origin and credential combination was found.")

    server = _header(headers, "Server")
    powered = _header(headers, "X-Powered-By")
    if powered or (server and re.search(r"[/ ]\d", server)):
        exposed = ", ".join(value for value in (server, powered) if value)
        add("disclosure", "Technology disclosure", "warn", f"The response may disclose software or version details: {exposed[:150]}",
            "Remove unnecessary Server version details and X-Powered-By headers.", 3)
    else:
        add("disclosure", "Technology disclosure", "pass", "No explicit version was found in common response headers.")

    content_type = _header(headers, "Content-Type").lower()
    if final_https and "html" in content_type:
        text = body.decode("utf-8", errors="ignore")
        mixed = bool(re.search(r"(?:src|href|action)\s*=\s*['\"]?http://", text, re.I))
        if mixed:
            add("mixed", "Mixed content", "warn", "The HTML sample references a resource over HTTP.",
                "Change page resources to HTTPS or relative URLs.", 8)
        else:
            add("mixed", "Mixed content", "pass", "No obvious HTTP resource reference was found in the downloaded HTML sample.")

    if status >= 400:
        add("status", "HTTP status", "warn", f"The final page returned HTTP {status}.",
            "Confirm that the URL points to a publicly accessible page.", 5)

    if truncated:
        add("limit", "Content sample limit", "info", "The response exceeded 384 KiB, so only its first section was analyzed.")

    score = max(0, 100 - sum(check["deduction"] for check in checks))
    risk = "low" if score >= 80 else "medium" if score >= 55 else "high"
    quality = page_quality(body, content_type)
    seo = seo_audit(body, content_type)
    accessibility = accessibility_score(body, content_type)
    performance = performance_score(elapsed_ms, len(body), truncated, redirects)
    technologies = detect_technologies(headers, body, content_type)
    csp_analysis = analyze_csp(_header(headers, "Content-Security-Policy"))
    supply_chain = third_party_supply_chain(body, content_type, final_url)
    tls = certificate_details(certificate)
    categories = {
        "security": category(score, checks),
        "page_quality": category(quality["score"], quality["checks"]),
        "accessibility": category(accessibility["score"], accessibility["checks"]),
        "performance": category(performance["score"], performance["checks"]),
    }
    return {
        "ok": True, "score": score, "risk": risk, "initial_url": initial_url,
        "final_url": final_url, "status": status, "redirects": redirects,
        "elapsed_ms": round(elapsed_ms, 1), "certificate_expires": tls["expires_at"] if tls else None,
        "tls": tls, "page_quality": {key: value for key, value in quality.items() if key != "links"},
        "accessibility": accessibility, "performance": performance, "categories": categories,
        "seo": seo, "technologies": technologies, "csp_analysis": csp_analysis,
        "supply_chain": supply_chain,
        "checked_at": datetime.now(timezone.utc).isoformat(), "checks": checks,
        "summary": {
            "passed": sum(item["state"] == "pass" for item in checks),
            "warnings": sum(item["state"] == "warn" for item in checks),
            "failed": sum(item["state"] == "fail" for item in checks),
            "informational": sum(item["state"] == "info" for item in checks),
        },
        "scope": "Checks only HTTPS, response headers, cookie attributes, and initial HTML signals on a public page.",
    }


def _fetch_follow(url, resolver, requester, max_redirects=2):
    for _ in range(max_redirects + 1):
        normalized, host, port, addresses = validate_target(url, resolver)
        status, headers, body, truncated, certificate = requester(normalized, host, port, addresses)
        if status in {301, 302, 303, 307, 308} and headers.get("Location"):
            url = urljoin(normalized, headers["Location"])
            continue
        return normalized, status, headers, body, truncated, certificate, addresses
    raise ScanError("The resource exceeded its redirect limit.")


def _doh_lookup(name, record_type, resolver=socket.getaddrinfo, requester=_request):
    query_url = ("https://dns.google/resolve?name=" + quote(name, safe=".-_")
                 + "&type=" + quote(record_type, safe=""))
    _, status, _, body, _, _, _ = _fetch_follow(query_url, resolver, requester, max_redirects=1)
    if status != 200:
        raise ScanError(f"The DNS service returned HTTP {status}.")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScanError("The DNS service returned an invalid response.") from exc
    answers = [str(item.get("data", "")).strip('"').replace('" "', "")
               for item in payload.get("Answer", []) if item.get("data")]
    return {"status": payload.get("Status"), "authenticated": bool(payload.get("AD")),
            "answers": answers}


def _base_domain(host):
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    labels = host.rstrip(".").lower().split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    common_second_level = {"ac", "co", "com", "edu", "gov", "net", "org"}
    if len(labels[-1]) == 2 and labels[-2] in common_second_level and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def dns_email_security(host, lookup):
    domain = _base_domain(host)
    if not domain:
        return {"available": False, "domain": host, "score": None, "checks": [], "records": {}}
    queries = {"txt": (domain, "TXT"), "caa": (domain, "CAA"), "mx": (domain, "MX"),
               "dmarc": ("_dmarc." + domain, "TXT"),
               "mta_sts": ("_mta-sts." + domain, "TXT"),
               "tls_rpt": ("_smtp._tls." + domain, "TXT")}
    records = {}
    errors = []
    for key, (name, record_type) in queries.items():
        try:
            records[key] = lookup(name, record_type)
        except ScanError as exc:
            records[key] = {"status": None, "authenticated": False, "answers": []}
            errors.append(str(exc))
    txt = records["txt"]["answers"]
    spf = next((value for value in txt if value.lower().startswith("v=spf1")), "")
    dmarc = next((value for value in records["dmarc"]["answers"]
                  if value.lower().startswith("v=dmarc1")), "")
    mta = next((value for value in records["mta_sts"]["answers"]
                if value.lower().startswith("v=stsv1")), "")
    tls_rpt = next((value for value in records["tls_rpt"]["answers"]
                    if value.lower().startswith("v=tlsrptv1")), "")
    has_mail = bool(records["mx"]["answers"])
    authenticated = any(item["authenticated"] for item in records.values())
    base_items = [
        ("DNSSEC validation", authenticated,
         "The DNS response was authenticated with DNSSEC." if authenticated else "No authenticated DNSSEC response was observed."),
        ("CAA restrictions", bool(records["caa"]["answers"]),
         f"Found {len(records['caa']['answers'])} CAA record(s)." if records["caa"]["answers"] else "No CAA record limits certificate authorities."),
    ]
    mail_items = [
        ("SPF anti-spoofing", bool(spf), "An SPF policy was found." if spf else "No SPF policy was found."),
        ("DMARC policy", bool(dmarc), "A DMARC policy was found." if dmarc else "No DMARC policy was found."),
        ("MTA-STS", bool(mta), "An MTA-STS discovery record was found." if mta else "No MTA-STS discovery record was found."),
        ("TLS reporting", bool(tls_rpt), "A TLS-RPT policy was found." if tls_rpt else "No TLS-RPT policy was found."),
    ]
    scored_items = base_items + (mail_items if has_mail else [])
    checks = [{"title": title, "state": "pass" if passed else "warn", "detail": detail}
              for title, passed, detail in base_items]
    checks.append({"title": "Mail exchange", "state": "pass" if has_mail else "info",
                   "detail": f"Found {len(records['mx']['answers'])} MX record(s)." if has_mail else "No MX record was found; email-specific checks are informational."})
    checks.extend({"title": title, "state": ("pass" if passed else "warn") if has_mail else "info",
                   "detail": detail} for title, passed, detail in mail_items)
    score = round(sum(item[1] for item in scored_items) / len(scored_items) * 100)
    available = not errors or any(item["answers"] for item in records.values())
    if not available:
        checks = [{"title": "DNS lookup", "state": "info",
                   "detail": "The external DNS service could not be reached, so no DNS or email score was assigned."}]
    return {"available": available,
            "domain": domain, "score": score if available else None, "checks": checks, "records": records,
            "spf": spf, "dmarc": dmarc, "mta_sts": mta, "tls_rpt": tls_rpt,
            "errors": errors[:2]}


def scan_url(raw_url, resolver=socket.getaddrinfo, requester=_request, crawl_limit=3):
    started = time.perf_counter()
    current, _, _, _ = validate_target(raw_url, resolver)
    initial = current
    redirects = []
    for _ in range(MAX_REDIRECTS + 1):
        current, host, port, addresses = validate_target(current, resolver)
        status, headers, body, truncated, certificate = requester(current, host, port, addresses)
        location = headers.get("Location")
        if status in {301, 302, 303, 307, 308} and location:
            if len(redirects) >= MAX_REDIRECTS:
                raise ScanError("The site exceeded the limit of 5 redirects.")
            next_url = urljoin(current, location)
            # Validation is repeated before every fetch, including redirects.
            normalized, _, _, _ = validate_target(next_url, resolver)
            redirects.append({"status": status, "from": current, "to": normalized})
            current = normalized
            continue
        report = analyze_response(initial, current, status, headers, body, truncated,
                                  certificate, redirects,
                                  (time.perf_counter() - started) * 1000)
        _, final_host, _, dns_addresses = validate_target(current, resolver)
        report["dns"] = {"hostname": final_host, "addresses": dns_addresses}
        report["categories"]["tls_domain"] = tls_domain_score(
            current, report["tls"], dns_addresses)

        security_netloc = f"[{final_host}]" if ":" in final_host else final_host
        security_url = urlunsplit(("https", security_netloc, "/.well-known/security.txt", "", ""))
        try:
            sec_url, sec_status, sec_headers, sec_body, _, _, _ = _fetch_follow(
                security_url, resolver, requester)
            text = sec_body.decode("utf-8", errors="replace") if sec_status == 200 else ""
            report["security_txt"] = {
                "url": sec_url, "found": sec_status == 200,
                "valid_content_type": "text/plain" in _header(sec_headers, "Content-Type").lower(),
                "has_contact": bool(re.search(r"(?im)^contact\s*:", text)),
                "has_expires": bool(re.search(r"(?im)^expires\s*:", text)),
                "status": sec_status,
            }
        except ScanError as exc:
            report["security_txt"] = {"url": security_url, "found": False, "error": str(exc)}

        robots_url = urlunsplit((urlsplit(current).scheme, urlsplit(current).netloc,
                                "/robots.txt", "", ""))
        try:
            robots_final, robots_status, robots_headers, robots_body, _, _, _ = _fetch_follow(
                robots_url, resolver, requester)
            robots_text = robots_body.decode("utf-8", errors="replace") if robots_status == 200 else ""
            sitemaps = re.findall(r"(?im)^sitemap\s*:\s*(\S+)", robots_text)[:10]
            report["robots_txt"] = {"url": robots_final, "found": robots_status == 200,
                                     "status": robots_status, "sitemaps": sitemaps}
        except ScanError as exc:
            report["robots_txt"] = {"url": robots_url, "found": False, "error": str(exc),
                                     "sitemaps": []}

        quality = page_quality(body, _header(headers, "Content-Type"))
        pages = [{"url": current, "status": status, "missing_headers": [
            name for name in ("Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy")
            if not _header(headers, name)]}]
        origin = (urlsplit(current).scheme, urlsplit(current).hostname)
        candidates = []
        for href in quality.get("links", []):
            candidate = urljoin(current, href).split("#", 1)[0]
            parts = urlsplit(candidate)
            candidate = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))
            if (parts.scheme, parts.hostname) == origin and candidate != current and candidate not in candidates:
                candidates.append(candidate)
        for candidate in candidates[:max(0, min(int(crawl_limit), 5) - 1)]:
            try:
                page_url, page_status, page_headers, _, _, _, _ = _fetch_follow(
                    candidate, resolver, requester, max_redirects=1)
                pages.append({"url": page_url, "source_url": candidate,
                              "redirected": page_url != candidate, "status": page_status, "missing_headers": [
                    name for name in ("Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy")
                    if not _header(page_headers, name)]})
            except ScanError as exc:
                pages.append({"url": candidate, "source_url": candidate, "redirected": False,
                              "status": None, "error": str(exc), "missing_headers": []})
        report["pages"] = pages
        linked_pages = pages[1:]
        broken = [page for page in linked_pages
                  if page.get("status") is None or page.get("status", 0) >= 400]
        redirected = [page for page in linked_pages if page.get("redirected")]
        link_score = (round((len(linked_pages) - len(broken)) / len(linked_pages) * 100)
                      if linked_pages else None)
        report["link_health"] = {
            "available": bool(linked_pages), "score": link_score,
            "checked": len(linked_pages), "working": len(linked_pages) - len(broken),
            "broken": broken, "redirected": redirected,
            "limit": max(0, min(int(crawl_limit), 5) - 1),
        }
        report["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 1)
        return report
    raise ScanError("The site exceeded the redirect limit.")


def security_scan_url(raw_url, resolver=socket.getaddrinfo, requester=_request):
    report = scan_url(raw_url, resolver=resolver, requester=requester, crawl_limit=1)
    host = urlsplit(report["final_url"]).hostname or ""
    report["dns_email_security"] = dns_email_security(
        host, lambda name, record_type: _doh_lookup(name, record_type, resolver, requester))
    report["analysis_type"] = "security"
    return report
