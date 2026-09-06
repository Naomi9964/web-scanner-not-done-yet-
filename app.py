"""SiteLens local website analysis service and teaching WAF."""

import argparse
from collections import Counter, deque
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import threading
import time
from urllib.parse import parse_qs, urlsplit

from sitelens.rules import RULES, inspect_request
from sitelens.scan_store import ScanStore
from sitelens.url_scan import ScanError, scan_url, security_scan_url

ROOT = Path(__file__).resolve().parent
WEB_DIR = ROOT / "web"
DATA_DIR = ROOT / "data"
MAX_BODY = 64 * 1024
MAX_RESPONSE = 2 * 1024 * 1024
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection"}
BODY_TYPES = {"application/json", "application/x-www-form-urlencoded", "text/plain"}
SCAN_SEMAPHORE = threading.BoundedSemaphore(3)


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.events = deque(maxlen=200)
        self.totals = Counter(total=0, allowed=0, blocked=0, error=0)
        self.categories = Counter()
        self.buckets = {}
        self.started = time.time()
        self.latency_sum = 0

    def record(self, method, target, action, status, rule, source, elapsed_ms):
        now = time.time()
        minute = int(now // 60)
        # Query values, bodies, cookies, and authorization are deliberately not logged.
        path = target.split("?", 1)[0][:160]
        with self.lock:
            self.totals["total"] += 1
            self.totals[action] += 1
            self.latency_sum += elapsed_ms
            if action == "blocked":
                self.categories[rule] += 1
            self.buckets = {k: v for k, v in self.buckets.items() if k > minute - 60}
            bucket = self.buckets.setdefault(minute, Counter(allowed=0, blocked=0, error=0))
            bucket[action] += 1
            self.events.appendleft({
                "id": self.totals["total"],
                "time": datetime.fromtimestamp(now, timezone.utc).isoformat(),
                "method": method, "path": path, "action": action, "status": status,
                "rule": rule, "source": source, "latency_ms": round(elapsed_ms, 2),
            })

    def snapshot(self):
        minute = int(time.time() // 60)
        with self.lock:
            return {
                "totals": dict(self.totals), "categories": dict(self.categories),
                "events": list(self.events), "uptime_seconds": int(time.time() - self.started),
                "average_latency_ms": round(self.latency_sum / max(1, self.totals["total"]), 2),
                "traffic": [{"timestamp": index * 60,
                             **dict(self.buckets.get(index, Counter(allowed=0, blocked=0, error=0)))}
                            for index in range(minute - 59, minute + 1)],
                "rules": [{"id": rule.id, "name": rule.name, "description": rule.description}
                          for rule in RULES],
            }


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # One request per connection simplifies this demo.
    server_version = "MiniWAF/1.0"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_):
        pass  # BaseHTTPRequestHandler's access log would include secret query values.

    def reply(self, status, payload, content_type="application/json; charset=utf-8", headers=()):
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        elif isinstance(payload, str):
            payload = payload.encode("utf-8")
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def local_host(self):
        hosts = self.headers.get_all("Host", [])
        port = self.server.server_port
        return len(hosts) == 1 and hosts[0].lower() in {
            f"localhost:{port}", f"127.0.0.1:{port}"}


def hop_names(headers):
    names = set(HOP_HEADERS)
    for value in headers.get_all("Connection", []):
        names.update(token.strip().lower() for token in value.split(","))
    return names


class ProxyHandler(Handler):
    def run_proxy(self):
        started = time.perf_counter()
        outcome = {"action": "error", "status": 500, "rule": "INTERNAL", "source": "proxy"}

        def reject(status, rule, message, source="protocol"):
            outcome.update(action="blocked", status=status, rule=rule, source=source)
            self.reply(status, {"blocked": True, "rule": rule, "source": source, "message": message},
                       headers=[("X-Mini-WAF", "blocked")])

        try:
            if not self.local_host():
                return reject(400, "HOST", "Use the displayed localhost or 127.0.0.1 address")
            if not self.path.startswith("/") or self.path.startswith("//") or "#" in self.path:
                return reject(400, "TARGET", "Only origin-form request targets are supported")
            if len(self.path) > 8192:
                return reject(414, "URL-LIMIT", "URL exceeds 8192 characters")
            if self.command not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
                return reject(405, "METHOD", "HTTP method is not supported")
            if sum(len(k) + len(v) for k, v in self.headers.items()) > 32768:
                return reject(431, "HEADER-LIMIT", "Headers exceed 32 KiB")
            for name, value in self.headers.items():
                if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or re.search(r"[\x00-\x1f\x7f]", value):
                    return reject(400, "HEADERS", "Invalid header characters")
            if self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Upgrade"):
                return reject(400, "FRAMING", "Chunked requests and protocol upgrades are not supported")
            if self.headers.get_all("Expect"):
                return reject(417, "EXPECT", "Expect requests are not supported")
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) > 1 or (lengths and not re.fullmatch(r"[0-9]{1,10}", lengths[0])):
                return reject(400, "FRAMING", "Invalid or duplicate Content-Length")
            length = int(lengths[0]) if lengths else 0
            if length > MAX_BODY:
                return reject(413, "BODY-LIMIT", "Request body exceeds 64 KiB")
            if len(self.headers.get_all("Content-Type", [])) > 1:
                return reject(400, "FRAMING", "Duplicate Content-Type")
            if self.headers.get_all("Content-Encoding"):
                return reject(415, "ENCODING", "Encoded request bodies are not supported")
            media = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if length and media not in BODY_TYPES:
                return reject(415, "BODY-TYPE", "Use application/json, form-urlencoded, or text/plain")
            body = self.rfile.read(length) if length else b""
            if len(body) != length:
                return reject(400, "FRAMING", "Incomplete request body")
            try:
                match = inspect_request(self.path, self.headers, body)
            except ValueError:
                return reject(400, "PAYLOAD", "Invalid request data or too many parameters", "payload")
            if match:
                return reject(403, match["id"], match["name"], match["source"])

            # The upstream is fixed at startup; request data cannot choose a destination.
            upstream_timeout = 60 if self.path in {"/api/scan", "/api/security-scan"} else 5
            upstream = HTTPConnection("127.0.0.1", self.server.backend_port, timeout=upstream_timeout)
            try:
                excluded = hop_names(self.headers) | {"host", "content-length", "forwarded", "accept-encoding"}
                upstream.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                upstream.putheader("Host", f"127.0.0.1:{self.server.backend_port}")
                for key, value in self.headers.items():
                    if key.lower() not in excluded and not key.lower().startswith("x-forwarded-"):
                        upstream.putheader(key, value)
                upstream.putheader("X-Forwarded-For", self.client_address[0])
                upstream.putheader("Accept-Encoding", "identity")
                upstream.putheader("Content-Length", str(len(body)))
                upstream.putheader("Connection", "close")
                upstream.endheaders(body)
                response = upstream.getresponse()
                payload = response.read(MAX_RESPONSE + 1)
                if len(payload) > MAX_RESPONSE or response.status < 200:
                    raise HTTPException("Unsupported upstream response")
                response_headers = response.getheaders()
                if any(re.search(r"[\r\n\x00]", k + v) for k, v in response_headers):
                    raise HTTPException("Invalid upstream header")
                excluded_response = hop_names(response.headers) | {"content-length", "server", "date", "x-mini-waf"}
                outcome.update(action="allowed", status=response.status, rule="—", source="—")
                self.close_connection = True
                self.send_response(response.status)
                for key, value in response_headers:
                    if key.lower() not in excluded_response:
                        self.send_header(key, value)
                # Preserve representation length for HEAD; no body for 204 / 304.
                if self.command == "HEAD" or response.status == 304:
                    representation_length = response.getheader("Content-Length")
                    if representation_length and representation_length.isdigit():
                        self.send_header("Content-Length", representation_length)
                elif response.status != 204:
                    self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.send_header("X-Mini-WAF", "allowed")
                self.end_headers()
                if self.command != "HEAD" and response.status not in {204, 304}:
                    self.wfile.write(payload)
            except (OSError, HTTPException, ValueError):
                # Avoid writing a second response if the downstream disconnected.
                if outcome["action"] == "allowed":
                    return
                outcome.update(action="error", status=502, rule="UPSTREAM", source="proxy")
                self.reply(502, {"error": "Demo backend unavailable or response unsupported"})
            finally:
                upstream.close()
        except TimeoutError:
            reject(408, "TIMEOUT", "Request body timed out")
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.server.state.record(self.command, self.path, elapsed_ms=(time.perf_counter() - started) * 1000,
                                     **outcome)

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_TRACE = do_CONNECT = run_proxy


class DemoHandler(Handler):
    def handle_demo(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_BODY or length < 0:
            return self.reply(413, {"error": "Body too large"})
        body = self.rfile.read(length) if length else b""
        path = urlsplit(self.path).path
        if path == "/":
            page = (WEB_DIR / "home.html").read_text(encoding="utf-8")
            return self.reply(200, page.replace("__DASHBOARD_PORT__", str(self.server.dashboard_port)),
                              "text/html; charset=utf-8")
        if path == "/scanner":
            page = (WEB_DIR / "demo.html").read_text(encoding="utf-8")
            return self.reply(200, page.replace("__DASHBOARD_PORT__", str(self.server.dashboard_port)),
                              "text/html; charset=utf-8")
        if path == "/inspector":
            return self.reply(200, (WEB_DIR / "inspector.html").read_bytes(),
                              "text/html; charset=utf-8")
        if path == "/security-analysis":
            return self.reply(200, (WEB_DIR / "security_analysis.html").read_bytes(),
                              "text/html; charset=utf-8")
        if path == "/history":
            return self.reply(200, (WEB_DIR / "history.html").read_bytes(), "text/html; charset=utf-8")
        if path == "/api/history" and self.command == "GET":
            return self.reply(200, {"ok": True, "scans": self.server.store.list()})
        if path.startswith("/api/report/") and self.command == "GET":
            scan_id = path.rsplit("/", 1)[-1]
            report = self.server.store.get(scan_id)
            if not report:
                return self.reply(404, {"ok": False, "error": "Scan report not found."})
            download = parse_qs(urlsplit(self.path).query).get("download") == ["1"]
            headers = [("Content-Disposition", f'attachment; filename="sitelens-{scan_id}.json"')] if download else []
            return self.reply(200, report, headers=headers)
        if path == "/health":
            return self.reply(200, {"ok": True, "service": "demo-backend"})
        if path == "/api/scan" and self.command == "POST":
            try:
                data = json.loads(body.decode("utf-8"))
                target_url = data.get("url") if isinstance(data, dict) else None
                if not isinstance(target_url, str):
                    raise ScanError("Provide the URL as a string.")
            except (UnicodeDecodeError, json.JSONDecodeError):
                return self.reply(400, {"ok": False, "error": "The JSON request is invalid."})
            if not SCAN_SEMAPHORE.acquire(blocking=False):
                return self.reply(429, {"ok": False, "error": "Three scans are already running. Try again shortly."})
            try:
                crawl_limit = data.get("crawl_limit", 3)
                if not isinstance(crawl_limit, int) or isinstance(crawl_limit, bool):
                    crawl_limit = 3
                report = scan_url(target_url, crawl_limit=min(max(crawl_limit, 1), 5))
                report["scan_id"] = self.server.store.save(report)
                return self.reply(200, report)
            except ScanError as exc:
                return self.reply(400, {"ok": False, "error": str(exc)})
            finally:
                SCAN_SEMAPHORE.release()
        if path == "/api/security-scan" and self.command == "POST":
            try:
                data = json.loads(body.decode("utf-8"))
                target_url = data.get("url") if isinstance(data, dict) else None
                if not isinstance(target_url, str):
                    raise ScanError("Provide the URL as a string.")
            except (UnicodeDecodeError, json.JSONDecodeError):
                return self.reply(400, {"ok": False, "error": "The JSON request is invalid."})
            if not SCAN_SEMAPHORE.acquire(blocking=False):
                return self.reply(429, {"ok": False, "error": "Three scans are already running. Try again shortly."})
            try:
                report = security_scan_url(target_url)
                report["scan_id"] = self.server.store.save(report)
                return self.reply(200, report)
            except ScanError as exc:
                return self.reply(400, {"ok": False, "error": str(exc)})
            finally:
                SCAN_SEMAPHORE.release()
        if path in {"/search", "/echo"}:
            return self.reply(200, {"message": "The request passed the WAF and reached the demo backend.",
                                    "method": self.command, "path": path,
                                    "query": parse_qs(urlsplit(self.path).query),
                                    "body": body.decode("utf-8", errors="replace")})
        return self.reply(404, {"error": "Demo route not found"})

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = handle_demo


class DashboardHandler(Handler):
    def do_GET(self):
        if not self.local_host():
            return self.reply(403, {"error": "Invalid dashboard Host"})
        if self.path == "/api/stats":
            return self.reply(200, self.server.state.snapshot())
        if self.path == "/":
            page = (WEB_DIR / "dashboard.html").read_text(encoding="utf-8")
            return self.reply(200, page.replace("__PROXY_PORT__", str(self.server.proxy_port)),
                              "text/html; charset=utf-8")
        return self.reply(404, {"error": "Not found"})

    do_HEAD = do_GET


def make_servers(proxy_port=8080, dashboard_port=8081, backend_port=9001, history_path=None):
    """A zero port lets the OS select a free port for tests."""
    servers = []
    try:
        backend = LocalServer(("127.0.0.1", backend_port), DemoHandler)
        DATA_DIR.mkdir(exist_ok=True)
        backend.store = ScanStore(history_path or DATA_DIR / "scan_history.db")
        servers.append(backend)
        proxy = LocalServer(("127.0.0.1", proxy_port), ProxyHandler)
        servers.append(proxy)
        dashboard = LocalServer(("127.0.0.1", dashboard_port), DashboardHandler)
        servers.append(dashboard)
        state = State()
        proxy.state = dashboard.state = state
        proxy.backend_port = backend.server_port
        backend.dashboard_port = dashboard.server_port
        dashboard.proxy_port = proxy.server_port
        return servers
    except Exception:
        for server in servers:
            server.server_close()
        if servers and hasattr(servers[0], "store"):
            servers[0].store.close()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy-port", type=int, default=8080)
    parser.add_argument("--dashboard-port", type=int, default=8081)
    parser.add_argument("--backend-port", type=int, default=9001)
    args = parser.parse_args()
    try:
        servers = make_servers(args.proxy_port, args.dashboard_port, args.backend_port)
    except (OSError, OverflowError) as exc:
        parser.exit(1, f"Cannot start local servers: {exc}\nTry different --proxy-port / --dashboard-port / --backend-port values.\n")
    threads = []
    for server in servers:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
    backend, proxy, dashboard = servers
    print(f"URL risk checker: http://127.0.0.1:{proxy.server_port}", flush=True)
    print(f"Dashboard:      http://127.0.0.1:{dashboard.server_port}", flush=True)
    print(f"Demo backend:   127.0.0.1:{backend.server_port} (direct access bypasses WAF)", flush=True)
    print("Local teaching example. Press Ctrl+C to stop.", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...", flush=True)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        backend.store.close()
        for thread in threads:
            thread.join(timeout=2)


if __name__ == "__main__":
    main()
