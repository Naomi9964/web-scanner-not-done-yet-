"""Send a small, fixed test set only to this example's local WAF."""
import argparse
from http.client import HTTPConnection
import json
from urllib.parse import urlencode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    cases = [
        ("normal search", "/search?" + urlencode({"q": "hello world"}), None, 200),
        ("normal JSON", "/echo", {"message": "hello"}, 200),
        ("SQL injection", "/search?" + urlencode({"q": "' UNION SELECT 1,2 --"}), None, 403),
        ("XSS", "/search?" + urlencode({"q": "<script>alert(1)</script>"}), None, 403),
        ("path traversal", "/search?" + urlencode({"file": "../../demo.txt"}), None, 403),
        ("command injection", "/search?" + urlencode({"q": "hello; whoami"}), None, 403),
        ("JSON XSS", "/echo", {"profile": {"bio": "<img src=x onerror=alert(1)>"}}, 403),
        ("backend 404", "/missing-page", None, 404),
    ]
    failed = 0
    for name, path, value, expected in cases:
        connection = HTTPConnection("127.0.0.1", args.port, timeout=7)
        try:
            body = json.dumps(value).encode() if value is not None else None
            connection.request("POST" if body else "GET", path, body,
                               {"Content-Type": "application/json"} if body else {})
            response = connection.getresponse()
            response.read()
            ok = response.status == expected
            failed += not ok
            print(f"{'PASS' if ok else 'FAIL'}  {name:20} HTTP {response.status}  WAF={response.getheader('X-Mini-WAF')}")
        except OSError as exc:
            parser.exit(1, f"Connection failed: {exc}\nStart app.py first.\n")
        finally:
            connection.close()
    print(f"\n{len(cases) - failed}/{len(cases)} expected results. Open the dashboard to see the events.")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
