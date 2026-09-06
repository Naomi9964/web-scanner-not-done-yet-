# SiteLens

SiteLens is a local website health and defensive security analysis project written in Python. Enter a public website URL to review security headers, TLS and domain health, page quality, accessibility, performance, SEO, internal links, public DNS and email controls, Content Security Policy, and third-party supply-chain exposure.

The application stores reports in a local SQLite database. Previous scans can be reopened or exported as JSON. The runtime uses only the Python standard library.

## Features

### URL Scanner

The main scanner produces five independent scores:

- **Security:** HTTPS, HSTS, CSP presence, framing protection, MIME protection, Referrer Policy, Permissions Policy, cookies, CORS, technology disclosure, and mixed content.
- **TLS & Domain:** HTTPS use, certificate validation and lifetime, public DNS resolution, and redirects.
- **Page Quality:** title, description, language, mobile viewport, and canonical URL.
- **Accessibility:** document language, image alternatives, form control names, and heading structure.
- **Performance:** initial response time, HTML size, and redirect count.

### Website Inspector

- SEO metadata and Open Graph checks
- `robots.txt` and sitemap declaration discovery
- A bounded broken-link sample of up to four same-site links
- Public technology fingerprint detection

### Security Analysis

- **DNS & Email Security:** DNSSEC, CAA, MX, SPF, DMARC, MTA-STS, and TLS-RPT
- **CSP Policy Analyzer:** source fallback, inline script, dynamic evaluation, object, base URL, and frame embedding controls
- **Third-Party Supply Chain:** external scripts, stylesheets, and iframes with HTTPS, Subresource Integrity, and sandbox checks

### Local WAF Demonstration

The project also includes a teaching WAF that inspects request targets, selected headers, JSON, forms, and text bodies for a small set of SQL injection, XSS, path traversal, and command injection patterns. Its separate dashboard displays traffic, blocks, errors, latency, and recent events.

## Requirements

- Python 3.10 or newer
- No third-party Python packages
- Internet access for scanning public websites

The project has been tested with Python 3.13 on Windows.

## Run the application

From PowerShell:

```powershell
cd C:\Users\max08\codex\mini_waf
python app.py
```

Open these pages after the servers start:

| Page | URL |
|---|---|
| Home | <http://127.0.0.1:8080/> |
| URL Scanner | <http://127.0.0.1:8080/scanner> |
| Website Inspector | <http://127.0.0.1:8080/inspector> |
| Security Analysis | <http://127.0.0.1:8080/security-analysis> |
| Scan History | <http://127.0.0.1:8080/history> |
| WAF Dashboard | <http://127.0.0.1:8081/> |

Press `Ctrl+C` in the terminal to stop all three local servers.

Use different ports if the defaults are occupied:

```powershell
python app.py --proxy-port 8180 --dashboard-port 8181 --backend-port 9101
```

## Project structure

```text
mini_waf/
├── app.py                         Application entry point and local HTTP servers
├── README.md                      Project documentation
├── sitelens/                      Python application package
│   ├── __init__.py
│   ├── rules.py                   WAF rules and request inspection
│   ├── scan_store.py              Thread-safe SQLite report storage
│   └── url_scan.py                Website fetching and analysis logic
├── web/                           HTML user interfaces
│   ├── home.html
│   ├── demo.html                  Five-category URL Scanner
│   ├── inspector.html             SEO, link, and technology inspector
│   ├── security_analysis.html     Defensive security analysis
│   ├── history.html
│   └── dashboard.html
├── tests/                         Automated tests
│   ├── test_url_scan.py
│   └── test_waf.py
├── tools/
│   └── demo_client.py             Fixed local WAF demonstration requests
└── data/
    └── scan_history.db            Local scan database, created automatically
```

## Architecture

```text
Browser or demo client
        |
        v
127.0.0.1:8080  WAF proxy and public application entry
        |
        +-- malformed or matched request --> blocked response and event
        |
        +-- accepted request -----------------------------+
                                                           |
                                                           v
                                                127.0.0.1:9001
                                                application backend

127.0.0.1:8081  isolated WAF dashboard and /api/stats
```

All services bind to IPv4 loopback. Port `9001` is the demonstration backend; connecting to it directly bypasses the WAF. Use port `8080` for normal demonstrations. Dashboard traffic is separated from protected application traffic.

## API routes

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/api/scan` | Run the general website scan and save its report |
| `POST` | `/api/security-scan` | Run DNS, CSP, and supply-chain analysis |
| `GET` | `/api/history` | List locally saved reports |
| `GET` | `/api/report/{id}` | Read a saved JSON report |
| `GET` | `/api/report/{id}?download=1` | Download a report as JSON |
| `GET` | `/api/stats` on port 8081 | Read WAF dashboard statistics |

Example scan request:

```powershell
curl.exe -X POST `
  -H "Content-Type: application/json" `
  --data '{"url":"https://example.com","crawl_limit":3}' `
  http://127.0.0.1:8080/api/scan
```

Security Analysis sends the entered domain name and DNS record types to Google Public DNS over HTTPS. Website responses and scan reports remain stored locally.

## Run the tests

```powershell
python -m unittest discover -s tests -v
```

The tests cover URL validation, SSRF restrictions, redirects, response analysis, DNS and email policy scoring, CSP parsing, supply-chain extraction, WAF forwarding and blocking, HTTP framing, body limits, dashboard isolation, report storage, and all application routes.

Run the fixed WAF demonstration client while the application is running:

```powershell
python tools\demo_client.py
```

It sends eight requests to the local WAF: three expected allowed responses and five expected blocks. Use `--port 8180` if the proxy runs on a custom port.

## Safety boundaries

Website scans accept only public `http://` and `https://` targets on ports 80 and 443. The scanner rejects credentials in URLs and blocks local, private, reserved, and special-use IP addresses. DNS is resolved and pinned before each connection, and every redirect is validated again. Downloads, redirects, pages, concurrent scans, and timeouts are bounded.

The scanner performs a lightweight remote configuration review. It does not sign in, submit attack payloads, scan arbitrary ports, or prove that a site is free from SQL injection, XSS, authorization flaws, or server-side vulnerabilities. Performance results are server-observed measurements rather than Lighthouse or Core Web Vitals results. Technology and third-party ownership detection uses public fingerprints and can be incomplete.

The bundled WAF is a classroom prototype. Its small regular-expression rule set can produce false positives and false negatives. `http.server` is not intended for production deployment. Production applications still need parameterized database queries, output encoding, authentication and authorization controls, dependency management, rate limiting, monitoring, and a production-grade HTTP server.

References:

- [Python `http.server` documentation](https://docs.python.org/3/library/http.server.html)
- [OWASP Web Application Firewall information](https://owasp.org/www-community/Web_Application_Firewall)
