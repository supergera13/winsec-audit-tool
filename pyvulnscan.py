#!/usr/bin/env python3
"""
PyVulnScan — Lightweight Web Application Vulnerability Scanner
A second product for Gumroad/Etsy. Scans web apps for common vulns.
"""

__version__ = "1.0.0"
__author__ = "Mattia"

import argparse
import json
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from datetime import datetime

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("ERROR: 'requests' library required. Install: pip install requests")
    sys.exit(1)


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class Finding:
    category: str
    name: str
    severity: str
    url: str
    description: str
    evidence: str = ""
    remediation: str = ""
    cvss: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class Scanner:
    def __init__(self, target: str, timeout: int = 10, threads: int = 5, 
                 user_agent: str = None, cookies: dict = None, 
                 headers: dict = None, auth: tuple = None,
                 verbose: bool = False):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": user_agent or f"PyVulnScan/{__version__} (Security Audit)"
        })
        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)
        if auth:
            self.session.auth = auth
        self.verbose = verbose
        self.findings: list[Finding] = []
        self.scanned_urls: set = set()

    def log(self, msg: str, level: str = "info"):
        if self.verbose:
            icons = {"info": "[.]", "warn": "[!]", "vuln": "[V]", "ok": "[+]"}
            print(f"  {icons.get(level, '[.]')} {msg}")

    def add_finding(self, **kwargs):
        f = Finding(**kwargs)
        self.findings.append(f)
        sev = f.severity
        icon = {"Critical": "[!!!]", "High": "[!!]", "Medium": "[!]", "Low": "[-]", "Info": "[i]"}.get(sev, "[?]")
        print(f"  {icon} {f.category} | {f.name} | {f.url}")
        return f

    def safe_get(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=False, **kwargs)
            return resp
        except requests.RequestException as e:
            self.log(f"Request failed: {url} — {e}", "warn")
            return None

    def safe_post(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            resp = self.session.post(url, timeout=self.timeout, allow_redirects=False, **kwargs)
            return resp
        except requests.RequestException as e:
            self.log(f"Request failed: {url} — {e}", "warn")
            return None

    # ═══════════════════════════════════════
    # CHECK 1: Security Headers
    # ═══════════════════════════════════════
    def check_security_headers(self):
        print("\n[*] Checking security headers...")
        resp = self.safe_get(self.target)
        if not resp:
            return

        headers = resp.headers
        checks = [
            ("Strict-Transport-Security", "Missing HSTS", Severity.HIGH,
             "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
             6.1),
            ("Content-Security-Policy", "Missing CSP", Severity.MEDIUM,
             "Implement a Content-Security-Policy header",
             5.0),
            ("X-Content-Type-Options", "Missing X-Content-Type-Options", Severity.LOW,
             "Add: X-Content-Type-Options: nosniff",
             3.0),
            ("X-Frame-Options", "Missing X-Frame-Options (Clickjacking)", Severity.MEDIUM,
             "Add: X-Frame-Options: DENY",
             4.0),
            ("X-XSS-Protection", "Missing X-XSS-Protection", Severity.LOW,
             "Add: X-XSS-Protection: 1; mode=block",
             2.0),
            ("Referrer-Policy", "Missing Referrer-Policy", Severity.LOW,
             "Add: Referrer-Policy: strict-origin-when-cross-origin",
             2.0),
            ("Permissions-Policy", "Missing Permissions-Policy", Severity.LOW,
             "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
             2.0),
        ]

        for header, name, sev, fix, cvss in checks:
            if header not in headers:
                self.add_finding(
                    category="Security Headers", name=name, severity=sev.value,
                    url=self.target, description=f"HTTP header '{header}' is not set",
                    remediation=fix, cvss=cvss
                )
            else:
                self.log(f"{header}: present", "ok")

        # Check for server info leakage
        if "Server" in headers:
            self.add_finding(
                category="Information Disclosure", name="Server Header Leaks Version",
                severity=Severity.LOW.value, url=self.target,
                description=f"Server header reveals: {headers['Server']}",
                remediation="Remove or genericize the Server header",
                cvss=2.0
            )
        if "X-Powered-By" in headers:
            self.add_finding(
                category="Information Disclosure", name="X-Powered-By Header Leaks Tech",
                severity=Severity.LOW.value, url=self.target,
                description=f"X-Powered-By reveals: {headers['X-Powered-By']}",
                remediation="Remove the X-Powered-By header",
                cvss=2.0
            )

    # ═══════════════════════════════════════
    # CHECK 2: Directory / File Discovery
    # ═══════════════════════════════════════
    def check_sensitive_files(self):
        print("\n[*] Checking for sensitive files and directories...")
        
        sensitive_paths = [
            ("/.env", "Environment Variables", Severity.CRITICAL, "Contains secrets, API keys, DB credentials"),
            ("/.git/config", "Git Repository Exposed", Severity.HIGH, "Source code and credentials may be accessible"),
            ("/.git/HEAD", "Git HEAD Exposed", Severity.HIGH, "Git repository metadata accessible"),
            ("/robots.txt", "Robots.txt", Severity.INFO, "May reveal hidden paths"),
            ("/sitemap.xml", "Sitemap", Severity.INFO, "Reveals site structure"),
            ("/.htaccess", "htaccess File", Severity.MEDIUM, "May contain sensitive configuration"),
            ("/wp-config.php.bak", "WordPress Config Backup", Severity.CRITICAL, "Database credentials exposed"),
            ("/config.php.bak", "PHP Config Backup", Severity.CRITICAL, "Configuration backup accessible"),
            ("/backup.sql", "SQL Backup", Severity.CRITICAL, "Database dump accessible"),
            ("/dump.sql", "SQL Dump", Severity.CRITICAL, "Database dump accessible"),
            ("/.DS_Store", "macOS DS_Store", Severity.LOW, "Reveals directory structure"),
            ("/server-status", "Apache Server Status", Severity.MEDIUM, "Server status page exposed"),
            ("/server-info", "Apache Server Info", Severity.MEDIUM, "Server info page exposed"),
            ("/.svn/entries", "SVN Repository", Severity.HIGH, "Version control metadata exposed"),
            ("/package.json", "Package.json", Severity.LOW, "Reveals dependencies"),
            ("/composer.json", "Composer.json", Severity.LOW, "Reveals PHP dependencies"),
            ("/web.config", "Web.config", Severity.MEDIUM, "IIS configuration exposed"),
            ("/crossdomain.xml", "Cross-domain Policy", Severity.MEDIUM, "Overly permissive cross-domain policy"),
            ("/phpinfo.php", "PHP Info", Severity.MEDIUM, "Server configuration exposed"),
            ("/info.php", "PHP Info (alt)", Severity.MEDIUM, "Server configuration exposed"),
            ("/debug", "Debug Endpoint", Severity.MEDIUM, "Debug mode may be enabled"),
            ("/trace", "TRACE Endpoint", Severity.MEDIUM, "HTTP TRACE enabled (XST risk)"),
            ("/test", "Test Page", Severity.LOW, "Test/development page exposed"),
            ("/actuator", "Spring Actuator", Severity.HIGH, "Spring Boot actuator exposed"),
            ("/actuator/env", "Spring Environment", Severity.CRITICAL, "Environment variables exposed"),
            ("/swagger-ui.html", "Swagger UI", Severity.MEDIUM, "API documentation exposed"),
            ("/api-docs", "API Docs", Severity.MEDIUM, "API documentation exposed"),
            ("/graphql", "GraphQL Endpoint", Severity.INFO, "GraphQL endpoint found — test for introspection"),
            ("/.well-known/security.txt", "Security.txt", Severity.INFO, "Security contact info available"),
        ]

        for path, name, sev, desc in sensitive_paths:
            url = f"{self.target}{path}"
            resp = self.safe_get(url)
            if resp and resp.status_code == 200:
                # Verify it's not a generic error page
                body = resp.text[:500].lower()
                if any(x in body for x in ["404", "not found", "error", "denied"]):
                    continue
                
                # Special checks
                if path == "/.env":
                    if any(k in body for k in ["password", "secret", "key", "token", "database"]):
                        self.add_finding(
                            category="Sensitive Files", name=name, severity=sev.value,
                            url=url, description=desc,
                            evidence=resp.text[:200],
                            remediation="Remove .env from web root. Add to .gitignore and webserver deny rules.",
                            cvss=9.0
                        )
                elif path == "/.git/HEAD":
                    if "ref:" in body:
                        self.add_finding(
                            category="Sensitive Files", name=name, severity=sev.value,
                            url=url, description=desc,
                            evidence=resp.text.strip(),
                            remediation="Block .git directory in web server configuration",
                            cvss=8.0
                        )
                elif path == "/graphql":
                    # Test introspection
                    intro_resp = self.safe_post(url, json={"query": "{ __schema { types { name } } }"})
                    if intro_resp and "__schema" in intro_resp.text:
                        self.add_finding(
                            category="GraphQL", name="GraphQL Introspection Enabled",
                            severity=Severity.MEDIUM.value, url=url,
                            description="GraphQL introspection is enabled, exposing full schema",
                            remediation="Disable introspection in production",
                            cvss=5.0
                        )
                else:
                    self.add_finding(
                        category="Sensitive Files", name=name, severity=sev.value,
                        url=url, description=desc,
                        remediation=f"Restrict access to {path}",
                        cvss=cvss if 'cvss' in dir() else 5.0
                    )

    # ═══════════════════════════════════════
    # CHECK 3: XSS Reflection
    # ═══════════════════════════════════════
    def check_xss_reflection(self):
        print("\n[*] Testing for reflected XSS...")
        
        # First, discover URLs with parameters
        resp = self.safe_get(self.target)
        if not resp:
            return
        
        # Find forms
        forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', resp.text, re.I)
        inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\']', resp.text, re.I)
        
        # Find URLs with parameters
        param_urls = re.findall(r'href=["\']([^"\']*\?[^"\']+)["\']', resp.text, re.I)
        
        xss_payloads = [
            '<script>alert("xss")</script>',
            '"><img src=x onerror=alert("xss")>',
            "'-alert('xss')-'",
            'javascript:alert("xss")',
        ]
        
        # Test URL parameters
        for param_url in param_urls[:10]:  # Limit to 10
            full_url = urllib.parse.urljoin(self.target, param_url)
            parsed = urllib.parse.urlparse(full_url)
            params = urllib.parse.parse_qs(parsed.query)
            
            for param_name in params:
                for payload in xss_payloads[:2]:  # Test 2 payloads per param
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    resp = self.safe_get(test_url)
                    if resp and payload in resp.text:
                        self.add_finding(
                            category="XSS", name=f"Reflected XSS in parameter '{param_name}'",
                            severity=Severity.HIGH.value, url=test_url,
                            description=f"Input in parameter '{param_name}' is reflected without sanitization",
                            evidence=f"Payload '{payload}' found in response",
                            remediation="Implement output encoding and input validation. Use CSP headers.",
                            cvss=7.0
                        )
                        break  # One finding per parameter is enough

    # ═══════════════════════════════════════
    # CHECK 4: Open Redirect
    # ═══════════════════════════════════════
    def check_open_redirect(self):
        print("\n[*] Testing for open redirects...")
        
        redirect_params = ["url", "redirect", "next", "return", "goto", "continue", 
                          "dest", "destination", "redir", "redirect_uri", "return_to",
                          "checkout_url", "return_url"]
        
        evil_domain = "https://evil.com"
        
        for param in redirect_params:
            test_url = f"{self.target}/?{param}={evil_domain}"
            resp = self.safe_get(test_url)
            if resp and resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    self.add_finding(
                        category="Open Redirect", name=f"Open Redirect via '{param}'",
                        severity=Severity.MEDIUM.value, url=test_url,
                        description=f"Parameter '{param}' allows redirect to arbitrary domains",
                        evidence=f"Redirects to: {location}",
                        remediation="Whitelist allowed redirect domains or use relative paths only",
                        cvss=5.0
                    )

    # ═══════════════════════════════════════
    # CHECK 5: CORS Misconfiguration
    # ═══════════════════════════════════════
    def check_cors(self):
        print("\n[*] Checking CORS configuration...")
        
        evil_origins = [
            "https://evil.com",
            "null",
            f"https://evil.{urllib.parse.urlparse(self.target).netloc}",
        ]
        
        for origin in evil_origins:
            resp = self.safe_get(self.target, headers={"Origin": origin})
            if resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                
                if acao == "*" and acac.lower() == "true":
                    self.add_finding(
                        category="CORS", name="Wildcard CORS with Credentials",
                        severity=Severity.HIGH.value, url=self.target,
                        description="Access-Control-Allow-Origin: * with Allow-Credentials: true",
                        remediation="Do not use wildcard origin with credentials. Whitelist specific origins.",
                        cvss=7.0
                    )
                elif acao == origin and origin in ("https://evil.com", "null"):
                    self.add_finding(
                        category="CORS", name=f"CORS Reflects Arbitrary Origin ({origin})",
                        severity=Severity.MEDIUM.value, url=self.target,
                        description=f"Server reflects '{origin}' in Access-Control-Allow-Origin",
                        remediation="Validate and whitelist allowed origins",
                        cvss=5.0
                    )

    # ═══════════════════════════════════════
    # CHECK 6: Cookie Security
    # ═══════════════════════════════════════
    def check_cookies(self):
        print("\n[*] Checking cookie security flags...")
        
        resp = self.safe_get(self.target)
        if not resp:
            return
        
        for cookie in resp.cookies:
            set_cookie_header = None
            for h in resp.headers.get("Set-Cookie", "").split(","):
                if cookie.name in h:
                    set_cookie_header = h
                    break
            
            if set_cookie_header:
                checks = []
                if "secure" not in set_cookie_header.lower():
                    checks.append("Missing Secure flag")
                if "httponly" not in set_cookie_header.lower():
                    checks.append("Missing HttpOnly flag")
                if "samesite" not in set_cookie_header.lower():
                    checks.append("Missing SameSite attribute")
                
                if checks:
                    self.add_finding(
                        category="Cookies", name=f"Cookie '{cookie.name}' Insecure",
                        severity=Severity.LOW.value, url=self.target,
                        description=f"Cookie '{cookie.name}': {', '.join(checks)}",
                        remediation="Set Secure, HttpOnly, and SameSite flags on all cookies",
                        cvss=3.0
                    )

    # ═══════════════════════════════════════
    # CHECK 7: HTTP Methods
    # ═══════════════════════════════════════
    def check_http_methods(self):
        print("\n[*] Checking HTTP methods...")
        
        risky_methods = ["TRACE", "DELETE", "PUT", "OPTIONS"]
        
        for method in risky_methods:
            try:
                resp = self.session.request(method, self.target, timeout=self.timeout, verify=False)
                if resp.status_code == 200 and method == "TRACE":
                    self.add_finding(
                        category="HTTP Methods", name="TRACE Method Enabled (XST)",
                        severity=Severity.MEDIUM.value, url=self.target,
                        description="HTTP TRACE is enabled, enabling Cross-Site Tracing attacks",
                        remediation="Disable TRACE method in web server configuration",
                        cvss=5.0
                    )
                elif resp.status_code == 200 and method == "OPTIONS":
                    allow = resp.headers.get("Allow", "")
                    self.log(f"OPTIONS response: {allow}", "info")
            except requests.RequestException:
                pass

    # ═══════════════════════════════════════
    # CHECK 8: SSL/TLS
    # ═══════════════════════════════════════
    def check_ssl(self):
        print("\n[*] Checking SSL/TLS configuration...")
        
        parsed = urllib.parse.urlparse(self.target)
        if parsed.scheme != "https":
            self.add_finding(
                category="SSL/TLS", name="No HTTPS",
                severity=Severity.HIGH.value, url=self.target,
                description="Target does not use HTTPS",
                remediation="Enable HTTPS with a valid certificate. Redirect HTTP to HTTPS.",
                cvss=7.0
            )
            
            # Check if HTTPS is available
            https_url = self.target.replace("http://", "https://")
            resp = self.safe_get(https_url)
            if resp and resp.status_code == 200:
                self.add_finding(
                    category="SSL/TLS", name="HTTPS Available but Not Enforced",
                    severity=Severity.MEDIUM.value, url=https_url,
                    description="HTTPS works but HTTP is not redirected",
                    remediation="Configure HTTP -> HTTPS redirect",
                    cvss=5.0
                )

    # ═══════════════════════════════════════
    # MAIN SCAN
    # ═══════════════════════════════════════
    def scan(self):
        print(f"\n{'='*60}")
        print(f"  PyVulnScan v{__version__}")
        print(f"  Target: {self.target}")
        print(f"  Started: {datetime.now().isoformat()}")
        print(f"{'='*60}")
        
        start_time = time.time()
        
        self.check_ssl()
        self.check_security_headers()
        self.check_sensitive_files()
        self.check_http_methods()
        self.check_cors()
        self.check_cookies()
        self.check_open_redirect()
        self.check_xss_reflection()
        
        elapsed = time.time() - start_time
        
        # Summary
        by_sev = {}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        
        print(f"\n{'='*60}")
        print(f"  Scan Complete — {elapsed:.1f}s")
        print(f"  Total findings: {len(self.findings)}")
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            count = by_sev.get(sev, 0)
            if count:
                print(f"    {sev}: {count}")
        print(f"{'='*60}")
        
        return self.findings

    def generate_html_report(self, output_path: str = "pyvulnscan-report.html"):
        """Generate a professional HTML report."""
        critical = sum(1 for f in self.findings if f.severity == "Critical")
        high = sum(1 for f in self.findings if f.severity == "High")
        medium = sum(1 for f in self.findings if f.severity == "Medium")
        low = sum(1 for f in self.findings if f.severity == "Low")
        info = sum(1 for f in self.findings if f.severity == "Info")
        total = len(self.findings)
        
        score = max(0, 100 - (critical * 15) - (high * 8) - (medium * 3) - (low * 1))
        score_color = "#4ade80" if score >= 80 else "#fbbf24" if score >= 60 else "#fb923c" if score >= 40 else "#ef4444"
        
        rows = ""
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        for f in sorted(self.findings, key=lambda x: severity_order.get(x.severity, 5)):
            sev_class = f"sev-{f.severity.lower()}"
            rows += f"""
            <tr>
                <td><span class="badge {sev_class}">{f.severity}</span></td>
                <td>{f.category}</td>
                <td>{f.name}</td>
                <td><code>{f.url}</code></td>
                <td>{f.description}</td>
                <td class="fix">{f.remediation}</td>
            </tr>"""
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PyVulnScan Report — {self.target}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
  .meta {{ color: #64748b; font-size: 0.9rem; margin-bottom: 2rem; }}
  .score-box {{ background: #1e293b; border-radius: 12px; padding: 2rem; text-align: center; margin-bottom: 2rem; }}
  .score-num {{ font-size: 4rem; font-weight: 700; color: {score_color}; }}
  .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin-bottom: 2rem; }}
  .stat {{ background: #1e293b; border-radius: 8px; padding: 1rem; text-align: center; }}
  .stat-count {{ font-size: 2rem; font-weight: 700; }}
  .stat-label {{ font-size: 0.8rem; color: #94a3b8; }}
  .critical {{ color: #ef4444; }} .high {{ color: #f97316; }} .medium {{ color: #eab308; }}
  .low {{ color: #a3a3a3; }} .info {{ color: #38bdf8; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #1e293b; padding: 0.75rem; text-align: left; font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; }}
  td {{ padding: 0.75rem; border-bottom: 1px solid #1e293b; font-size: 0.85rem; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
  .sev-critical {{ background: #7f1d1d; color: #fca5a5; }}
  .sev-high {{ background: #7c2d12; color: #fdba74; }}
  .sev-medium {{ background: #713f12; color: #fde047; }}
  .sev-low {{ background: #3f3f46; color: #a1a1aa; }}
  .sev-info {{ background: #0c4a6e; color: #7dd3fc; }}
  .fix {{ color: #94a3b8; font-style: italic; }}
  code {{ background: #1e293b; padding: 2px 6px; border-radius: 4px; font-size: 0.8rem; }}
  .footer {{ margin-top: 3rem; color: #475569; font-size: 0.8rem; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <h1>PyVulnScan Report</h1>
  <p class="meta">Target: {self.target} | Date: {datetime.now().strftime('%Y-%m-%d %H:%M')} | Version: {__version__}</p>
  <div class="score-box">
    <div>Security Score</div>
    <div class="score-num">{score}/100</div>
  </div>
  <div class="stats">
    <div class="stat"><div class="stat-count critical">{critical}</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-count high">{high}</div><div class="stat-label">High</div></div>
    <div class="stat"><div class="stat-count medium">{medium}</div><div class="stat-label">Medium</div></div>
    <div class="stat"><div class="stat-count low">{low}</div><div class="stat-label">Low</div></div>
    <div class="stat"><div class="stat-count info">{info}</div><div class="stat-label">Info</div></div>
  </div>
  <table>
    <thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>URL</th><th>Description</th><th>Remediation</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <div class="footer">Generated by PyVulnScan v{__version__} | {datetime.now().isoformat()}</div>
</div>
</body>
</html>"""
        
        with open(output_path, "w") as f:
            f.write(html)
        
        print(f"\n[+] HTML report saved: {output_path}")
        return output_path

    def export_json(self, output_path: str = "pyvulnscan-results.json"):
        """Export findings as JSON."""
        data = {
            "target": self.target,
            "scan_date": datetime.now().isoformat(),
            "version": __version__,
            "total_findings": len(self.findings),
            "findings": [asdict(f) for f in self.findings]
        }
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] JSON export saved: {output_path}")
        return output_path


def main():
    parser = argparse.ArgumentParser(
        description="PyVulnScan — Lightweight Web Application Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pyvulnscan.py https://example.com
  python pyvulnscan.py https://example.com -v --html report.html
  python pyvulnscan.py https://example.com --cookie "session=abc123" --json results.json
        """
    )
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--cookie", help="Cookie string (e.g., 'session=abc')")
    parser.add_argument("--header", action="append", help="Custom header (repeatable)")
    parser.add_argument("--html", metavar="FILE", help="Save HTML report to file")
    parser.add_argument("--json", metavar="FILE", help="Save JSON results to file")
    parser.add_argument("--version", action="version", version=f"PyVulnScan {__version__}")
    
    args = parser.parse_args()
    
    # Parse cookies
    cookies = {}
    if args.cookie:
        for c in args.cookie.split(";"):
            if "=" in c:
                k, v = c.strip().split("=", 1)
                cookies[k] = v
    
    # Parse headers
    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
    
    scanner = Scanner(
        target=args.target,
        timeout=args.timeout,
        verbose=args.verbose,
        cookies=cookies if cookies else None,
        headers=headers if headers else None,
    )
    
    scanner.scan()
    
    if args.html:
        scanner.generate_html_report(args.html)
    
    if args.json:
        scanner.export_json(args.json)
    
    # Default: save both if no output specified
    if not args.html and not args.json:
        scanner.generate_html_report()
        scanner.export_json()


if __name__ == "__main__":
    main()
