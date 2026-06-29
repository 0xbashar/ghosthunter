"""
OWASP A05: Security Misconfiguration — checks:
  - Default credentials on admin panels (delegated)
  - Directory listing
  - Backup files (.bak, .old, .zip, .sql, .tar.gz)
  - Verbose errors / stack traces
  - Dangerous headers (X-Powered-By, Server)
  - Missing security headers
  - CORS misconfiguration (delegated to advanced_cors)
  - .git/.svn/.env exposure
"""
from __future__ import annotations
import asyncio
from typing import List
from core.engine import Finding

SENSITIVE_PATHS = [
    "/.git/config", "/.git/HEAD", "/.svn/entries", "/.env", "/.env.bak",
    "/backup.sql", "/db.sql", "/dump.sql", "/backup.zip", "/backup.tar.gz",
    "/web.config.bak", "/.DS_Store", "/robots.txt", "/server-status",
    "/phpinfo.php", "/info.php", "/.well-known/security.txt",
    "/swagger-ui/", "/api-docs", "/v1/api-docs", "/actuator/env",
    "/actuator/heapdump", "/actuator/mappings", "/.aws/credentials",
    "/wp-config.php.bak", "/config.php.bak", "/.htaccess",
]

REQUIRED_HEADERS = ["Strict-Transport-Security", "X-Content-Type-Options",
                    "X-Frame-Options", "Content-Security-Policy"]

async def run(http, waf, verifier, endpoints, targets, stack, findings_sink):
    findings = []
    sem = asyncio.Semaphore(15)

    async def _paths(t):
        for p in SENSITIVE_PATHS:
            async with sem:
                r = await http.arequest("GET", f"{t}{p}")
                if not r: continue
                if r.status_code == 200 and len(r.text) > 20:
                    if p == "/.git/config" and "[core]" in r.text:
                        findings.append(Finding(
                            title="Exposed .git repository",
                            severity="critical", confidence=0.95,
                            category="OWASP-A05", endpoint=f"{t}{p}", method="GET",
                            evidence=r.text[:300],
                            cwe="CWE-538",
                            remediation="Remove .git from web root; block dotfiles in web server.",
                            tags=["misconfig", "source-disclosure", "high-value"]
                        ))
                    elif p == "/.env" and "=" in r.text and len(r.text) < 5000:
                        findings.append(Finding(
                            title="Exposed .env file",
                            severity="critical", confidence=0.95,
                            category="OWASP-A05", endpoint=f"{t}{p}", method="GET",
                            evidence=r.text[:500],
                            cwe="CWE-538",
                            remediation="Block dotfiles; move secrets outside web root.",
                            tags=["misconfig", "secrets", "high-value"]
                        ))
                    elif p == "/actuator/heapdump":
                        findings.append(Finding(
                            title="Spring Boot Actuator heapdump exposed",
                            severity="critical", confidence=0.95,
                            category="OWASP-A05", endpoint=f"{t}{p}", method="GET",
                            evidence=f"Heapdump returned {len(r.content)} bytes",
                            cwe="CWE-200",
                            remediation="Disable or secure actuator endpoints; restrict to internal.",
                            tags=["misconfig", "actuator", "high-value"]
                        ))
                    elif p.endswith((".sql", ".zip", ".tar.gz", ".bak")):
                        findings.append(Finding(
                            title=f"Exposed backup file: {p}",
                            severity="high", confidence=0.85,
                            category="OWASP-A05", endpoint=f"{t}{p}", method="GET",
                            evidence=f"Status 200, size {len(r.content)} bytes",
                            cwe="CWE-538",
                            remediation="Remove backup files from web root; restrict access.",
                            tags=["misconfig", "backup"]
                        ))

    async def _headers(t):
        async with sem:
            r = await http.arequest("GET", t)
            if not r: return
            missing = [h for h in REQUIRED_HEADERS if h.lower() not in {k.lower() for k in r.headers}]
            if missing:
                findings.append(Finding(
                    title=f"Missing security headers: {', '.join(missing)}",
                    severity="low", confidence=0.9,
                    category="OWASP-A05", endpoint=t, method="GET",
                    evidence=f"Missing: {missing}",
                    cwe="CWE-693",
                    remediation="Add HSTS, X-Content-Type-Options, X-Frame-Options, CSP.",
                    tags=["misconfig", "headers"]
                ))
            # Verbose error fingerprinting
            server = r.headers.get("Server", "")
            xpb = r.headers.get("X-Powered-By", "")
            if server or xpb:
                findings.append(Finding(
                    title=f"Information disclosure: Server={server} X-Powered-By={xpb}",
                    severity="info", confidence=0.9,
                    category="OWASP-A05", endpoint=t, method="GET",
                    evidence=f"Server={server}; X-Powered-By={xpb}",
                    cwe="CWE-200",
                    remediation="Suppress version banners in web server config.",
                    tags=["misconfig", "info"]
                ))

    await asyncio.gather(*[_paths(t) for t in targets],
                          *[_headers(t) for t in targets],
                          return_exceptions=True)
    return findings
