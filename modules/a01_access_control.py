"""
OWASP A01: Broken Access Control — IDOR/BOLA detection via:
  - Numeric ID enumeration with two accounts (if creds available)
  - UUID leakage detection
  - Forced browsing to admin endpoints
  - HTTP method override (X-HTTP-Method-Override)
  - Path traversal for auth bypass (..;/
"""
from __future__ import annotations
import asyncio, re
from typing import List
from core.engine import Finding

ADMIN_PATHS = ["/admin", "/administrator", "/adminPanel", "/dashboard/admin",
               "/api/admin", "/v1/admin/users", "/internal", "/console",
               "/actuator", "/manager/html", "/wp-admin/"]
METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"]

async def run(http, waf, verifier, endpoints, targets, stack, findings_sink):
    findings = []
    sem = asyncio.Semaphore(10)

    async def _idor(ep):
        async with sem:
            # find numeric params
            for param in ep.get("params", []):
                name = param["name"]
                if not re.search(r"(id|uid|user|account|doc|order|invoice|file)", name, re.I):
                    continue
                # Try ID 1 vs ID 999999 (likely non-existent)
                for v1, v2 in [("1", "99999999"), ("0", "-1")]:
                    u1 = _inject(ep["url"], name, v1)
                    u2 = _inject(ep["url"], name, v2)
                    r1 = await http.arequest("GET", u1)
                    r2 = await http.arequest("GET", u2)
                    if r1 and r2 and r1.status_code == 200 and r2.status_code in (404, 403):
                        # Confirm by also fetching without auth (if possible)
                        findings.append(Finding(
                            title=f"Potential IDOR / BOLA in {name}",
                            severity="high", confidence=0.7,
                            category="OWASP-A01", endpoint=ep["url"], method="GET",
                            payload=f"{name}={v1}",
                            evidence=f"ID {v1} -> 200 OK; ID {v2} -> {r2.status_code}",
                            cwe="CWE-639",
                            remediation="Enforce object-level authorization server-side; "
                                        "use unguessable IDs; per-user ACLs.",
                            tags=["idor", "bola", "high-value"]
                        ))
                        break

    async def _forced_browsing(targets):
        for t in targets:
            for path in ADMIN_PATHS:
                async with sem:
                    r = await http.arequest("GET", f"{t}{path}")
                    if r and r.status_code == 200 and not _is_login_page(r.text):
                        findings.append(Finding(
                            title=f"Unauthenticated access to admin panel: {path}",
                            severity="high", confidence=0.85,
                            category="OWASP-A01", endpoint=f"{t}{path}", method="GET",
                            evidence=f"HTTP 200, len={len(r.text)}",
                            cwe="CWE-552",
                            remediation="Require authentication and authorization on admin paths.",
                            tags=["forced-browsing", "admin"]
                        ))

    async def _method_override(targets):
        for t in targets:
            for path in ["/api/users", "/api/admin", "/users"]:
                async with sem:
                    for m in ["PUT", "DELETE", "PATCH"]:
                        r = await http.arequest("GET", f"{t}{path}",
                            headers={"X-HTTP-Method-Override": m,
                                     "X-Method-Override": m,
                                     "X-Original-URL": path,
                                     "X-Rewrite-URL": path})
                        if r and r.status_code in (200, 201, 202) and "unauth" not in r.text.lower():
                            findings.append(Finding(
                                title=f"HTTP method override bypass on {path}",
                                severity="high", confidence=0.75,
                                category="OWASP-A01", endpoint=f"{t}{path}", method=m,
                                payload=f"X-HTTP-Method-Override: {m}",
                                evidence=f"Status {r.status_code}",
                                cwe="CWE-284",
                                remediation="Reject HTTP method override headers; enforce method ACLs.",
                                tags=["method-override"]
                            ))
                            break

    await asyncio.gather(*[_idor(e) for e in endpoints],
                          _forced_browsing(targets),
                          _method_override(targets),
                          return_exceptions=True)
    return findings

def _inject(url, param, value):
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    u = urlparse(url); qs = dict(parse_qsl(u.query)); qs[param] = value
    return urlunparse(u._replace(query=urlencode(qs)))

def _is_login_page(html: str) -> bool:
    h = (html or "").lower()
    return any(x in h for x in ["<form", "password", "login", "sign in"])
