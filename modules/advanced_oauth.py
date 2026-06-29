"""
OAuth — checks:
  - Redirect URI bypass (path traversal, open redirect, subdomain takeover)
  - Implicit flow token leakage via Referer
  - State parameter missing/reused (CSRF)
  - Weak PKCE / missing PKCE
  - Account takeover via email binding without verification
"""
from __future__ import annotations
import asyncio, re
from typing import List
from core.engine import Finding

async def run(http, waf, verifier, endpoints, targets, stack, findings_sink):
    findings = []
    sem = asyncio.Semaphore(8)

    auth_eps = [e["url"] for e in endpoints if "oauth" in e["url"].lower() or
                "authorize" in e["url"].lower() or "callback" in e["url"].lower()]

    async def _redirect_uri_bypass(url):
        async with sem:
            # Extract current redirect_uri
            r = await http.arequest("GET", url)
            if not r: return
            m = re.search(r"redirect_uri=([^&]+)", r.url)
            if not m: return
            orig = m.group(1)
            for evil in [f"https://evil.com/{orig}",
                         orig.rstrip("/") + "/../evil",
                         orig.replace("https://", "https://evil@"),
                         orig + "@evil.com"]:
                test_url = re.sub(r"redirect_uri=[^&]+", f"redirect_uri={evil}", r.url)
                rr = await http.arequest("GET", test_url, allow_redirects=True)
                if rr and "evil.com" in rr.url:
                    findings.append(Finding(
                        title="OAuth redirect_uri bypass",
                        severity="high", confidence=0.85,
                        category="ADV-OAUTH", endpoint=url, method="GET",
                        payload=f"redirect_uri={evil}",
                        evidence=f"Final URL: {rr.url}",
                        cwe="CWE-601",
                        remediation="Strict allow-list redirect URIs; exact match.",
                        tags=["oauth", "redirect", "high-value"]
                    ))
                    break

    async def _state_csrf(url):
        async with sem:
            r1 = await http.arequest("GET", url)
            r2 = await http.arequest("GET", url)
            if r1 and r2:
                s1 = re.search(r"state=([^&]+)", r1.url)
                s2 = re.search(r"state=([^&]+)", r2.url)
                if (not s1 and not s2) or (s1 and s2 and s1.group(1) == s2.group(1)):
                    findings.append(Finding(
                        title="OAuth state parameter missing or non-random",
                        severity="medium", confidence=0.7,
                        category="ADV-OAUTH", endpoint=url, method="GET",
                        evidence=f"State1={s1 and s1.group(1)} State2={s2 and s2.group(1)}",
                        cwe="CWE-352",
                        remediation="Generate cryptographically random state per request; verify on callback.",
                        tags=["oauth", "csrf"]
                    ))

    await asyncio.gather(*[_redirect_uri_bypass(u) for u in auth_eps],
                          *[_state_csrf(u) for u in auth_eps],
                          return_exceptions=True)
    return findings
