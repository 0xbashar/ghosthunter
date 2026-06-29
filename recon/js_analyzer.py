"""
JSAnalyzer — fetches JS assets, extracts API endpoints, secrets, tokens,
cloud keys, internal URLs. Reports as info/medium findings.
"""
from __future__ import annotations
import re, asyncio
from typing import List
from core.engine import Finding

PATTERNS = {
    "AWS Access Key":  r"AKIA[0-9A-Z]{16}",
    "AWS Secret":      r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}",
    "GCP API Key":     r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Key":      r"sk_live_[0-9a-zA-Z]{24}",
    "Slack Token":     r"xox[baprs]-[0-9a-zA-Z-]{10,}",
    "JWT":             r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Firebase URL":    r"https?://[a-z0-9-]+\.firebaseio\.com",
    "Private Key":     r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) PRIVATE KEY-----",
    "Generic Secret":  r"(?i)(api[_-]?key|secret|token|passwd|password)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,})[\"']",
    "Internal IP":     r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
    "GraphQL EP":      r"/graphql\b",
    "API EP":          r"/api/v\d+/[a-z0-9_/-]+",
}

class JSAnalyzer:
    def __init__(self, http):
        self.http = http

    async def analyze_many(self, endpoints: List[dict]) -> List[Finding]:
        js_eps = [e for e in endpoints if e["url"].endswith(".js") or
                  "javascript" in e.get("headers", {}).get("Content-Type", "")]
        findings = []
        sem = asyncio.Semaphore(20)
        async def _a(e):
            async with sem:
                r = await self.http.arequest("GET", e["url"])
                if not r: return
                for name, pat in PATTERNS.items():
                    for m in re.findall(pat, r.text):
                        sev = "high" if "Key" in name or "Secret" in name or "Private" in name else "info"
                        findings.append(Finding(
                            title=f"Exposed {name} in JS",
                            severity=sev, confidence=0.9,
                            category="RECON-JS",
                            endpoint=e["url"], method="GET",
                            evidence=str(m)[:200],
                            cwe="CWE-200",
                            remediation="Remove sensitive data from client-side code; rotate leaked credentials.",
                            tags=["js", "secret"]
                        ))
        await asyncio.gather(*[_a(e) for e in js_eps])
        return findings
