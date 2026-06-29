"""
SSTI — tests for Jinja2, Twig, FreeMarker, Velocity, Smarty, Mako, ERB.
Uses polyglot probe + math evaluation oracle.
"""
from __future__ import annotations
import asyncio, re, hashlib
from typing import List
from core.engine import Finding

PROBE = "{{7*7}}${7*7}<%= 7*7 %>{{= 7*7 }}#{7*7}*{7*7}@[7*7]"
ORACLES = {
    "Jinja2":  (r"49", "{{7*7}}"),
    "Twig":    (r"49", "{{7*7}}"),
    "FreeMarker": (r"49", "${7*7}"),
    "Velocity": (r"49", "#set($x=7*7)$x"),
    "Smarty":  (r"49", "{7*7}"),
    "Mako":    (r"49", "${7*7}"),
    "ERB":     (r"49", "<%= 7*7 %>"),
    "Express": (r"49", "{{= 7*7 }}"),
}

async def run(http, waf, verifier, endpoints, targets, stack, findings_sink):
    findings = []
    sem = asyncio.Semaphore(15)

    async def _test(ep, param):
        async with sem:
            url = _inject(ep["url"], param, PROBE)
            r = await http.arequest("GET", url)
            if not r: return
            body = r.text or ""
            if "49" in body and PROBE not in body:
                # Identify engine
                engine = "unknown"
                for eng, (sig, _) in ORACLES.items():
                    if sig in body:
                        engine = eng; break
                findings.append(Finding(
                    title=f"SSTI ({engine}) in {param}",
                    severity="critical", confidence=0.95,
                    category="ADV-SSTI", endpoint=ep["url"], method="GET",
                    payload=PROBE,
                    evidence=f"7*7 evaluated to 49; engine={engine}",
                    cwe="CWE-1336",
                    remediation="Use sandboxed templating; never render user input as template.",
                    tags=["ssti", "rce", "high-value"]
                ))

    params_to_test = set()
    for ep in endpoints:
        for p in ep.get("params", [{"name": "name"}]):
            if any(k in p["name"].lower() for k in ["name","q","search","template","msg","content","page","render"]):
                params_to_test.add((ep["url"], p["name"]))
    await asyncio.gather(*[_test(u, p) for u, p in params_to_test], return_exceptions=True)
    return findings

def _inject(url, param, value):
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    u = urlparse(url); qs = dict(parse_qsl(u.query)); qs[param] = value
    return urlunparse(u._replace(query=urlencode(qs)))
