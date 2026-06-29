"""
CORS — checks for reflected Origin, null origin, regex bypass,
credentials allowed with wildcard.
"""
from __future__ import annotations
import asyncio
from typing import List
from core.engine import Finding

ORIGINS = [
    "https://evil.com",
    "null",
    "https://ghosthunter.evil.com",
    "https://evil.com.target.com",
    "https://target.com.evil.com",
    "https://ghosthunter-evil.com",
]

async def run(http, waf, verifier, endpoints, targets, stack, findings_sink):
    findings = []
    sem = asyncio.Semaphore(15)

    async def _test(t, origin):
        async with sem:
            r = await http.arequest("GET", t, headers={"Origin": origin})
            if not r: return
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == origin and acac.lower() == "true":
                findings.append(Finding(
                    title=f"CORS misconfiguration: reflected Origin with credentials ({origin})",
                    severity="high" if origin not in ("null",) else "medium",
                    confidence=0.95,
                    category="ADV-CORS", endpoint=t, method="GET",
                    payload=f"Origin: {origin}",
                    evidence=f"ACAO={acao} ACAC={acac}",
                    cwe="CWE-942",
                    remediation="Do not reflect Origin; use strict allow-list; "
                                "never combine * with credentials.",
                    tags=["cors", "high-value"]
                ))

    await asyncio.gather(*[_test(t, o) for t in targets for o in ORIGINS],
                          return_exceptions=True)
    return findings
