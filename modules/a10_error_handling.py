"""
OWASP A10:2025 - Mishandling of Exceptional Conditions
Fuzzes endpoints to trigger:
  - Unhandled exceptions (500 errors)
  - Stack traces in responses
  - Race conditions in state-changing endpoints
  - DoS via resource exhaustion
"""
from __future__ import annotations
import asyncio, re, time, json
from typing import List
from core.engine import Finding

# Fuzzing payloads to trigger errors
FUZZ_PAYLOADS = [
    # Type confusion
    {"json": "string"}, {"array": [1,2,3]}, {"object": {"nested": True}},
    # Extreme values
    {"id": -1}, {"id": 999999999999}, {"id": 0}, {"id": 2**31},
    # Null/empty
    {"id": None}, {"id": ""}, {"id": "null"}, {"id": "undefined"},
    # Malformed
    {"id": "1' OR '1'='1"}, {"id": "<script>"}, {"id": "../../../etc/passwd"},
    # Nested objects
    {"user": {"id": {"$gt": ""}}}, {"data": {"__proto__": {"isAdmin": True}}},
    # Array manipulation
    {"ids": [1,2,3,4,5,6,7,8,9,10]}, {"ids": ["1","2","3"]},
]

RACE_CONDITION_ENDPOINTS = [
    "/api/transfer", "/api/withdraw", "/api/vote", "/api/checkout",
    "/api/coupon/apply", "/api/referral", "/api/like", "/api/follow"
]

async def run(http, waf, verifier, endpoints, targets, stack, findings_sink, ai_engine=None):
    findings = []
    sem = asyncio.Semaphore(10)
    
    async def _fuzz(ep):
        async with sem:
            for payload in FUZZ_PAYLOADS:
                # Test as JSON body
                r = await http.arequest("POST", ep["url"], json=payload,
                    headers={"Content-Type": "application/json"})
                if not r: continue
                
                # Check for stack traces
                if r.status_code >= 500:
                    stack_trace = re.search(
                        r'(Traceback|Exception|Error|at\s[\w\.]+\s\([^)]+\)|\s+at\s)',
                        r.text, re.I
                    )
                    if stack_trace:
                        findings.append(Finding(
                            title=f"Unhandled Exception (Stack Trace) at {ep['url']}",
                            severity="high", confidence=0.85,
                            category="OWASP-A10", endpoint=ep["url"], method="POST",
                            payload=json.dumps(payload),
                            evidence=f"HTTP {r.status_code}\n{stack_trace.group(0)}\n{r.text[:300]}",
                            cwe="CWE-209",
                            remediation="Implement global exception handlers; return generic errors; log internally.",
                            tags=["error-handling", "stack-trace", "high-value"]
                        ))
                
                # Check for DoS indicators (response time > 10s)
                elif r.elapsed.total_seconds() > 10:
                    findings.append(Finding(
                        title=f"Potential DoS via Resource Exhaustion at {ep['url']}",
                        severity="medium", confidence=0.7,
                        category="OWASP-A10", endpoint=ep["url"], method="POST",
                        payload=json.dumps(payload),
                        evidence=f"Response time: {r.elapsed.total_seconds():.1f}s",
                        cwe="CWE-400",
                        remediation="Implement rate limiting, timeouts, and resource quotas.",
                        tags=["error-handling", "dos"]
                    ))

    async def _race_condition(ep):
        """Test for race conditions by sending concurrent requests."""
        if not any(x in ep["url"] for x in RACE_CONDITION_ENDPOINTS):
            return
            
        async with sem:
            # Send 20 concurrent requests with same payload
            payload = {"amount": 100, "to_user": "attacker"}
            tasks = []
            for _ in range(20):
                tasks.append(http.arequest("POST", ep["url"], json=payload,
                    headers={"Content-Type": "application/json"}))
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            success_count = sum(1 for r in responses if r and r.status_code in (200, 201))
            
            # If more than 1 succeeds, potential race condition
            if success_count > 1:
                findings.append(Finding(
                    title=f"Race Condition in {ep['url']}",
                    severity="critical", confidence=0.9,
                    category="OWASP-A10", endpoint=ep["url"], method="POST",
                    payload=json.dumps(payload),
                    evidence=f"{success_count}/20 concurrent requests succeeded",
                    cwe="CWE-362",
                    remediation="Use database transactions, locking, or idempotency keys.",
                    tags=["error-handling", "race-condition", "critical", "high-value"]
                ))

    tasks = [_fuzz(ep) for ep in endpoints] + [_race_condition(ep) for ep in endpoints]
    await asyncio.gather(*tasks, return_exceptions=True)
    return findings
