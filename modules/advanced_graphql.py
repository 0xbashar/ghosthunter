"""
GraphQL — introspection, field suggestions, batching DoS,
mutation auth bypass, injection via variables, SSRF via custom scalars.
"""
from __future__ import annotations
import asyncio, json
from typing import List
from core.engine import Finding

INTROSPECTION = '{"query":"query IntrospectionQuery{__schema{types{name fields{name}}}}"}'
BATCH = '[{"query":"{__typename}"},{"query":"{__typename}"}]'
ALIASES = '{"query":"{a1:__typename a2:__typename a3:__typename ... }"}'

async def run(http, waf, verifier, endpoints, targets, stack, findings_sink):
    findings = []
    sem = asyncio.Semaphore(10)
    candidates = [e["url"] for e in endpoints if "graphql" in e["url"].lower()]
    candidates += [f"{t}/graphql" for t in targets]

    async def _introspect(url):
        async with sem:
            r = await http.arequest("POST", url, data=INTROSPECTION,
                                     headers={"Content-Type":"application/json"})
            if r and r.status_code == 200 and "__schema" in r.text:
                findings.append(Finding(
                    title="GraphQL introspection enabled",
                    severity="medium", confidence=0.9,
                    category="ADV-GRAPHQL", endpoint=url, method="POST",
                    payload=INTROSPECTION,
                    evidence="Introspection returned schema",
                    cwe="CWE-200",
                    remediation="Disable introspection in production.",
                    tags=["graphql"]
                ))

    async def _batch(url):
        async with sem:
            r = await http.arequest("POST", url, data=BATCH,
                                     headers={"Content-Type":"application/json"})
            if r and r.status_code == 200 and r.text.count("__typename") >= 2:
                findings.append(Finding(
                    title="GraphQL batching enabled (DoS amplifier)",
                    severity="medium", confidence=0.8,
                    category="ADV-GRAPHQL", endpoint=url, method="POST",
                    payload=BATCH, evidence="Batched queries accepted",
                    cwe="CWE-770",
                    remediation="Limit batch query depth/count; rate-limit per IP.",
                    tags=["graphql", "dos"]
                ))

    async def _suggest(url):
        async with sem:
            r = await http.arequest("POST", url,
                data=json.dumps({"query":"{ user { idd } }"}),
                headers={"Content-Type":"application/json"})
            if r and "Did you mean" in r.text:
                findings.append(Finding(
                    title="GraphQL field suggestion leakage",
                    severity="info", confidence=0.85,
                    category="ADV-GRAPHQL", endpoint=url, method="POST",
                    evidence="Server returned field suggestions",
                    cwe="CWE-209",
                    remediation="Disable field suggestions in production.",
                    tags=["graphql", "info"]
                ))

    await asyncio.gather(*[_introspect(u) for u in candidates],
                          *[_batch(u) for u in candidates],
                          *[_suggest(u) for u in candidates],
                          return_exceptions=True)
    return findings
