"""
GhostHunter Engine — orchestrates recon, modules, WAF evasion, verification,
and reporting. Designed for high-signal / low-noise bug hunting.
"""
from __future__ import annotations
import asyncio, importlib, time, traceback
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from pathlib import Path

from core.logger import Logger
from core.anonymizer import Anonymizer
from core.http_client import HTTPClient
from core.verifier import Verifier
from recon.subdomains import SubdomainEnumerator
from recon.crawler import Crawler
from recon.js_analyzer import JSAnalyzer
from recon.param_discovery import ParamDiscovery
from recon.tech_detect import TechDetector
from waf.bypass import WAFBypass
from reporters.json_reporter import JSONReporter
from reporters.html_reporter import HTMLReporter

log = Logger.get_logger("engine")

@dataclass
class Finding:
    title: str
    severity: str           # critical | high | medium | low | info
    confidence: float       # 0.0 - 1.0
    category: str           # OWASP A01..A10, or "ADV-XXX"
    endpoint: str
    method: str
    payload: Optional[str] = None
    evidence: str = ""
    request: str = ""
    response_snippet: str = ""
    cwe: str = ""
    remediation: str = ""
    tags: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

class GhostHunterEngine:
    def __init__(self, config: Dict[str, Any]):
        self.cfg = config
        self.anonymizer = Anonymizer(config["anonymity"])
        self.http = HTTPClient(config["http"], self.anonymizer)
        self.waf = WAFBypass(self.http, config["waf"])
        self.verifier = Verifier(self.http, config["scanning"])
        self.findings: List[Finding] = []
        self.targets: List[str] = []
        self.endpoints: List[Dict] = []

    async def run(self, domain: str):
        log.header(f"GHOSTHUNTER :: Targeting {domain}")
        await self.anonymizer.bootstrap()
        self.waf.detect(domain)

        # ---- Phase 1: Recon ----
        log.phase("Phase 1 :: Subdomain Enumeration")
        subs = await SubdomainEnumerator(self.http).enumerate(domain)
        log.info(f"Discovered {len(subs)} subdomains")
        self.targets = subs[:50] if self.cfg["target"].get("scope_only", True) else [domain]

        log.phase("Phase 2 :: Crawling & Endpoint Collection")
        for t in self.targets:
            endpoints = await Crawler(self.http, self.cfg["target"]).crawl(t)
            self.endpoints.extend(endpoints)
        log.info(f"Collected {len(self.endpoints)} endpoints")

        log.phase("Phase 3 :: JS Analysis & Param Discovery")
        js_secrets = await JSAnalyzer(self.http).analyze_many(self.endpoints)
        for s in js_secrets:
            self.findings.append(s)

        await ParamDiscovery(self.http, self.cfg["scanning"]).discover(self.endpoints)

        log.phase("Phase 4 :: Tech Fingerprinting")
        stack = await TechDetector(self.http).detect(self.targets[0])
        log.info(f"Stack: {stack}")

        # ---- Phase 5: Vulnerability modules ----
        log.phase("Phase 5 :: Active Vulnerability Hunting")
        await self._run_modules(stack)

        # ---- Phase 6: Verification & de-duplication ----
        log.phase("Phase 6 :: Verification & Triaging")
        self.findings = await self._verify_all()

        # ---- Phase 7: Reporting ----
        log.phase("Phase 7 :: Reporting")
        self._report(domain)
        log.success(f"Done. {len(self.findings)} high-confidence findings.")

    async def _run_modules(self, stack: Dict[str, str]):
        modules = [
            "modules.a01_access_control",
            "modules.a03_injection",
            "modules.a05_misconfig",
            "modules.a07_auth",
            "modules.a10_ssrf",
            "modules.advanced_ssti",
            "modules.advanced_xxe",
            "modules.advanced_graphql",
            "modules.advanced_oauth",
            "modules.advanced_jwt",
            "modules.advanced_cors",
        ]
        sem = asyncio.Semaphore(self.cfg["target"]["threads"])

        async def _run(mod_name: str):
            async with sem:
                try:
                    mod = importlib.import_module(mod_name)
                    runner = getattr(mod, "run")
                    results = await runner(
                        http=self.http,
                        waf=self.waf,
                        verifier=self.verifier,
                        endpoints=self.endpoints,
                        targets=self.targets,
                        stack=stack,
                        findings_sink=self.findings,
                    )
                    if results:
                        self.findings.extend(results)
                except Exception as e:
                    log.err(f"{mod_name} failed: {e}\n{traceback.format_exc()}")

        await asyncio.gather(*[_run(m) for m in modules])

    async def _verify_all(self) -> List[Finding]:
        verified = []
        for f in self.findings:
            if f.confidence >= self.cfg["scanning"]["false_positive_threshold"]:
                verified.append(f)
        # de-duplicate by (endpoint, category, payload)
        seen = set()
        deduped = []
        for f in verified:
            key = (f.endpoint, f.category, str(f.payload))
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    def _report(self, domain: str):
        out = Path(self.cfg["reporting"]["output_dir"]) / domain
        out.mkdir(parents=True, exist_ok=True)
        if "json" in self.cfg["reporting"]["formats"]:
            JSONReporter().dump(self.findings, out / "report.json")
        if "html" in self.cfg["reporting"]["formats"]:
            HTMLReporter().dump(self.findings, out / "report.html")
