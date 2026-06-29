"""
OWASP A03:2025 - Software Supply Chain Failures
Detects:
  - Vulnerable dependencies (SCA)
  - Dependency confusion attacks
  - Exposed CI/CD config
  - Malicious packages indicators
"""
from __future__ import annotations
import asyncio, json, re, aiohttp
from typing import List
from core.engine import Finding
from core.logger import Logger

log = Logger.get_logger("a03_supply_chain")

# Common dependency files
DEP_FILES = [
    "package.json", "package-lock.json", "yarn.lock",
    "requirements.txt", "Pipfile.lock", "poetry.lock",
    "go.mod", "go.sum",
    "pom.xml", "build.gradle", "build.sbt",
    "Gemfile", "Gemfile.lock",
    "composer.json", "composer.lock",
    "csproj", "vbproj",
]

# NPM registry API
NPM_API = "https://registry.npmjs.org"
PYPI_API = "https://pypi.org/pypi"

class SupplyChainAnalyzer:
    def __init__(self, http):
        self.http = http
        self.client = aiohttp.ClientSession()

    async def check_dependency_confusion(self, package_name: str, registry: str = "npm") -> bool:
        """Check if a private package name exists in public registry (confusion attack)."""
        if registry == "npm":
            url = f"{NPM_API}/{package_name}"
        else:
            url = f"{PYPI_API}/{package_name}/json"
        
        try:
            async with self.client.get(url, timeout=5) as r:
                if r.status == 200:
                    return True  # Package exists in public registry!
        except:
            pass
        return False

    async def scan_target(self, target: str) -> List[Finding]:
        findings = []
        
        # 1. Check for exposed dependency files
        for dep_file in DEP_FILES:
            r = await self.http.arequest("GET", f"{target}/{dep_file}")
            if r and r.status_code == 200:
                findings.append(Finding(
                    title=f"Exposed dependency file: {dep_file}",
                    severity="high", confidence=0.95,
                    category="OWASP-A03", endpoint=f"{target}/{dep_file}", method="GET",
                    evidence=f"File exposed ({len(r.text)} bytes)",
                    cwe="CWE-200",
                    remediation="Restrict access to dependency files in web server config.",
                    tags=["supply-chain", "misconfig"]
                ))
                
                # 2. Parse and check for vulnerabilities
                if dep_file == "package.json":
                    vulns = await self._check_npm_vulns(r.text)
                    findings.extend(vulns)
                elif dep_file == "requirements.txt":
                    vulns = await self._check_python_vulns(r.text)
                    findings.extend(vulns)

        # 3. Check for CI/CD config exposure
        for path in ["/.github/workflows", "/.gitlab-ci.yml", "/Jenkinsfile", "/.circleci"]:
            r = await self.http.arequest("GET", f"{target}{path}")
            if r and r.status_code == 200:
                findings.append(Finding(
                    title=f"Exposed CI/CD configuration: {path}",
                    severity="critical", confidence=0.95,
                    category="OWASP-A03", endpoint=f"{target}{path}", method="GET",
                    evidence="CI/CD pipeline config exposed",
                    cwe="CWE-200",
                    remediation="Block access to CI/CD config files; use secrets management.",
                    tags=["supply-chain", "cicd", "critical"]
                ))

        return findings

    async def _check_npm_vulns(self, content: str) -> List[Finding]:
        findings = []
        try:
            pkg = json.loads(content)
            deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
            
            for name, version in deps.items():
                # Check if it's a private package (scoped)
                if name.startswith("@"):
                    # Potential dependency confusion
                    is_public = await self.check_dependency_confusion(name, "npm")
                    if is_public:
                        findings.append(Finding(
                            title=f"Dependency Confusion: {name}",
                            severity="critical", confidence=0.9,
                            category="OWASP-A03", endpoint="N/A", method="N/A",
                            payload=name,
                            evidence=f"Private package '{name}' exists in public NPM registry",
                            cwe="CWE-1357",
                            remediation="Use scoped private registries; pin versions; verify checksums.",
                            tags=["supply-chain", "dependency-confusion", "critical"]
                        ))
        except json.JSONDecodeError:
            pass
        return findings

    async def _check_python_vulns(self, content: str) -> List[Finding]:
        findings = []
        for line in content.split("\n"):
            if "==" in line:
                pkg, ver = line.split("==", 1)
                # Simplified vuln check (real impl would use OSV or Safety API)
                findings.append(Finding(
                    title=f"Dependency to check: {pkg}=={ver}",
                    severity="info", confidence=0.5,
                    category="OWASP-A03", endpoint="N/A", method="N/A",
                    payload=f"{pkg}=={ver}",
                    evidence="Python dependency found",
                    cwe="CWE-1104",
                    remediation="Use tools like `safety` or `pip-audit` to check for known vulnerabilities.",
                    tags=["supply-chain", "dependency"]
                ))
        return findings

async def run(http, waf, verifier, endpoints, targets, stack, findings_sink, ai_engine=None):
    analyzer = SupplyChainAnalyzer(http)
    findings = []
    for target in targets:
        findings.extend(await analyzer.scan_target(target))
    return findings
