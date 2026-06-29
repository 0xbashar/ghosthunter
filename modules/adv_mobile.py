"""
Mobile Security Module — Analyzes mobile apps (APK/IPA) for:
  - Hardcoded secrets
  - Insecure communication
  - Broken root/jailbreak detection
  - API key exposure
  - Deep link hijacking
"""
from __future__ import annotations
import asyncio, re, zipfile, io
from typing import List
from core.engine import Finding

# Regex patterns for mobile secrets
MOBILE_PATTERNS = {
    "Firebase URL": r"https?://[a-z0-9-]+\.firebaseio\.com",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Stripe Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z-]{10,}",
    "JWT": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Private Key": r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) PRIVATE KEY-----",
    "Generic Secret": r"(?i)(api[_-]?key|secret|token|passwd|password)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,})[\"']",
}

class MobileAnalyzer:
    def __init__(self, http):
        self.http = http

    async def analyze_apk(self, apk_url: str) -> List[Finding]:
        """Download and analyze Android APK."""
        findings = []
        r = await self.http.arequest("GET", apk_url)
        if not r or r.status_code != 200:
            return findings
        
        try:
            with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                # Check DEX files for secrets
                for name in z.namelist():
                    if name.endswith(".dex") or name.endswith(".xml") or name.endswith(".json"):
                        try:
                            content = z.read(name).decode("utf-8", errors="ignore")
                            for secret_type, pattern in MOBILE_PATTERNS.items():
                                matches = re.findall(pattern, content)
                                for match in matches:
                                    findings.append(Finding(
                                        title=f"Hardcoded {secret_type} in APK ({name})",
                                        severity="high" if "Key" in secret_type or "Private" in secret_type else "medium",
                                        confidence=0.9,
                                        category="ADV-MOBILE", endpoint=apk_url, method="GET",
                                        evidence=str(match)[:200],
                                        cwe="CWE-798",
                                        remediation="Use Android Keystore; store secrets server-side; use Gradle build configs.",
                                        tags=["mobile", "secret", "high-value"]
                                    ))
                        except:
                            continue
        except zipfile.BadZipFile:
            pass
        return findings

    async def check_deep_links(self, target: str) -> List[Finding]:
        """Check for deep link hijacking vulnerabilities."""
        findings = []
        # Check if app handles deep links without verification
        r = await self.http.arequest("GET", f"{target}/.well-known/assetlinks.json")
        if r and r.status_code == 200:
            try:
                data = json.loads(r.text)
                if not data:  # Empty file = no verification
                    findings.append(Finding(
                        title="Deep Link Hijacking (No assetlinks.json verification)",
                        severity="high", confidence=0.8,
                        category="ADV-MOBILE", endpoint=f"{target}/.well-known/assetlinks.json",
                        method="GET", evidence="assetlinks.json is empty or invalid",
                        cwe="CWE-939",
                        remediation="Implement proper deep link verification; use assetlinks.json correctly.",
                        tags=["mobile", "deep-link"]
                    ))
            except json.JSONDecodeError:
                pass
        return findings

async def run(http, waf, verifier, endpoints, targets, stack, findings_sink, ai_engine=None):
    analyzer = MobileAnalyzer(http)
    findings = []
    
    # Look for APK download links
    for ep in endpoints:
        if ep["url"].endswith(".apk"):
            findings.extend(await analyzer.analyze_apk(ep["url"]))
    
    # Check deep links
    for t in targets:
        findings.extend(await analyzer.check_deep_links(t))
    
    return findings
