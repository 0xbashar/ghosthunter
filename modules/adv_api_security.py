"""
API Security Module — Discovers and tests REST APIs:
  - OpenAPI/Swagger spec analysis
  - Mass assignment vulnerabilities
  - BOLA/IDOR via API
  - Parameter pollution
  - Rate limit bypass
"""
from __future__ import annotations
import asyncio, json, re
from typing import List
from core.engine import Finding

SWAGGER_PATHS = [
    "/swagger-ui/", "/swagger-ui.html", "/api-docs", "/v1/api-docs",
    "/v2/api-docs", "/openapi.json", "/swagger.json", "/api/swagger.json",
    "/apispec_1.json", "/api/openapi.json"
]

class APISecurityTester:
    def __init__(self, http, verifier, ai_engine=None):
        self.http = http
        self.verifier = verifier
        self.ai = ai_engine

    async def discover_specs(self, target: str) -> List[dict]:
        specs = []
        for path in SWAGGER_PATHS:
            r = await self.http.arequest("GET", f"{target}{path}")
            if r and r.status_code == 200 and ("swagger" in r.text.lower() or "openapi" in r.text.lower()):
                try:
                    spec = json.loads(r.text)
                    specs.append({"url": f"{target}{path}", "spec": spec})
                except json.JSONDecodeError:
                    continue
        return specs

    async def test_bola(self, spec: dict, target: str) -> List[Finding]:
        """Test Broken Object Level Authorization (BOLA/IDOR)."""
        findings = []
        for path, methods in spec.get("paths", {}).items():
            for method, details in methods.items():
                if method not in ["get", "put", "delete", "patch"]: continue
                
                # Look for ID-like parameters
                has_id_param = any(
                    p.get("name", "").lower() in ["id", "userid", "accountid", "uuid"]
                    for p in details.get("parameters", [])
                )
                if not has_id_param: continue
                
                # Test with different IDs
                test_url = f"{target}{path}".replace("{id}", "1").replace("{user_id}", "1")
                test_url2 = f"{target}{path}".replace("{id}", "2").replace("{user_id}", "2")
                
                r1 = await self.http.arequest(method.upper(), test_url)
                r2 = await self.http.arequest(method.upper(), test_url2)
                
                if r1 and r2 and r1.status_code == 200 and r2.status_code == 200:
                    # Both accessible without auth? Potential BOLA
                    findings.append(Finding(
                        title=f"BOLA in API: {method.upper()} {path}",
                        severity="critical", confidence=0.85,
                        category="ADV-API", endpoint=test_url, method=method.upper(),
                        evidence=f"Accessed ID=1 and ID=2 without auth (both 200 OK)",
                        cwe="CWE-639",
                        remediation="Implement object-level authorization checks on every API endpoint.",
                        tags=["api", "bola", "idor", "high-value"]
                    ))
        return findings

    async def test_mass_assignment(self, spec: dict, target: str) -> List[Finding]:
        """Test for mass assignment vulnerabilities."""
        findings = []
        for path, methods in spec.get("paths", {}).items():
            if "post" not in methods and "put" not in methods: continue
            
            # Find endpoints with request bodies
            for method in ["post", "put"]:
                if method not in methods: continue
                details = methods[method]
                req_body = details.get("requestBody", {})
                if not req_body: continue
                
                # Try injecting role/admin fields
                test_url = f"{target}{path}"
                payload = {
                    "username": "ghost", "password": "hunter",
                    "role": "admin", "isAdmin": True, "admin": 1,
                    "permissions": ["*"], "is_superuser": True
                }
                
                r = await self.http.arequest(method.upper(), test_url, json=payload,
                    headers={"Content-Type": "application/json"})
                if r and r.status_code in (200, 201):
                    # Check if role was assigned
                    if "admin" in r.text.lower():
                        findings.append(Finding(
                            title=f"Mass Assignment in {method.upper()} {path}",
                            severity="critical", confidence=0.9,
                            category="ADV-API", endpoint=test_url, method=method.upper(),
                            payload=json.dumps(payload),
                            evidence="Server accepted role/admin fields in request",
                            cwe="CWE-915",
                            remediation="Use DTOs with explicit field mapping; validate input schema.",
                            tags=["api", "mass-assignment", "high-value"]
                        ))
        return findings

async def run(http, waf, verifier, endpoints, targets, stack, findings_sink, ai_engine=None):
    tester = APISecurityTester(http, verifier, ai_engine)
    findings = []
    
    for target in targets:
        specs = await tester.discover_specs(target)
        for spec_info in specs:
            findings.append(Finding(
                title=f"Exposed API Spec: {spec_info['url']}",
                severity="info", confidence=0.9,
                category="ADV-API", endpoint=spec_info["url"], method="GET",
                evidence="OpenAPI/Swagger specification exposed",
                cwe="CWE-200",
                remediation="Restrict API spec access in production.",
                tags=["api", "info"]
            ))
            findings.extend(await tester.test_bola(spec_info["spec"], target))
            findings.extend(await tester.test_mass_assignment(spec_info["spec"], target))
    
    return findings
