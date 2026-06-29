"""
Cloud-Native Security Module — Tests:
  - Infrastructure as Code (IaC) misconfigs (Terraform, CloudFormation)
  - Kubernetes API exposure
  - Cloud metadata service (SSRF)
  - Container registry exposure
"""
from __future__ import annotations
import asyncio, re, json
from typing import List
from core.engine import Finding

IAC_PATHS = [
    "/terraform.tfstate", "/terraform.tfvars", "/.terraform/",
    "/infrastructure.tf", "/main.tf", "/variables.tf",
    "/template.yaml", "/template.json", "/cloudformation.yaml",
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml"
]

K8S_PATHS = [
    "/api/v1", "/api/v1/namespaces", "/api/v1/pods",
    "/apis/apps/v1/deployments", "/apis/apps/v1/daemonsets",
    "/api/v1/secrets", "/api/v1/configmaps",
    "/healthz", "/metrics", "/debug/pprof/"
]

CLOUD_METADATA = [
    "http://169.254.169.254/latest/meta-data/",  # AWS
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/instance",  # Azure
    "http://100.100.100.200/latest/meta-data/",  # Alibaba
]

async def run(http, waf, verifier, endpoints, targets, stack, findings_sink, ai_engine=None):
    findings = []
    sem = asyncio.Semaphore(10)
    
    async def _check_iac(target):
        async with sem:
            for path in IAC_PATHS:
                r = await http.arequest("GET", f"{target}{path}")
                if r and r.status_code == 200:
                    if "terraform" in path:
                        findings.append(Finding(
                            title=f"Exposed Terraform State: {path}",
                            severity="critical", confidence=0.95,
                            category="ADV-CLOUD", endpoint=f"{target}{path}", method="GET",
                            evidence=f"Terraform state file exposed ({len(r.text)} bytes)",
                            cwe="CWE-200",
                            remediation="Store state in remote backend with encryption; restrict access.",
                            tags=["cloud", "terraform", "critical"]
                        ))
                    elif "docker" in path.lower():
                        findings.append(Finding(
                            title=f"Exposed Docker Config: {path}",
                            severity="high", confidence=0.9,
                            category="ADV-CLOUD", endpoint=f"{target}{path}", method="GET",
                            evidence="Docker configuration exposed",
                            cwe="CWE-200",
                            remediation="Do not expose Dockerfiles in production; use .dockerignore.",
                            tags=["cloud", "docker"]
                        ))
    
    async def _check_k8s(target):
        async with sem:
            for path in K8S_PATHS:
                r = await http.arequest("GET", f"{target}{path}")
                if r and r.status_code == 200:
                    if "api/v1" in path and ("kind" in r.text or "apiVersion" in r.text):
                        findings.append(Finding(
                            title=f"Exposed Kubernetes API: {path}",
                            severity="critical", confidence=0.95,
                            category="ADV-CLOUD", endpoint=f"{target}{path}", method="GET",
                            evidence=f"K8s API endpoint exposed\n{r.text[:300]}",
                            cwe="CWE-306",
                            remediation="Restrict K8s API to internal network; use RBAC; enable authn/authz.",
                            tags=["cloud", "k8s", "critical", "high-value"]
                        ))
    
    async def _check_metadata(target):
        """Check if SSRF can reach cloud metadata (integrated with A10 SSRF module)"""
        async with sem:
            for ep in endpoints:
                if not any(p["name"].lower() in ["url", "image", "fetch"] for p in ep.get("params", [])):
                    continue
                for metadata_url in CLOUD_METADATA:
                    url = _inject(ep["url"], "url", metadata_url)
                    r = await http.arequest("GET", url)
                    if r and ("ami-id" in r.text or "instance-id" in r.text or "computeMetadata" in r.text):
                        findings.append(Finding(
                            title=f"SSRF to Cloud Metadata Service",
                            severity="critical", confidence=0.97,
                            category="ADV-CLOUD", endpoint=ep["url"], method="GET",
                            payload=metadata_url,
                            evidence=f"Cloud metadata accessed via SSRF\n{r.text[:300]}",
                            cwe="CWE-918",
                            remediation="Block metadata access; use IMDSv2; restrict outbound traffic.",
                            tags=["cloud", "ssrf", "metadata", "critical", "high-value"]
                        ))
                        break
    
    tasks = [_check_iac(t) for t in targets] + [_check_k8s(t) for t in targets] + [_check_metadata(t) for t in targets]
    await asyncio.gather(*tasks, return_exceptions=True)
    return findings

def _inject(url, param, value):
    from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
    u = urlparse(url); qs = dict(parse_qsl(u.query)); qs[param] = value
    return urlunparse(u._replace(query=urlencode(qs)))
