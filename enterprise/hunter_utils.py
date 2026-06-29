# enterprise/hunter_utils.py
from fastapi import FastAPI, HTTPException, APIRouter
from pydantic import BaseModel
import httpx, base64, json, jwt, dns.resolver, whois, asyncio
from typing import Optional

router = APIRouter()

# --- Models ---
class HttpRequestModel(BaseModel):
    method: str
    url: str
    headers: Optional[dict] = {}
    body: Optional[str] = ""

class UtilityPayload(BaseModel):
    data: str
    key: Optional[str] = ""

# --- 1. HTTP Repeater (Mini-Burp) ---
@router.post("/api/repeater/send")
async def repeater_send(req: HttpRequestModel):
    """Send raw HTTP request and return response, simulating Burp Repeater."""
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=False) as client:
            response = await client.request(
                req.method, req.url, headers=req.headers, content=req.body, timeout=10.0
            )
            
            # Format headers for display
            resp_headers = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
            resp_body = response.text
            if "application/json" in response.headers.get("content-type", ""):
                try: resp_body = json.dumps(json.loads(resp_body), indent=2)
                except: pass
                
            return {
                "status_code": response.status_code,
                "headers": resp_headers,
                "body": resp_body,
                "time_ms": response.elapsed.total_seconds() * 1000
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- 2. Recon Tools ---
@router.get("/api/recon/dns/{domain}")
async def dns_lookup(domain: str):
    """Perform DNS reconnaissance."""
    records = {"A": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}
    for type in records.keys():
        try:
            answers = dns.resolver.resolve(domain, type)
            records[type] = [str(r) for r in answers]
        except: pass
    return records

@router.get("/api/recon/whois/{domain}")
async def whois_lookup(domain: str):
    """Fetch WHOIS info."""
    try:
        w = whois.whois(domain)
        return {"domain": w.domain_name, "registrar": w.registrar, "creation_date": str(w.creation_date), "emails": w.emails}
    except Exception as e:
        return {"error": str(e)}

# --- 3. Utility Belt ---
@router.post("/api/utils/encode")
async def encode_data(payload: UtilityPayload):
    """Multiple encoding formats."""
    data = payload.data.encode()
    return {
        "base64": base64.b64encode(data).decode(),
        "url": __import__("urllib").parse.quote(payload.data),
        "hex": data.hex(),
        "html": __import__("html").escape(payload.data)
    }

@router.post("/api/utils/decode")
async def decode_data(payload: UtilityPayload):
    """Auto-detect and decode."""
    data = payload.data
    result = {}
    try: result["base64"] = base64.b64decode(data).decode()
    except: result["base64"] = "Invalid Base64"
    try: result["url"] = __import__("urllib").parse.unquote(data)
    except: result["url"] = "Invalid URL"
    try: result["hex"] = bytes.fromhex(data).decode()
    except: result["hex"] = "Invalid Hex"
    return result

@router.post("/api/utils/jwt")
async def jwt_analyzer(payload: UtilityPayload):
    """Decode and analyze JWT."""
    token = payload.data
    try:
        header = jwt.get_unverified_header(token)
        decoded = jwt.decode(token, options={"verify_signature": False})
        return {"header": header, "payload": decoded, "algorithm": header.get("alg")}
    except Exception as e:
        return {"error": str(e)}
