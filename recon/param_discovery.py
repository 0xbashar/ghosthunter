"""
ParamDiscovery — Discovers hidden, unlinked, or historical parameters
via Wayback Machine and lightweight dictionary fuzzing.
"""
from __future__ import annotations
import asyncio, aiohttp
from typing import List, Dict
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from core.logger import Logger

log = Logger.get_logger("recon_params")

# Top 50 high-value parameter names to brute-force
HIGH_VALUE_PARAMS = [
    "id", "user", "url", "redirect", "file", "path", "template", 
    "next", "callback", "api", "key", "token", "admin", "debug",
    "test", "cmd", "exec", "query", "search", "page", "doc",
    "image", "proxy", "host", "port", "action", "run", "name",
    "email", "account", "uid", "uuid", "ref", "site", "target"
]

class ParamDiscovery:
    def __init__(self, http, scan_cfg):
        self.http = http
        self.cfg = scan_cfg

    async def discover(self, endpoints: List[Dict]):
        log.info(f"Mining parameters for {len(endpoints)} endpoints")
        sem = asyncio.Semaphore(20)
        
        async def _process(ep):
            async with sem:
                # 1. Extract from Wayback Machine
                wayback_params = await self._wayback_params(ep["url"])
                
                # 2. Fuzz High-Value Params
                fuzz_params = await self._fuzz_params(ep)
                
                # Merge discovered params into endpoint object
                existing_params = {p["name"].lower() for p in ep.get("params", [])}
                
                for p_name in wayback_params + fuzz_params:
                    if p_name.lower() not in existing_params:
                        ep.setdefault("params", []).append({"name": p_name, "type": "text", "value": ""})
        
        await asyncio.gather(*[_process(ep) for ep in endpoints])
        log.success("Parameter discovery complete. Endpoints enriched.")

    async def _wayback_params(self, url: str) -> list[str]:
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://web.archive.org/cdx/search/cdx?url={base_url}*&output=text&fl=original", timeout=5) as r:
                    if r.status == 200:
                        text = await r.text()
                        params = set()
                        for u in text.split('\n'):
                            qs = urlparse(u).query
                            if qs:
                                for k, v in parse_qsl(qs):
                                    params.add(k)
                        return list(params)
        except:
            pass
        return []

    async def _fuzz_params(self, ep: dict) -> list[str]:
        """Inject high-value params and look for response anomalies."""
        found = []
        base_url = ep["url"].split("?")[0]
        
        # Get baseline response length
        r_base = await self.http.arequest("GET", base_url)
        if not r_base: return []
        base_len = len(r_base.text)
        
        for param in HIGH_VALUE_PARAMS:
            test_url = _inject_param(base_url, param, "ghunter_test_123")
            r = await self.http.arequest("GET", test_url)
            if not r: continue
            
            # If response length changes significantly, parameter is likely processed
            if abs(len(r.text) - base_len) > 50:
                found.append(param)
        
        return found

def _inject_param(url: str, param: str, value: str) -> str:
    u = urlparse(url)
    qs = dict(parse_qsl(u.query))
    qs[param] = value
    return urlunparse(u._replace(query=urlencode(qs)))
