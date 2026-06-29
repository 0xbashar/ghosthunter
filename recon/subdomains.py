"""
SubdomainEnumerator — Passive enumeration via certificate transparency logs
and search engine caches. Resolves alive hosts asynchronously.
"""
from __future__ import annotations
import asyncio, aiohttp, re
from urllib.parse import urlparse
from core.logger import Logger
import aiodns

log = Logger.get_logger("recon_subs")

class SubdomainEnumerator:
    def __init__(self, http):
        self.http = http
        self.resolver = aiodns.DNSResolver()

    async def enumerate(self, domain: str) -> list[str]:
        log.info(f"Starting passive subdomain enumeration for {domain}")
        tasks = [
            self._crtsh(domain),
            self._hackertarget(domain),
            self._wayback(domain)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        unique_subs = set()
        for res in results:
            if isinstance(res, list):
                unique_subs.update(res)
        
        # Resolve alive hosts
        alive = await self._resolve_hosts(list(unique_subs))
        log.success(f"Found {len(alive)} alive subdomains out of {len(unique_subs)} passive records")
        return alive

    async def _crtsh(self, domain: str) -> list[str]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10) as r:
                    if r.status == 200:
                        data = await r.json()
                        return [entry['name_value'].split('\n')[0].lower() for entry in data if 'name_value' in entry]
        except Exception as e:
            log.debug(f"crt.sh failed: {e}")
        return []

    async def _hackertarget(self, domain: str) -> list[str]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10) as r:
                    if r.status == 200:
                        text = await r.text()
                        return [line.split(',')[0].lower() for line in text.split('\n') if line]
        except Exception as e:
            log.debug(f"hackertarget failed: {e}")
        return []

    async def _wayback(self, domain: str) -> list[str]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey", timeout=10) as r:
                    if r.status == 200:
                        text = await r.text()
                        subs = set()
                        for url in text.split('\n'):
                            parsed = urlparse(url)
                            if parsed.netloc and domain in parsed.netloc:
                                subs.add(parsed.netloc.lower())
                        return list(subs)
        except Exception as e:
            log.debug(f"wayback failed: {e}")
        return []

    async def _resolve_hosts(self, hosts: list[str]) -> list[str]:
        alive = []
        sem = asyncio.Semaphore(50)
        
        async def _check(host):
            async with sem:
                try:
                    await self.resolver.gethostbyname(host, socket.AF_INET)
                    alive.append(host)
                except:
                    pass # Dead host
        
        await asyncio.gather(*[_check(h) for h in hosts])
        return alive

import socket # needed for AF_INET
