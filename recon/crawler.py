"""
Crawler — BFS over a target with form extraction, JS link discovery,
scope filtering, deduplication, and dynamic param injection points.
"""
from __future__ import annotations
import asyncio, re
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode
from bs4 import BeautifulSoup
from typing import List, Dict

class Crawler:
    def __init__(self, http, target_cfg):
        self.http = http
        self.depth = target_cfg.get("depth", 4)
        self.exclude = set(target_cfg.get("exclude", []))
        self.scope = target_cfg.get("scope", [""])

    async def crawl(self, root: str) -> List[Dict]:
        visited, results = set(), []
        queue = [(root, 0)]
        sem = asyncio.Semaphore(20)

        while queue:
            url, depth = queue.pop(0)
            if url in visited or depth > self.depth: continue
            if not self._in_scope(url): continue
            visited.add(url)
            async with sem:
                r = await self.http.arequest("GET", url)
            if not r: continue
            results.append({"url": url, "method": "GET", "status": r.status_code,
                            "headers": dict(r.headers), "body": r.text[:200000]})

            for f in self._extract_forms(url, r.text):
                results.append(f)

            for link in self._extract_links(url, r.text):
                if link not in visited and self._in_scope(link):
                    queue.append((link, depth+1))
        return results

    def _in_scope(self, url: str) -> bool:
        u = urlparse(url)
        if any(x in url for x in self.exclude): return False
        if not self.scope or self.scope == [""]: return True
        return any(u.path.startswith(s) for s in self.scope)

    def _extract_links(self, base, html) -> List[str]:
        soup = BeautifulSoup(html, "lxml")
        links = set()
        for a in soup.find_all("a", href=True):
            links.add(urljoin(base, a["href"]))
        for s in soup.find_all("script", src=True):
            links.add(urljoin(base, s["src"]))
        # Also extract URLs from JS strings
        for m in re.findall(r"['\"](/[^'\"]{2,})['\"]", html):
            links.add(urljoin(base, m))
        return list(links)

    def _extract_forms(self, base, html) -> List[Dict]:
        soup = BeautifulSoup(html, "lxml")
        forms = []
        for form in soup.find_all("form"):
            action = urljoin(base, form.get("action", ""))
            method = (form.get("method") or "GET").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                n = inp.get("name")
                if n:
                    inputs.append({"name": n, "type": inp.get("type", "text"),
                                   "value": inp.get("value", "")})
            forms.append({"url": action, "method": method, "params": inputs,
                          "form": True, "body": html[:5000]})
        return forms
