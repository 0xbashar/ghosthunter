"""
HTTPClient — thin async wrapper around requests (with PySocks support for Tor).
Handles header rotation, retries, redirect control, signature suppression.
"""
from __future__ import annotations
import time, random, requests, urllib3
from typing import Dict, Optional, Any
from core.logger import Logger
from core.encoder import Encoder

urllib3.disable_warnings()
log = Logger.get_logger("http")

class HTTPClient:
    def __init__(self, cfg: dict, anonymizer):
        self.cfg = cfg
        self.anon = anonymizer
        self.session = requests.Session()
        self.session.verify = False
        self.session.max_redirects = cfg.get("max_redirects", 5)
        self.session.allow_redirects = cfg.get("follow_redirects", False)
        self._default_headers = cfg.get("default_headers", {})

    def _headers(self, extra: Optional[dict] = None) -> dict:
        h = dict(self._default_headers)
        h["User-Agent"] = self.anon.get_user_agent()
        h["X-Forwarded-For"] = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        h["X-Originating-IP"] = "127.0.0.1"
        h["X-Remote-IP"] = "127.0.0.1"
        h["X-Client-IP"] = "10.0.0.1"
        h["X-Forwarded-Host"] = "localhost"
        if extra:
            h.update(extra)
        return h

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        encoded_url = Encoder.url(url) if "://" not in url.split("?")[0] else url
        # ^ keep scheme; encode path/params

        kwargs.setdefault("headers", {}).update(self._headers(kwargs.pop("extra_headers", None)))
        kwargs.setdefault("timeout", self.cfg.get("timeout", 15))
        kwargs.setdefault("proxies", self.anon.get_proxy())

        for attempt in range(self.cfg.get("retries", 3)):
            try:
                self.anon.tick()
                r = self.session.request(method, encoded_url, **kwargs)
                return r
            except requests.exceptions.RequestException as e:
                log.debug(f"retry {attempt+1} {url} -> {e}")
                time.sleep(2 ** attempt + random.random())
        return None

    async def arequest(self, method: str, url: str, **kw):
        # Run blocking call in thread executor (kept simple)
        loop = __import__("asyncio").get_event_loop()
        return await loop.run_in_executor(None, lambda: self.request(method, url, **kw))
