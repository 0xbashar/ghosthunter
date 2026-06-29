"""
Anonymizer — Manages operational security (OpSec) for the scanner.
Handles:
  - Tor SOCKS5 routing & NEWNYM identity rotation
  - Custom proxy chain rotation
  - User-Agent & header spoofing
  - Random request jittering to evade rate-limits and WAF behavior analysis
"""
from __future__ import annotations
import asyncio
import random
import socket
import socks
from typing import List, Optional
from stem import Signal
from stem.control import Controller
from core.logger import Logger
from faker import Faker

log = Logger.get_logger("anonymizer")

# Pool of realistic, modern User-Agents to blend in with normal traffic
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]

class Anonymizer:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.proxy_chain: List[str] = list(cfg.get("proxy_chain", []))
        self.request_count = 0
        self.faker = Faker()
        self.tor_ctrl: Optional[Controller] = None

    async def bootstrap(self):
        """Initialize Tor connection if enabled."""
        if self.cfg.get("use_tor"):
            try:
                host, port = self.cfg["tor_control"].split(":")
                self.tor_ctrl = Controller.from_port(host=host, port=int(port))
                self.tor_ctrl.authenticate()
                log.success("Tor circuit established and authenticated")
            except Exception as e:
                log.warn(f"Tor unavailable ({e}). Falling back to direct or proxy chain.")
        else:
            log.info("Tor disabled. Using direct connection or proxy chain.")
            
        log.info(f"Proxy chain length: {len(self.proxy_chain)}")

    def rotate_identity(self):
        """Send NEWNYM signal to Tor to get a new IP address."""
        if self.tor_ctrl:
            try:
                self.tor_ctrl.signal(Signal.NEWNYM)
                log.info("🟣 Tor identity rotated (NEWNYM)")
            except Exception as e:
                log.warn(f"Tor rotation failed: {e}")
        elif self.proxy_chain:
            log.info("🟣 Rotating to next proxy in chain (simulated by random selection)")

    def get_proxy(self) -> Optional[dict]:
        """Return the proxy dictionary for the requests library."""
        if self.cfg.get("use_tor"):
            host, port = self.cfg["tor_socks"].split(":")
            return {
                "http": f"socks5://{host}:{port}",
                "https": f"socks5://{host}:{port}"
            }
        if self.proxy_chain:
            p = random.choice(self.proxy_chain)
            return {"http": p, "https": p}
        return None

    def get_user_agent(self) -> str:
        """Return a random User-Agent."""
        if not self.cfg.get("user_agent_rotation", True):
            return UA_POOL[0]
        return random.choice(UA_POOL)

    def get_spoofed_headers(self) -> dict:
        """Generate headers to spoof origin and bypass IP-based ACLs."""
        # Generate a random internal IP to test X-Forwarded-For bypasses
        ip = f"127.0.0.{random.randint(1, 10)}"
        return {
            "X-Forwarded-For": ip,
            "X-Originating-IP": ip,
            "X-Remote-IP": ip,
            "X-Client-IP": ip,
            "X-Forwarded-Host": "localhost"
        }

    async def throttle(self):
        """Random delay between requests to avoid WAF rate-limiting."""
        lo, hi = self.cfg.get("random_delay", [0.3, 1.5])
        # Add jitter
        delay = random.uniform(lo, hi) * (1 + 0.3 * random.random())
        await asyncio.sleep(delay)

    def tick(self):
        """Increment request counter and rotate identity if threshold reached."""
        self.request_count += 1
        rotate_every = self.cfg.get("rotate_identity_every", 30)
        if rotate_every > 0 and self.request_count % rotate_every == 0:
            self.rotate_identity()
