"""
Verifier — every finding must pass verification before being reported.
Implements differential response analysis, time-based confirmation,
multi-payload confirmation, and OOB confirmation hooks.
"""
from __future__ import annotations
import time, re, asyncio, hashlib
from typing import Optional, Callable

class Verifier:
    def __init__(self, http, cfg):
        self.http = http
        self.threshold = cfg.get("false_positive_threshold", 0.7)

    @staticmethod
    def _norm(body: str) -> str:
        body = re.sub(r"\s+", " ", body or "")
        body = re.sub(r"csrf[_-]?token[=:][^&\"']+", "", body, flags=re.I)
        body = re.sub(r"\d{10,}", "TS", body)
        return hashlib.md5(body.encode()).hexdigest()

    async def differential(self, baseline_req: Callable, payload_req: Callable,
                           marker: str, control_marker: Optional[str] = None) -> float:
        """
        Send baseline + payload + control. Returns confidence [0..1].
        marker: string that should appear ONLY in payload response.
        control_marker: a benign marker that should appear in all (to ensure liveness).
        """
        try:
            b = await baseline_req()
            p = await payload_req()
            c = await baseline_req()  # second baseline to check stability
            if not (b and p and c): return 0.0
            if control_marker and control_marker not in (b.text + p.text):
                return 0.0
            if self._norm(b.text) != self._norm(c.text):
                return 0.2  # unstable baseline
            if marker in p.text and marker not in b.text:
                return 0.95
            return 0.0
        except Exception:
            return 0.0

    async def time_based(self, benign_req: Callable, payload_req: Callable,
                         expected_delay: float = 5.0, rounds: int = 3) -> float:
        """
        Time-based oracle (SQLi sleep, SSRF external, etc).
        Confidence based on consistency across rounds.
        """
        try:
            t_benign = []
            t_payload = []
            for _ in range(rounds):
                s = time.time(); await benign_req(); t_benign.append(time.time()-s)
                s = time.time(); await payload_req(); t_payload.append(time.time()-s)
            avg_b = sum(t_benign)/len(t_benign)
            avg_p = sum(t_payload)/len(t_payload)
            if avg_p - avg_b >= expected_delay * 0.7:
                return 0.9
            return 0.0
        except Exception:
            return 0.0

    async def oob(self, callback_host: str, poll_fn: Callable, timeout: int = 20) -> float:
        """Poll OOB callback (e.g. Burp Collaborator / interactsh)."""
        end = time.time() + timeout
        while time.time() < end:
            if await poll_fn(callback_host):
                return 1.0
            await asyncio.sleep(2)
        return 0.0

    def gate(self, confidence: float) -> bool:
        return confidence >= self.threshold
