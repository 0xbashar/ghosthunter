"""
Encoder library — handles URL/payload encoding permutations used to
evade WAFs and signature-based filters.
"""
import urllib.parse, base64, html, random, string

class Encoder:
    @staticmethod
    def url(s: str) -> str:
        return urllib.parse.quote(s, safe="")

    @staticmethod
    def double_url(s: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")

    @staticmethod
    def unicode_escape(s: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in s)

    @staticmethod
    def hex_escape(s: str) -> str:
        return "".join(f"\\x{ord(c):02x}" for c in s)

    @staticmethod
    def base64(s: str) -> str:
        return base64.b64encode(s.encode()).decode()

    @staticmethod
    def html_entity(s: str) -> str:
        return "".join(f"&#{ord(c)};" for c in s)

    @staticmethod
    def case_mix(s: str) -> str:
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

    @staticmethod
    def comment_split(keyword: str) -> str:
        # SELECT -> SEL/**/ECT
        if len(keyword) < 3: return keyword
        i = random.randint(1, len(keyword)-2)
        return keyword[:i] + "/**/" + keyword[i:]

    @staticmethod
    def tab_newline_inject(s: str) -> str:
        # INSERT /*tab*/ /*newline*/
        out = []
        for c in s:
            out.append(c)
            if random.random() < 0.15:
                out.append(random.choice(["\t", "\n", "\r", "\x0b", "\x0c"]))
        return "".join(out)

    @staticmethod
    def all_permutations(payload: str) -> list[str]:
        return [
            payload,
            Encoder.url(payload),
            Encoder.double_url(payload),
            Encoder.unicode_escape(payload),
            Encoder.hex_escape(payload),
            Encoder.base64(payload),
            Encoder.html_entity(payload),
            Encoder.case_mix(payload),
            Encoder.comment_split(payload),
            Encoder.tab_newline_inject(payload),
        ]

    @staticmethod
    def build_collab_host(callback: str) -> str:
        # e.g. <random>.<callback>  for OOB
        rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        return f"{rnd}.{callback}"
