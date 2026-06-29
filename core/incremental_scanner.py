"""
Incremental Scanner — Re-scans only changed parts of an application.
Uses content hashing to detect changes.
"""
import hashlib, json
from pathlib import Path
from typing import Dict, List

class IncrementalScanner:
    def __init__(self, state_dir: str = ".gh_state"):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(exist_ok=True)
    
    def _state_path(self, target: str) -> Path:
        return self.state_dir / f"{target.replace('/', '_')}.json"
    
    def load_state(self, target: str) -> Dict:
        path = self._state_path(target)
        if path.exists():
            return json.loads(path.read_text())
        return {"endpoints": {}, "last_scan": 0}
    
    def save_state(self, target: str, state: Dict):
        self._state_path(target).write_text(json.dumps(state, indent=2))
    
    def get_changed_endpoints(self, target: str, current_endpoints: List[dict]) -> List[dict]:
        """Return only endpoints that have changed since last scan."""
        state = self.load_state(target)
        changed = []
        
        for ep in current_endpoints:
            url = ep["url"]
            content_hash = hashlib.md5(ep.get("body", "").encode()).hexdigest()
            
            if url not in state["endpoints"]:
                changed.append(ep)
            elif state["endpoints"][url]["hash"] != content_hash:
                changed.append(ep)
        
        return changed
    
    def update_state(self, target: str, endpoints: List[dict]):
        state = self.load_state(target)
        for ep in endpoints:
            url = ep["url"]
            content_hash = hashlib.md5(ep.get("body", "").encode()).hexdigest()
            state["endpoints"][url] = {"hash": content_hash}
        state["last_scan"] = __import__("time").time()
        self.save_state(target, state)
