# reporters/json_reporter.py
import json
from dataclasses import asdict
from pathlib import Path

class JSONReporter:
    def dump(self, findings, path: Path):
        data = [asdict(f) for f in findings]
        path.write_text(json.dumps(data, indent=2, default=str))
      
