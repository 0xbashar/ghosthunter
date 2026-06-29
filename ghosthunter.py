#!/usr/bin/env python3
"""
GhostHunter 2.0 — The Apex Predator Framework
"""
import argparse, asyncio, yaml, sys, os
from pathlib import Path
from core.engine import GhostHunterEngine
from core.logger import Logger
from core.ai_engine import AIEngine
from core.incremental_scanner import IncrementalScanner

def main():
    ap = argparse.ArgumentParser(description="GhostHunter 2.0")
    ap.add_argument("-d","--domain", required=True)
    ap.add_argument("-c","--config", default="config.yaml")
    ap.add_argument("--passive", action="store_true")
    ap.add_argument("--no-tor", action="store_true")
    ap.add_argument("--no-ai", action="store_true")
    ap.add_argument("--distributed", action="store_true")
    ap.add_argument("--incremental", action="store_true")
    ap.add_argument("--dashboard", action="store_true")
    args = ap.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text())
    cfg["target"]["domain"] = args.domain
    if args.no_tor: cfg["anonymity"]["use_tor"] = False
    if args.no_ai: cfg["ai"]["enabled"] = False
    if args.distributed: cfg["scanning"]["distributed"] = True
    if args.incremental: cfg["scanning"]["incremental"] = True

    log = Logger.get_logger("main")
    log.header("👻 GHOSTHUNTER 2.0 :: AI-Powered Bug Hunting")
    log.info(f"Target: {args.domain} | AI: {cfg['ai']['enabled']} | Distributed: {cfg['scanning']['distributed']}")

    if args.dashboard:
        import uvicorn
        from enterprise.dashboard import app
        uvicorn.run(app, host="0.0.0.0", port=8000)
        return

    if cfg["scanning"]["distributed"]:
        from core.distributed_manager import scan_target
        result = scan_target.delay(args.domain)
        log.info(f"Distributed scan started. Task ID: {result.id}")
        return

    engine = GhostHunterEngine(cfg)
    try:
        asyncio.run(engine.run(args.domain))
    except KeyboardInterrupt:
        log.warn("Interrupted")
        sys.exit(130)
      # Add this to ghosthunter.py
@app.command()
def dashboard(
    host: str = "0.0.0.0",
    port: int = 8000,
    reload: bool = True
):
    """Launch the GhostHunter Command Center."""
    import uvicorn
    from enterprise.dashboard import app
    Logger.get_logger("main").header("👻 Launching GhostHunter Command Center")
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    main()
