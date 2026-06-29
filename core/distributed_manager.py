"""
Distributed Manager — Celery-based task queue for horizontal scaling.
Distributes scan tasks across multiple worker nodes.
"""
from celery import Celery
import asyncio, yaml
from core.engine import GhostHunterEngine

app = Celery("ghosthunter",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/1"
)

@app.task(bind=True)
def scan_target(self, target: str, config_path: str = "config.yaml"):
    """Celery task to scan a target."""
    config = yaml.safe_load(open(config_path))
    config["target"]["domain"] = target
    
    engine = GhostHunterEngine(config)
    
    # Run async engine in sync Celery worker
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        loop.run_until_complete(engine.run(target))
        findings = [{
            "title": f.title, "severity": f.severity,
            "confidence": f.confidence, "endpoint": f.endpoint
        } for f in engine.findings]
        return {"target": target, "findings": findings, "count": len(findings)}
    except Exception as e:
        return {"target": target, "error": str(e)}
    finally:
        loop.close()

@app.task
def scan_batch(targets: list):
    """Schedule batch of targets."""
    for target in targets:
        scan_target.delay(target)
    return {"scheduled": len(targets)}

# Worker startup: celery -A core.distributed_manager worker --loglevel=info -c 4
