"""
CI/CD Integration — Provides entry points for:
  - Jenkins (via Python script)
  - GitLab CI (via CLI)
  - GitHub Actions (via CLI)
"""
import sys, json, argparse
from pathlib import Path
from core.engine import GhostHunterEngine
import yaml

class CICDPlugin:
    @staticmethod
    def jenkins_entrypoint():
        """Called by Jenkins plugin."""
        target = sys.argv[1]
        config = yaml.safe_load(Path("config.yaml").read_text())
        config["target"]["domain"] = target
        config["reporting"]["formats"] = ["json"]
        config["reporting"]["output_dir"] = "reports"
        
        engine = GhostHunterEngine(config)
        import asyncio
        asyncio.run(engine.run(target))
        
        # Output for Jenkins to parse
        report = Path(f"reports/{target}/report.json")
        if report.exists():
            findings = json.loads(report.read_text())
            print(f"GHOSTHUNTER_RESULTS: {json.dumps(findings)}")
            # Exit with error if critical findings
            if any(f["severity"] == "critical" for f in findings):
                sys.exit(1)

    @staticmethod
    def github_action_entrypoint():
        """Called by GitHub Action."""
        target = os.environ.get("INPUT_TARGET")
        fail_on = os.environ.get("INPUT_FAIL_ON", "critical")
        
        config = yaml.safe_load(Path("config.yaml").read_text())
        config["target"]["domain"] = target
        
        engine = GhostHunterEngine(config)
        import asyncio
        asyncio.run(engine.run(target))
        
        report = Path(f"reports/{target}/report.json")
        if report.exists():
            findings = json.loads(report.read_text())
            # Set output for GitHub Action
            with open(os.environ["GITHUB_OUTPUT"], "a") as f:
                f.write(f"findings={json.dumps(findings)}\n")
            
            if fail_on == "critical" and any(f["severity"] == "critical" for f in findings):
                sys.exit(1)
            elif fail_on == "high" and any(f["severity"] in ("critical", "high") for f in findings):
                sys.exit(1)

    @staticmethod
    def gitlab_ci_entrypoint():
        """Called by GitLab CI."""
        target = os.environ.get("TARGET_DOMAIN")
        config = yaml.safe_load(Path("config.yaml").read_text())
        config["target"]["domain"] = target
        
        engine = GhostHunterEngine(config)
        import asyncio
        asyncio.run(engine.run(target))
        
        # GitLab expects artifacts
        print(f"Artifacts saved in reports/{target}/")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ci", choices=["jenkins", "github", "gitlab"], required=True)
    args = parser.parse_args()
    
    if args.ci == "jenkins":
        CICDPlugin.jenkins_entrypoint()
    elif args.ci == "github":
        CICDPlugin.github_action_entrypoint()
    elif args.ci == "gitlab":
        CICDPlugin.gitlab_ci_entrypoint()
