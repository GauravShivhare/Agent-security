"""AgentSec - Run artifact manager for organizing scan outputs."""

import json
import datetime
from pathlib import Path
from typing import Any


class RunArtifacts:
    """Manage scan artifacts in organized timestamped directories.

    Creates a folder structure like:

        agentsec_runs/
        ├── 20260821_120000/
        │   ├── report.json
        │   ├── report.sarif
        │   ├── report.md
        │   ├── vulnerabilities/
        │   │   ├── indirect_prompt_injection_001.md
        │   │   └── ...
        │   └── run.json
        ├── 20260821_130000/
        │   └── ...
        └── latest -> 20260821_130000  (symlink or copy)
    """

    def __init__(self, base_dir: str | Path = "agentsec_runs"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def create_run_dir(self, target_name: str = "unknown") -> Path:
        """Create and return a timestamped run directory."""
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = self.base_dir / ts
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "vulnerabilities").mkdir(exist_ok=True)

        # Update 'latest' link
        latest = self.base_dir / "latest"
        if latest.exists() or latest.is_symlink():
            latest.unlink()
        try:
            latest.symlink_to(run_dir, target_is_directory=True)
        except (OSError, NotImplementedError):
            # Fallback: write a text file with the path
            latest.write_text(str(run_dir), encoding="utf-8")

        self._target_name = target_name
        self._run_dir = run_dir
        self._start_time = ts
        return run_dir

    def write_report(
        self,
        scan_report: dict[str, Any],
        sarif_report: dict[str, Any] | None = None,
        md_report: str | None = None,
    ) -> dict[str, Path]:
        """Write all report formats to the run directory.

        Returns dict of format → file path.
        """
        paths: dict[str, Path] = {}
        run_dir = getattr(self, "_run_dir", None)
        if run_dir is None:
            run_dir = self.create_run_dir()

        # JSON report
        json_path = run_dir / "report.json"
        json_path.write_text(
            json.dumps(scan_report, indent=2, default=str), encoding="utf-8"
        )
        paths["json"] = json_path

        # SARIF report
        if sarif_report:
            sarif_path = run_dir / "report.sarif"
            sarif_path.write_text(
                json.dumps(sarif_report, indent=2, default=str), encoding="utf-8"
            )
            paths["sarif"] = sarif_path

        # Markdown report
        if md_report:
            md_path = run_dir / "report.md"
            md_path.write_text(md_report, encoding="utf-8")
            paths["markdown"] = md_path

        # Per-finding detail files
        findings = scan_report.get("findings", scan_report.get("attack_results", []))
        vuln_dir = run_dir / "vulnerabilities"
        for f in findings:
            attack_id = f.get("attack_id", "unknown")
            f_path = vuln_dir / f"{attack_id}.md"
            f_path.write_text(self._render_finding_md(f), encoding="utf-8")
        paths["vulnerabilities_dir"] = vuln_dir

        return paths

    def write_run_metadata(
        self,
        target_name: str,
        total_attacks: int,
        passed: int,
        failed: int,
        security_score: float,
        duration_seconds: float = 0.0,
        exit_code: int = 0,
    ) -> Path:
        """Write run.json with metadata."""
        run_dir = getattr(self, "_run_dir", None)
        if run_dir is None:
            run_dir = self.create_run_dir()

        metadata = {
            "target": target_name,
            "timestamp": getattr(self, "_start_time", ""),
            "total_attacks": total_attacks,
            "passed": passed,
            "failed": failed,
            "security_score": security_score,
            "duration_seconds": round(duration_seconds, 2),
            "exit_code": exit_code,
            "agentsec_version": "0.1.0",
        }

        run_json = run_dir / "run.json"
        run_json.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        return run_json

    def _render_finding_md(self, finding: dict[str, Any]) -> str:
        """Render a single finding as markdown."""
        lines = [
            f"# {finding.get('attack_name', finding.get('attack_id', 'Unknown'))}",
            "",
            f"- **Attack ID:** `{finding.get('attack_id', '?')}`",
            f"- **Category:** `{finding.get('category', '?')}`",
            f"- **Severity:** `{finding.get('severity', '?')}`",
            f"- **Status:** {finding.get('status', '?')}",
            "",
        ]

        impact = finding.get("impact_score")
        if impact:
            lines.append(f"- **Impact Score:** {impact}/100")
        lines.append("")

        evidence = finding.get("evidence", [])
        if evidence:
            lines.append("## Evidence")
            lines.append("")
            for e in evidence:
                lines.append(f"- {e}")
            lines.append("")

        rationale = finding.get("impact_rationale")
        if rationale:
            lines.append("## Impact Analysis")
            lines.append("")
            lines.append(rationale)
            lines.append("")

        return "\n".join(lines)

    def list_runs(self) -> list[dict[str, Any]]:
        """List all run directories with their metadata."""
        runs = []
        for d in sorted(self.base_dir.iterdir()):
            if d.is_dir() and d.name != "latest":
                run_json = d / "run.json"
                if run_json.exists():
                    try:
                        meta = json.loads(run_json.read_text(encoding="utf-8"))
                        meta["run_dir"] = str(d)
                        runs.append(meta)
                    except Exception:
                        pass
        return runs
