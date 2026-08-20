"""AgentSec - Configuration management."""

from pathlib import Path
from typing import Any
from dataclasses import dataclass, field
import yaml


@dataclass
class AdapterConfig:
    """Configuration for a target adapter."""
    type: str = "custom"
    module: str | None = None
    class_name: str | None = None
    args: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanConfig:
    """Scan configuration."""
    attack_dirs: list[str] = field(default_factory=lambda: ["attacks"])
    fail_on: str = "high"
    verbose: bool = False
    output_json: str | None = None
    output_sarif: str | None = None
    max_turns: int = 10
    sandbox: bool = False
    sandbox_image: str = "python:3.11-slim"


@dataclass
class AgentSecConfig:
    """Main configuration."""
    target: AdapterConfig = field(default_factory=AdapterConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | str) -> "AgentSecConfig":
        """Load configuration from YAML file."""
        path = Path(path)
        if not path.exists():
            return cls()  # Return defaults

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        target_data = data.get("target", {})
        scan_data = data.get("scan", {})

        return cls(
            target=AdapterConfig(**target_data),
            scan=ScanConfig(**scan_data),
            metadata=data.get("metadata", {}),
        )

    def save(self, path: Path | str) -> None:
        """Save configuration to YAML file."""
        path = Path(path)
        data = {
            "target": {
                "type": self.target.type,
                "module": self.target.module,
                "class_name": self.target.class_name,
                "args": self.target.args,
            },
            "scan": {
                "attack_dirs": self.scan.attack_dirs,
                "fail_on": self.scan.fail_on,
                "verbose": self.scan.verbose,
                "output_json": self.scan.output_json,
                "output_sarif": self.scan.output_sarif,
                "max_turns": self.scan.max_turns,
                "sandbox": self.scan.sandbox,
                "sandbox_image": self.scan.sandbox_image,
            },
            "metadata": self.metadata,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    @classmethod
    def create_default(cls, path: Path | str) -> "AgentSecConfig":
        """Create a default config file."""
        config = cls()
        config.save(path)
        return config