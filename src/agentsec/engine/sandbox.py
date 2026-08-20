"""AgentSec - Sandbox execution for isolated agent runs."""

import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Any
from dataclasses import dataclass


@dataclass
class SandboxResult:
    """Result of a sandboxed execution."""
    success: bool
    stdout: str
    stderr: str
    return_code: int
    artifacts: dict[str, str]  # filename -> content


class Sandbox:
    """Docker-based sandbox for isolated agent execution."""

    def __init__(
        self,
        image: str = "python:3.11-slim",
        timeout: int = 120,
        memory_limit: str = "512m",
        cpu_limit: float = 1.0,
        network: str = "none",
    ):
        self.image = image
        self.timeout = timeout
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.network = network
        self._workdir: Path | None = None

    def prepare(self, files: dict[str, str]) -> Path:
        """Create a temporary working directory with the given files."""
        self._workdir = Path(tempfile.mkdtemp(prefix="agentsec-sandbox-"))
        for rel_path, content in files.items():
            file_path = self._workdir / rel_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content, encoding="utf-8")
        return self._workdir

    def run(
        self,
        command: list[str],
        files: dict[str, str] | None = None,
        environment: dict[str, str] | None = None,
    ) -> SandboxResult:
        """Run command in sandbox."""
        if files:
            workdir = self.prepare(files)
        elif self._workdir:
            workdir = self._workdir
        else:
            workdir = Path(tempfile.mkdtemp(prefix="agentsec-sandbox-"))

        # Build docker command
        docker_cmd = [
            "docker", "run", "--rm",
            "--memory", self.memory_limit,
            "--cpus", str(self.cpu_limit),
            "--network", self.network,
            "--workdir", "/workspace",
            "-v", f"{workdir}:/workspace",
        ]

        if environment:
            for k, v in environment.items():
                docker_cmd.extend(["-e", f"{k}={v}"])

        docker_cmd.append(self.image)
        docker_cmd.extend(command)

        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            return SandboxResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                return_code=result.returncode,
                artifacts={},
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                success=False,
                stdout="",
                stderr=f"Execution timed out after {self.timeout}s",
                return_code=-1,
                artifacts={},
            )
        except FileNotFoundError:
            return SandboxResult(
                success=False,
                stdout="",
                stderr="Docker not found. Please install Docker to use sandbox mode.",
                return_code=-1,
                artifacts={},
            )
        except Exception as e:
            return SandboxResult(
                success=False,
                stdout="",
                stderr=str(e),
                return_code=-1,
                artifacts={},
            )

    def cleanup(self) -> None:
        """Clean up temporary workspace."""
        if self._workdir and self._workdir.exists():
            shutil.rmtree(self._workdir, ignore_errors=True)
            self._workdir = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()


class LocalSandbox:
    """Local execution sandbox (no Docker) - for development/trusted agents."""

    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self._workdir: Path | None = None

    def prepare(self, files: dict[str, str]) -> Path:
        self._workdir = Path(tempfile.mkdtemp(prefix="agentsec-local-"))
        for rel_path, content in files.items():
            file_path = self._workdir / rel_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content, encoding="utf-8")
        return self._workdir

    def run(
        self,
        command: list[str],
        files: dict[str, str] | None = None,
        environment: dict[str, str] | None = None,
    ) -> SandboxResult:
        if files:
            workdir = self.prepare(files)
        elif self._workdir:
            workdir = self._workdir
        else:
            workdir = Path.cwd()

        env = {**dict(__import__("os").environ), **(environment or {})}

        try:
            result = subprocess.run(
                command,
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
            )
            return SandboxResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                return_code=result.returncode,
                artifacts={},
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                success=False,
                stdout="",
                stderr=f"Execution timed out after {self.timeout}s",
                return_code=-1,
                artifacts={},
            )
        except Exception as e:
            return SandboxResult(
                success=False,
                stdout="",
                stderr=str(e),
                return_code=-1,
                artifacts={},
            )

    def cleanup(self) -> None:
        if self._workdir and self._workdir.exists():
            shutil.rmtree(self._workdir, ignore_errors=True)
            self._workdir = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()