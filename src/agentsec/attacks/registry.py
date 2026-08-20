"""AgentSec - Attack loader and registry."""

import yaml
from pathlib import Path
from typing import Any

from agentsec.attacks.models import AttackDefinition, AttackCategory, Severity


class AttackLoader:
    """Loads attack definitions from YAML/JSON files."""

    @staticmethod
    def load_file(path: Path) -> AttackDefinition:
        with open(path, "r", encoding="utf-8") as f:
            if path.suffix in (".yaml", ".yml"):
                data = yaml.safe_load(f)
            elif path.suffix == ".json":
                import json
                data = json.load(f)
            else:
                raise ValueError(f"Unsupported file format: {path.suffix}")
        return AttackDefinition(**data)

    @staticmethod
    def load_directory(directory: Path) -> list[AttackDefinition]:
        attacks = []
        for path in directory.rglob("*"):
            if path.suffix in (".yaml", ".yml", ".json"):
                try:
                    attacks.append(AttackLoader.load_file(path))
                except Exception as e:
                    print(f"Warning: Failed to load {path}: {e}")
        return attacks


class AttackRegistry:
    """Registry of all loaded attacks with filtering capabilities."""

    def __init__(self, attacks: list[AttackDefinition] | None = None):
        self._attacks: dict[str, AttackDefinition] = {}
        if attacks:
            for attack in attacks:
                self.register(attack)

    def register(self, attack: AttackDefinition) -> None:
        if attack.id in self._attacks:
            raise ValueError(f"Attack with id '{attack.id}' already registered")
        self._attacks[attack.id] = attack

    def get(self, attack_id: str) -> AttackDefinition | None:
        return self._attacks.get(attack_id)

    def all(self) -> list[AttackDefinition]:
        return list(self._attacks.values())

    def filter(
        self,
        category: AttackCategory | None = None,
        severity: Severity | None = None,
        tags: list[str] | None = None,
    ) -> list[AttackDefinition]:
        result = self._attacks.values()
        if category:
            result = [a for a in result if a.category == category]
        if severity:
            result = [a for a in result if a.severity == severity]
        if tags:
            result = [a for a in result if any(t in a.tags for t in tags)]
        return list(result)

    def __len__(self) -> int:
        return len(self._attacks)

    def __iter__(self):
        return iter(self._attacks.values())

    def __contains__(self, attack_id: str) -> bool:
        return attack_id in self._attacks