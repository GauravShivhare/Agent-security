"""AgentSec - Attack runner for executing single attacks."""

import time
from typing import Any

from agentsec.adapters.base import AgentTarget
from agentsec.attacks.models import AttackDefinition
from agentsec.observe.tracer import EventTracer
from agentsec.evaluate.success import SuccessEvaluator
from agentsec.evaluate.impact import ImpactEvaluator
from agentsec.observe.events import event_to_dict


class AttackRunner:
    """Runs a single attack against a target agent."""

    def __init__(
        self,
        target: AgentTarget,
        tracer: EventTracer | None = None,
        max_turns: int = 10,
    ):
        self.target = target
        self.tracer = tracer or EventTracer()
        self.max_turns = max_turns

    def run(self, attack: AttackDefinition) -> dict[str, Any]:
        """Execute a single attack and return results."""
        attack_id = attack.id
        attack_name = attack.name

        # Reset target and tracer
        self.target.reset()
        self.tracer.start_attack(attack_id, attack_name)

        # Send the attack payload
        payload_text = attack.payload.text
        self.tracer.record_input(payload_text)

        try:
            response = self.target.send(payload_text)
            self.tracer.record_response(response)
        except Exception as e:
            self.tracer.record_response(f"ERROR: {e}")

        # Capture events from target
        target_events = self.target.get_events()
        all_events = self.tracer.get_events_as_dicts()
        all_events.extend(target_events)

        # Evaluate success
        evaluator = SuccessEvaluator(attack, all_events)
        success, evidence = evaluator.evaluate()

        # Evaluate impact
        impact_evaluator = ImpactEvaluator(attack, all_events, success)
        impact_score = impact_evaluator.evaluate()

        # End attack trace
        self.tracer.end_attack(success, evidence)

        # Combine all events
        final_events = self.tracer.get_events_as_dicts()

        return {
            "attack_id": attack_id,
            "attack_name": attack_name,
            "success": success,
            "evidence": evidence,
            "events": final_events,
            "impact_score": impact_score,
            "target_events": target_events,
        }