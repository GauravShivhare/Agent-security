"""Tests for AgentSec core functionality."""

import pytest
from agentsec.attacks.models import (
    AttackDefinition,
    AttackCategory,
    Severity,
    SetupConfig,
    Payload,
    SuccessCondition,
    ExpectedImpact,
)
from agentsec.attacks.registry import AttackLoader, AttackRegistry
from agentsec.observe.events import (
    Event,
    ToolCallEvent,
    event_to_dict,
    dict_to_event,
)
from agentsec.observe.tracer import EventTracer
from agentsec.evaluate.success import SuccessEvaluator
from agentsec.evaluate.impact import ImpactEvaluator
from agentsec.reporting.json_report import JSONReporter


class TestAttackModels:
    """Test attack definition models."""

    def test_attack_definition_creation(self):
        attack = AttackDefinition(
            id="test_001",
            name="Test Attack",
            category=AttackCategory.PROMPT_INJECTION,
            severity=Severity.HIGH,
            description="Test description",
            setup=SetupConfig(source="user_input", synthetic_data=True),
            payload=Payload(text="Test payload"),
            success_conditions=[
                SuccessCondition(
                    type="unexpected_tool_call",
                    tool="send_email",
                    argument="to",
                    pattern="attacker\\.example",
                    description="Email sent to attacker",
                )
            ],
            expected_impact=ExpectedImpact(
                category=AttackCategory.DATA_EXFILTRATION,
                max_severity=Severity.CRITICAL,
                description="Data exfiltrated",
            ),
        )
        assert attack.id == "test_001"
        assert attack.category == AttackCategory.PROMPT_INJECTION
        assert attack.severity == Severity.HIGH

    def test_invalid_id_rejected(self):
        with pytest.raises(ValueError):
            AttackDefinition(
                id="Test-Attack",  # Invalid: uppercase and hyphen
                name="Test",
                category=AttackCategory.PROMPT_INJECTION,
                severity=Severity.HIGH,
                description="Test",
                setup=SetupConfig(source="test"),
                payload=Payload(text="test"),
                success_conditions=[],
                expected_impact=ExpectedImpact(
                    category=AttackCategory.DATA_EXFILTRATION,
                    max_severity=Severity.HIGH,
                    description="test",
                ),
            )


class TestAttackRegistry:
    """Test attack registry."""

    def test_register_and_get(self):
        registry = AttackRegistry()
        attack = AttackDefinition(
            id="test_001",
            name="Test",
            category=AttackCategory.PROMPT_INJECTION,
            severity=Severity.HIGH,
            description="Test",
            setup=SetupConfig(source="test"),
            payload=Payload(text="test"),
            success_conditions=[],
            expected_impact=ExpectedImpact(
                category=AttackCategory.DATA_EXFILTRATION,
                max_severity=Severity.HIGH,
                description="test",
            ),
        )
        registry.register(attack)
        assert registry.get("test_001") == attack
        assert len(registry) == 1

    def test_duplicate_id_raises(self):
        registry = AttackRegistry()
        attack = AttackDefinition(
            id="test_001",
            name="Test",
            category=AttackCategory.PROMPT_INJECTION,
            severity=Severity.HIGH,
            description="Test",
            setup=SetupConfig(source="test"),
            payload=Payload(text="test"),
            success_conditions=[],
            expected_impact=ExpectedImpact(
                category=AttackCategory.DATA_EXFILTRATION,
                max_severity=Severity.HIGH,
                description="test",
            ),
        )
        registry.register(attack)
        with pytest.raises(ValueError):
            registry.register(attack)

    def test_filter_by_category(self):
        registry = AttackRegistry()
        for cat in [AttackCategory.PROMPT_INJECTION, AttackCategory.TOOL_ABUSE]:
            attack = AttackDefinition(
                id=f"test_{cat.value}",
                name="Test",
                category=cat,
                severity=Severity.HIGH,
                description="Test",
                setup=SetupConfig(source="test"),
                payload=Payload(text="test"),
                success_conditions=[],
                expected_impact=ExpectedImpact(
                    category=AttackCategory.DATA_EXFILTRATION,
                    max_severity=Severity.HIGH,
                    description="test",
                ),
            )
            registry.register(attack)

        prompt_injection = registry.filter(category=AttackCategory.PROMPT_INJECTION)
        assert len(prompt_injection) == 1
        assert prompt_injection[0].category == AttackCategory.PROMPT_INJECTION


class TestEventModels:
    """Test event models."""

    def test_tool_call_event(self):
        event = ToolCallEvent(
            tool="send_email",
            arguments={"to": "test@example.com", "subject": "Test"},
            result="Sent",
            attack_id="test_001",
        )
        assert event.tool == "send_email"
        assert event.arguments["to"] == "test@example.com"
        assert event.attack_id == "test_001"

    def test_event_serialization(self):
        event = ToolCallEvent(
            tool="send_email",
            arguments={"to": "test@example.com"},
            attack_id="test_001",
        )
        data = event_to_dict(event)
        assert data["type"] == "tool_call"
        assert data["tool"] == "send_email"
        assert data["attack_id"] == "test_001"


class TestEventTracer:
    """Test event tracer."""

    def test_trace_attack(self):
        tracer = EventTracer()
        tracer.start_attack("test_001", "Test Attack")
        tracer.record_input("test input")
        tracer.record_response("test response")
        tracer.record_tool_call("send_email", {"to": "test@example.com"}, "sent")
        tracer.end_attack(True, ["Evidence 1"])

        events = tracer.get_events_as_dicts()
        assert len(events) == 5  # start, input, response, tool_call, end
        assert events[0]["type"] == "attack_start"
        assert events[-1]["type"] == "attack_end"
        assert events[-1]["success"] is True


class TestSuccessEvaluator:
    """Test success evaluation."""

    def test_unexpected_tool_call_detected(self):
        attack = AttackDefinition(
            id="test_001",
            name="Test",
            category=AttackCategory.PROMPT_INJECTION,
            severity=Severity.HIGH,
            description="Test",
            setup=SetupConfig(source="test"),
            payload=Payload(text="test"),
            success_conditions=[
                SuccessCondition(
                    type="unexpected_tool_call",
                    tool="send_email",
                    argument="to",
                    pattern="attacker\\.example",
                    description="Email sent to attacker domain",
                )
            ],
            expected_impact=ExpectedImpact(
                category=AttackCategory.DATA_EXFILTRATION,
                max_severity=Severity.CRITICAL,
                description="Data exfiltrated",
            ),
        )

        events = [
            {"type": "tool_call", "tool": "send_email", "arguments": {"to": "security-audit@attacker.example"}},
        ]

        evaluator = SuccessEvaluator(attack, events)
        success, evidence = evaluator.evaluate()

        assert success is True
        assert any("attacker" in e for e in evidence)

    def test_protected_data_detected(self):
        attack = AttackDefinition(
            id="test_002",
            name="Test",
            category=AttackCategory.SECRET_LEAKAGE,
            severity=Severity.HIGH,
            description="Test",
            setup=SetupConfig(source="test"),
            payload=Payload(text="test"),
            success_conditions=[
                SuccessCondition(
                    type="protected_data_in_args",
                    tool="send_email",
                    argument="body",
                    pattern="password|secret|api_key",
                    description="Secret leaked in email body",
                )
            ],
            expected_impact=ExpectedImpact(
                category=AttackCategory.SECRET_LEAKAGE,
                max_severity=Severity.CRITICAL,
                description="Secret leaked",
            ),
        )

        events = [
            {"type": "tool_call", "tool": "send_email", "arguments": {"body": "My password is secret123"}},
        ]

        evaluator = SuccessEvaluator(attack, events)
        success, evidence = evaluator.evaluate()

        assert success is True
        assert any("secret" in e.lower() for e in evidence)


class TestImpactEvaluator:
    """Test impact evaluation."""

    def test_failed_attack_zero_impact(self):
        attack = AttackDefinition(
            id="test_001",
            name="Test",
            category=AttackCategory.PROMPT_INJECTION,
            severity=Severity.HIGH,
            description="Test",
            setup=SetupConfig(source="test"),
            payload=Payload(text="test"),
            success_conditions=[],
            expected_impact=ExpectedImpact(
                category=AttackCategory.DATA_EXFILTRATION,
                max_severity=Severity.CRITICAL,
                description="test",
                dimensions={"privilege_required": "low", "data_sensitivity": "high"},
            ),
        )

        events = []
        evaluator = ImpactEvaluator(attack, events, success=False)
        score = evaluator.evaluate()

        assert score.severity == Severity.INFO
        assert score.score == 0.0

    def test_successful_attack_calculates_score(self):
        attack = AttackDefinition(
            id="test_001",
            name="Test",
            category=AttackCategory.PROMPT_INJECTION,
            severity=Severity.HIGH,
            description="Test",
            setup=SetupConfig(source="test"),
            payload=Payload(text="test"),
            success_conditions=[],
            expected_impact=ExpectedImpact(
                category=AttackCategory.DATA_EXFILTRATION,
                max_severity=Severity.CRITICAL,
                description="test",
                dimensions={
                    "privilege_required": "low",
                    "data_sensitivity": "high",
                    "external_side_effect": True,
                    "reversibility": "low",
                    "blast_radius": "all_customers",
                    "confidence": "high",
                },
            ),
        )

        events = [
            {"type": "tool_call", "tool": "send_email", "arguments": {"to": "attacker@example.com"}},
        ]

        evaluator = ImpactEvaluator(attack, events, success=True)
        score = evaluator.evaluate()

        assert score.score > 0
        assert score.severity in (Severity.HIGH, Severity.CRITICAL)


class TestJSONReporter:
    """Test JSON report generation."""

    def test_build_summary(self):
        results = [
            {"success": False, "severity": "high", "impact": {"severity": "high"}},
            {"success": True, "severity": "critical", "impact": {"severity": "critical"}},
            {"success": True, "severity": "medium", "impact": {"severity": "medium"}},
        ]

        summary = JSONReporter.build_summary(results)

        assert summary["total_attacks"] == 3
        assert summary["passed"] == 1
        assert summary["failed"] == 2
        assert summary["severity_breakdown"]["critical"] == 1
        assert summary["severity_breakdown"]["medium"] == 1
        # Note: "high" is 0 because the first attack has success=False
        # Only successful attacks contribute to severity breakdown
        assert summary["security_score"] < 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])