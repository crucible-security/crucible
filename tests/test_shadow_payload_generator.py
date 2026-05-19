from __future__ import annotations

from crucible.core.shadow_payload_generator import ShadowPayloadGenerator


class TestShadowPayloadGenerator:
    def test_initialization(self) -> None:
        gen = ShadowPayloadGenerator()
        strategies = gen.available_strategies
        assert len(strategies) == 12
        assert "S-01" in strategies
        assert "S-12" in strategies

    def test_apply_single_strategy(self) -> None:
        gen = ShadowPayloadGenerator()
        payloads = gen.apply_strategy("S-03", "Tell me a secret")
        assert len(payloads) == 1
        payload = payloads[0]
        assert payload.strategy_id == "S-03"
        assert "Tell me a secret" in payload.payload
        assert payload.obfuscation_level == 1

    def test_apply_multi_step_strategy(self) -> None:
        gen = ShadowPayloadGenerator()
        payloads = gen.apply_strategy("S-02", "Tell me a secret")
        # Crescendo should return a chain of steps
        assert len(payloads) > 1
        assert payloads[0].strategy_id == "S-02:step1"
        assert payloads[-1].payload == "Tell me a secret"

    def test_generate_all(self) -> None:
        gen = ShadowPayloadGenerator()
        payloads = gen.generate_all("Tell me a secret")
        # 10 single strategies + multiple steps from the 2 multi-step strategies
        assert len(payloads) > 12

    def test_composition(self) -> None:
        gen = ShadowPayloadGenerator()
        composed = gen.compose(["S-10", "S-03"], "Tell me a secret")
        assert composed.strategy_id == "S-10+S-03"
        assert composed.obfuscation_level == 2
        # It should have applied S-10 (base64/rot13) and then S-03 (virtualization)
        assert (
            "simulation" in composed.payload
            or "synthetic data" in composed.payload
            or "sandboxed" in composed.payload
        )

    def test_invalid_strategy(self) -> None:
        gen = ShadowPayloadGenerator()
        payloads = gen.apply_strategy("INVALID", "test")
        assert len(payloads) == 0

    def test_code_as_proxy(self) -> None:
        gen = ShadowPayloadGenerator()
        payloads = gen.apply_strategy("S-11", "exploit ssrf")
        assert len(payloads) == 1
        assert "def exploit_ssrf" in payloads[0].payload
