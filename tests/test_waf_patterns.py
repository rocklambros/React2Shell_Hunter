"""WAF pattern validation tests."""
import re
import pytest


class TestWAFPatterns:
    """Test WAF rule patterns."""

    def test_regex_patterns_compile(self):
        """Verify regex patterns used in WAF are valid."""
        patterns = [
            r"process\.mainModule\.require",
            r"child_process",
            r"execSync",
            r"spawnSync",
            r"\$1:__proto__",
            r"__proto__:then",
            r"resolved_model",
        ]

        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as e:
                pytest.fail(f"Invalid WAF regex '{pattern}': {e}")

    def test_action_patterns_match_exploits(self):
        """Verify ACTION patterns match known exploit payloads."""
        action_patterns = [
            re.compile(r'\$ACTION_0:0'),
            re.compile(r'\$ACTION_REF'),
        ]

        exploit_payloads = [
            '$ACTION_0:0{"some":"payload"}',
            '$ACTION_REF_0',
        ]

        for payload in exploit_payloads:
            matched = any(p.search(payload) for p in action_patterns)
            assert matched, f"No pattern matched: {payload}"
