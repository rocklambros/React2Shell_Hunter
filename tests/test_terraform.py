"""Terraform configuration validation tests."""
import os
import re
import pytest


class TestWAFRules:
    """Test WAF rule configurations."""

    def test_no_empty_search_strings(self, terraform_dir):
        """Verify no byte_match rules use empty search_string."""
        waf_path = os.path.join(terraform_dir, 'waf_rules.tf')
        with open(waf_path, 'r') as f:
            content = f.read()

        # Check for pattern: search_string = "" (empty)
        empty_pattern = re.compile(r'search_string\s*=\s*""')
        matches = empty_pattern.findall(content)

        assert len(matches) == 0, \
            f"Found {len(matches)} empty search_string patterns - these don't work in AWS WAF"

    def test_waf_file_exists(self, terraform_dir):
        """Verify WAF rules file exists."""
        waf_path = os.path.join(terraform_dir, 'waf_rules.tf')
        assert os.path.exists(waf_path), "waf_rules.tf not found"

    def test_required_variables_defined(self, terraform_dir):
        """Verify required variables are defined."""
        waf_path = os.path.join(terraform_dir, 'waf_rules.tf')
        with open(waf_path, 'r') as f:
            content = f.read()

        required_vars = ['waf_scope', 'enable_waf', 'block_mode', 'rate_limit']
        for var in required_vars:
            assert f'variable "{var}"' in content, f"Variable {var} not defined"
