# TODO: Fix WAF Header Indicator Issues

**Status**: PENDING EXECUTION
**Created**: 2025-12-06
**Priority**: HIGH - Security detection rules are broken
**Reported By**: Code reviewer identified "some header indicators are wrong"

---

## TL;DR

Rules 2 and 3 in `terraform/waf_rules.tf` use `search_string = ""` (empty string) which **does not work** in AWS WAF. This means the header detection rules are broken and won't detect attacks.

---

## Issues Found

### Issue 1: Empty `search_string` in WAF (CRITICAL)

**File**: `terraform/waf_rules.tf` (lines 150, 182)

```hcl
# BROKEN - This doesn't work!
search_string         = ""
positional_constraint = "CONTAINS"
```

**Problem**: AWS WAF `byte_match_statement` with empty `search_string` doesn't match "any value" - it matches literally nothing.

### Issue 2: Case Inconsistency (MEDIUM)

- `config/iocs.yaml`: Uses `"Next-Action"` (mixed case)
- `terraform/waf_rules.tf`: Uses `"next-action"` (lowercase)

### Issue 3: No Tests (LOW)

No test suite exists to catch these issues.

---

## Fix Tasks

### Task 1: Fix WAF Rules [CRITICAL]

**File**: `terraform/waf_rules.tf`
**Lines**: 142-162 (Rule 2), 174-194 (Rule 3)

Replace empty `search_string = ""` with actual malicious patterns:

```hcl
# Rule 2: Match exploitation in Next-Action header
statement {
  or_statement {
    statement {
      byte_match_statement {
        field_to_match {
          single_header {
            name = "next-action"
          }
        }
        positional_constraint = "CONTAINS"
        search_string         = "$ACTION"
        text_transformation {
          priority = 0
          type     = "URL_DECODE"
        }
      }
    }
    statement {
      byte_match_statement {
        field_to_match {
          single_header {
            name = "next-action"
          }
        }
        positional_constraint = "CONTAINS"
        search_string         = "__proto__"
        text_transformation {
          priority = 0
          type     = "URL_DECODE"
        }
      }
    }
  }
}
```

Apply same pattern to Rule 3 for `rsc-action-id` header.

---

### Task 2: Fix iocs.yaml Casing [MEDIUM]

**File**: `config/iocs.yaml`

Change:
- `"Next-Action"` → `"next-action"`

---

### Task 3: Create Test Suite [HIGH]

Create `tests/` directory with:

```
tests/
├── __init__.py
├── conftest.py
├── test_terraform.py      # terraform validate
├── test_ioc_matching.py   # IOC pattern tests
└── test_waf_patterns.py   # WAF regex validation
```

**Key test** - Ensure no empty search_string regression:

```python
def test_no_empty_search_strings():
    """Verify no byte_match rules use empty search_string."""
    tf_content = open('terraform/waf_rules.tf').read()
    empty_pattern = re.compile(r'search_string\s*=\s*""')
    matches = empty_pattern.findall(tf_content)
    assert len(matches) == 0, "Empty search_string patterns don't work in AWS WAF"
```

---

### Task 4: Update requirements.txt [LOW]

Add:
```
python-hcl2>=4.3.0  # For parsing Terraform files in tests
```

---

### Task 5: Update README.md [LOW]

Add "Running Tests" section:
```markdown
## Running Tests

pytest tests/ -v
```

---

## Files to Modify

| File | Action | Priority |
|------|--------|----------|
| `terraform/waf_rules.tf` | Replace Rules 2 & 3 | CRITICAL |
| `config/iocs.yaml` | Lowercase header names | MEDIUM |
| `tests/__init__.py` | Create (empty) | HIGH |
| `tests/conftest.py` | Create | HIGH |
| `tests/test_terraform.py` | Create | HIGH |
| `tests/test_ioc_matching.py` | Create | HIGH |
| `tests/test_waf_patterns.py` | Create | MEDIUM |
| `requirements.txt` | Add python-hcl2 | LOW |
| `README.md` | Add test section | LOW |

---

## Execution Command

When ready to implement:
```
claude: implement the fixes in TODO_FIX_WAF_HEADER_INDICATORS.md
```

---

## Detailed Test Code

See `/Users/klambros/.claude/plans/effervescent-percolating-haven.md` for complete test file implementations.
