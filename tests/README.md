# React2Shell Hunter Test Suite

Comprehensive test suite for validating Terraform configurations, IOC patterns, and WAF rules.

## Test Files Created

1. **`__init__.py`** - Test package initialization
2. **`conftest.py`** - Pytest fixtures for shared test resources
3. **`test_terraform.py`** - Terraform configuration validation (10 tests)
4. **`test_ioc_matching.py`** - IOC pattern matching validation (38 tests)
5. **`test_waf_patterns.py`** - WAF regex and rule logic validation (21 tests)

## Test Coverage

### Terraform Validation Tests (`test_terraform.py`)
- WAF file existence and structure
- Required variables defined (waf_scope, enable_waf, block_mode, rate_limit)
- Malicious IP synchronization with IOC config
- Critical regex patterns present
- CloudWatch logging enabled
- Critical headers monitored (next-action, rsc-action-id)
- Rate limiting configured
- AWS managed rules included
- CloudWatch alarms configured
- **Empty search_string validation** (prevents AWS WAF errors)

### IOC Pattern Tests (`test_ioc_matching.py`)

#### Network IOCs
- IP address format validation
- Known C2 IPs present
- IP confidence levels
- Suspicious port validation
- Malicious domain structure

#### HTTP IOCs
- Header naming conventions (lowercase)
- Header severity levels
- Payload pattern regex compilation
- Critical exploit pattern detection
- ACTION parameter patterns
- User-agent categorization
- JA4 fingerprint format

#### Host IOCs
- Process patterns for Windows/Linux
- File indicator structure
- Environment variable pattern coverage

#### AWS IOCs
- CloudTrail event categorization
- Critical event monitoring
- GuardDuty finding severity
- Cryptocurrency mining detection

#### Metadata
- Complete metadata fields
- CVE ID documentation
- MITRE ATT&CK mapping
- Affected version documentation

### WAF Pattern Tests (`test_waf_patterns.py`)

#### Pattern Validation
- Regex pattern compilation
- ACTION parameter exploit matching
- Prototype pollution detection
- RCE command detection
- Header detection (case-insensitive)
- User-agent pattern matching
- RSC serialization markers
- Proper regex escaping
- Catastrophic backtracking prevention

#### Rule Logic
- IP blocking priority and structure
- Header blocking logic
- Body inspection configuration
- Text transformation application
- Rate limiting scope

#### Attack Coverage
- Initial access vectors
- Execution techniques
- Credential access prevention
- Persistence mechanism detection

## Running Tests

### Run All Tests
```bash
pytest tests/ -v
```

### Run Specific Test File
```bash
pytest tests/test_terraform.py -v
pytest tests/test_ioc_matching.py -v
pytest tests/test_waf_patterns.py -v
```

### Run Specific Test Class
```bash
pytest tests/test_terraform.py::TestWAFRules -v
pytest tests/test_ioc_matching.py::TestNetworkIOCs -v
pytest tests/test_waf_patterns.py::TestWAFPatterns -v
```

### Run with Coverage Report
```bash
pytest tests/ --cov=. --cov-report=html
```

### Run with Detailed Output
```bash
pytest tests/ -vv -s
```

## Critical Tests

### Empty Search String Validation
The most important test prevents the empty `search_string` issue in WAF rules:

```python
def test_no_empty_search_strings(self, terraform_dir):
    """Verify no byte_match rules use empty search_string."""
```

This test ensures that Rule 3 (RSC-Action-ID header) and any other byte_match rules
don't use empty search strings, which causes AWS WAF deployment failures.

### Pattern Compilation
Validates all regex patterns compile correctly:

```python
def test_regex_patterns_compile(self):
    """Verify regex patterns used in WAF are valid."""
```

### IP Synchronization
Ensures Terraform IP sets match the IOC configuration:

```python
def test_malicious_ips_in_ip_set(self, terraform_dir, ioc_config):
    """Verify known malicious IPs are in Terraform IP set."""
```

## Test Statistics

- **Total Tests**: 69
- **Terraform Tests**: 10
- **IOC Tests**: 38
- **WAF Pattern Tests**: 21

## Dependencies

All testing dependencies are in `requirements.txt`:
- pytest >= 8.2
- pytest-cov >= 4.1.0
- PyYAML >= 6.0.1
- python-hcl2 >= 4.3.0 (for Terraform parsing)

## Continuous Integration

These tests are designed to run in CI/CD pipelines to validate:
1. Terraform configuration changes don't break WAF rules
2. IOC updates maintain proper format and coverage
3. WAF patterns remain effective against known exploits
4. No deployment-blocking issues (like empty search_strings)

## Quality Gates

All tests must pass before:
- Deploying Terraform changes
- Updating IOC configurations
- Releasing new versions
- Merging pull requests

## Test Maintenance

When adding new IOCs:
1. Update `config/iocs.yaml`
2. Update `terraform/waf_rules.tf` if needed
3. Run tests to ensure synchronization
4. Add new test cases if introducing new patterns

## Known Issues to Test Against

### Empty Search String (Fixed)
- AWS WAF doesn't support empty `search_string` in byte_match statements
- Test validates this is never introduced

### Case Sensitivity
- Header names should be lowercase for consistency
- Tests validate naming conventions

### Regex Escaping
- Special characters must be properly escaped
- Tests validate correct escaping

### Coverage Gaps
- Tests ensure all critical attack vectors are covered
- MITRE ATT&CK techniques mapped
