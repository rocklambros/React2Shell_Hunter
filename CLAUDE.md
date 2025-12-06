# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

React2Shell Hunter is an AWS Organization-wide detection toolkit for CVE-2025-55182 (React Server Components RCE) and CVE-2025-66478 (Next.js). It provides:
- **Real-time detection** via GuardDuty ThreatIntelSet + EventBridge
- **Threat hunting** via Athena queries
- **HTTP protection** via WAF WebACL
- **Automated response** via Security Hub + SNS integration

---

## Critical Architecture Understanding

### **GuardDuty Does NOT Support Custom Detection Rules**

This is the most important concept. Detection works as follows:

```
1. ThreatIntelSet (custom IP list) → GuardDuty matches traffic → Generates "MaliciousIPCaller.Custom" finding
2. EventBridge rule filters finding type → Routes to SNS/Lambda/CloudWatch
3. Response team receives alert
```

**You CANNOT write detection rules in GuardDuty itself.** You can only:
- Upload IP lists (ThreatIntelSet) that trigger findings when matched
- Use EventBridge to filter and route the findings GuardDuty generates

---

## Commands

### Python Detection Script

```bash
# Install dependencies
pip install -r requirements.txt

# Basic single-account scan (last 24 hours)
python src/react2shell_detector.py --hours 24

# Organization-wide scan with all integrations
python src/react2shell_detector.py \
    --organization \
    --role-name SecurityAuditRole \
    --security-hub \
    --guardduty-bucket my-threat-intel-bucket \
    --vpc-log-group /aws/vpc/flowlogs \
    --waf-log-group aws-waf-logs-react2shell \
    --sns-topic arn:aws:sns:us-east-1:123456789012:alerts \
    --output json \
    --output-file findings.json

# Update GuardDuty ThreatIntelSet only
python src/react2shell_detector.py --guardduty-bucket my-bucket --hours 0
```

### Terraform Infrastructure

```bash
cd terraform

# Initialize
terraform init

# Plan (ALWAYS preview first)
terraform plan -var="threat_intel_bucket=my-bucket-name"

# Apply
terraform apply -var="threat_intel_bucket=my-bucket-name"

# Apply with WAF for CloudFront
terraform apply -var="threat_intel_bucket=my-bucket" -var="waf_scope=CLOUDFRONT"

# Destroy
terraform destroy -var="threat_intel_bucket=my-bucket-name"
```

### Athena Queries

```sql
-- Run in AWS Athena console after creating tables
-- See athena_queries/detection_queries.sql for 18 pre-built queries

-- Query 1: Detect C2 IP connections (CRITICAL)
SELECT * FROM cloudtrail_logs
WHERE sourceipaddress IN ('93.123.109.247', '45.77.33.136', ...)
```

---

## File Reference

### Core Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/react2shell_detector.py` | 1136 | Main Python scanner - CloudTrail, VPC, WAF, GuardDuty analysis |
| `config/iocs.yaml` | 452 | IOC database - IPs, domains, HTTP patterns, MITRE mappings |
| `terraform/guardduty.tf` | 405 | GuardDuty detector + ThreatIntelSet + S3 bucket + SNS |
| `terraform/eventbridge_rules.tf` | 533 | 7 EventBridge rules for specific finding types |
| `terraform/waf_rules.tf` | 644 | WAF WebACL with 9 detection rules |
| `lambda/ioc_scanner/handler.py` | 381 | Real-time Lambda for CloudTrail event processing |
| `athena_queries/detection_queries.sql` | 483 | 18 SQL queries for threat hunting |

### Documentation

| File | Purpose |
|------|---------|
| `docs/THREAT_INTELLIGENCE_REPORT.md` | Full threat intel report with IOCs |
| `docs/GUARDDUTY_EVENTBRIDGE_SETUP_GUIDE.md` | Manual setup guide (non-Terraform) |

---

## Python Script Architecture

### Classes and Their Responsibilities

```python
IOCLoader                 # Loads IOCs from config/iocs.yaml
├── get_malicious_ips()   # Returns Set[str] of C2 IPs
├── get_suspicious_ports()# Returns Set[int] of C2 ports
├── get_malicious_domains()# Returns Set[str] of C2 domains
└── get_payload_patterns()# Returns List[Dict] of HTTP patterns

CloudTrailAnalyzer        # Analyzes CloudTrail events via LookupEvents API
├── analyze_recent_events(hours) # Main entry point
└── _analyze_event()      # Checks source IP against IOCs

VPCFlowLogAnalyzer        # Analyzes VPC Flow Logs via CloudWatch Logs Insights
└── analyze_flow_logs(log_group, hours)

GuardDutyManager          # Manages GuardDuty integration
├── get_detector_id()     # Gets active detector
├── create_threat_intel_set(bucket) # Creates/updates ThreatIntelSet
└── get_relevant_findings(hours)    # Fetches matching findings

WAFLogAnalyzer            # Analyzes WAF logs for HTTP IOCs
└── analyze_waf_logs(log_group, hours)

OrganizationScanner       # Cross-account scanning
├── get_all_accounts()    # Lists org accounts
├── assume_role_in_account() # STS AssumeRole
└── scan_organization()   # Parallel account scanning

SecurityHubReporter       # Imports findings to Security Hub
└── import_findings(findings) # BatchImportFindings API

SNSAlerter                # Sends alerts via SNS
└── send_alert(findings)  # Publishes CRITICAL findings
```

### Data Flow

```
main()
├── IOCLoader(config/iocs.yaml)
├── if --organization:
│   └── OrganizationScanner.scan_organization()
│       └── For each account:
│           ├── CloudTrailAnalyzer.analyze_recent_events()
│           └── GuardDutyManager.get_relevant_findings()
├── else:
│   ├── CloudTrailAnalyzer.analyze_recent_events()
│   ├── GuardDutyManager.get_relevant_findings()
│   ├── if --guardduty-bucket:
│   │   └── GuardDutyManager.create_threat_intel_set()
│   ├── if --vpc-log-group:
│   │   └── VPCFlowLogAnalyzer.analyze_flow_logs()
│   └── if --waf-log-group:
│       └── WAFLogAnalyzer.analyze_waf_logs()
├── if --security-hub:
│   └── SecurityHubReporter.import_findings()
└── if --sns-topic:
    └── SNSAlerter.send_alert()
```

---

## Terraform Architecture

### guardduty.tf Creates:

1. **GuardDuty Detector** - Enables all data sources (S3, K8s, Malware, RDS, Runtime)
2. **S3 Bucket** - Stores threat intel IP list file
3. **ThreatIntelSet** - Loads C2 IPs, generates findings when matched
4. **IAM Role** - Allows GuardDuty to read S3 bucket
5. **SNS Topic** - Receives EventBridge notifications
6. **EventBridge Rule** - Filters high-severity findings (basic catch-all)
7. **CloudWatch Log Group** - Stores filtered findings

### eventbridge_rules.tf Creates 7 Specific Rules:

| Rule Name | Finding Pattern | Alert Message |
|-----------|-----------------|---------------|
| `react2shell-malicious-ip-caller` | `MaliciousIPCaller.Custom` | "CRITICAL: React2Shell C2 Communication" |
| `react2shell-credential-exfiltration` | `InstanceCredentialExfiltration.*` | "CRITICAL: EC2 Credential Exfiltration" |
| `react2shell-dns-exfiltration` | `DNSDataExfiltration` | "HIGH: DNS Data Exfiltration" |
| `react2shell-cryptocurrency-mining` | `CryptoCurrency:*` | "HIGH: Cryptocurrency Mining" |
| `react2shell-unusual-network-ports` | `NetworkPortUnusual` | "MEDIUM: Unusual Network Port" |
| `react2shell-malicious-domain` | `MaliciousDomainRequest.*` | "HIGH: Malicious Domain Request" |
| `react2shell-high-severity-catchall` | `severity >= 7` | (logs to CloudWatch) |

### waf_rules.tf Creates:

1. **IP Set** - 9 known C2 IPs in CIDR format
2. **Regex Pattern Set** - RCE patterns (`child_process`, `execSync`, etc.)
3. **WebACL** with 9 rules in priority order:
   - Priority 1: Block malicious IPs
   - Priority 2: Block `Next-Action` header
   - Priority 3: Block `rsc-action-id` header
   - Priority 4: Block prototype pollution (`__proto__`)
   - Priority 5: Block RCE patterns (regex)
   - Priority 6: Block `$ACTION_0:0` parameters
   - Priority 7: Rate limit suspicious user agents (COUNT only)
   - Priority 8: AWS Managed Known Bad Inputs
   - Priority 9: AWS Managed Common Rule Set
4. **CloudWatch Dashboard** - WAF metrics visualization
5. **CloudWatch Alarm** - High block rate alert

---

## IOC Database Structure (config/iocs.yaml)

```yaml
metadata:
  version: "1.0.0"
  cve_ids: [CVE-2025-55182, CVE-2025-66478]

mitre_attack:
  techniques:
    - id: T1190  # Exploit Public-Facing App
    - id: T1059.007  # JavaScript Execution
    - id: T1105  # Ingress Tool Transfer
    - id: T1552.001  # Credentials In Files
    - id: T1021  # Remote Services
    - id: T1496  # Resource Hijacking

network_iocs:
  malicious_ips:
    - ip: "93.123.109.247"
      port: 8000
      confidence: high
      source: "Datadog Security Labs"
    # ... 9 total IPs

  suspicious_ports: [652, 2045, 8000, 8080, 12000, 45178, 3333, 5555, ...]

  malicious_domains:
    exfiltration_services: [ceye.io, dnslog.cn, *.oastify.com]
    c2_domains: [sapo.shk0x.net, xwpoogfunv.zaza.eu.org]
    mining_pools: [*.c3pool.com, pool.supportxmr.com]

http_iocs:
  headers:
    - name: "Next-Action"
      severity: critical
    - name: "rsc-action-id"
      severity: critical

  payload_patterns:
    critical:
      - pattern: '__proto__:then'
      - pattern: 'process.mainModule.require'
      - pattern: 'child_process'
      - pattern: 'execSync'

aws_iocs:
  cloudtrail_patterns:
    credential_theft: [GetCallerIdentity, DescribeInstanceAttribute]
    lateral_movement: [SendCommand, StartSession, RunInstances]
    privilege_escalation: [CreateAccessKey, AttachUserPolicy, AttachRolePolicy]

  guardduty_findings:
    critical:
      - UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
      - Trojan:EC2/DNSDataExfiltration
      - CryptoCurrency:EC2/BitcoinTool.B!DNS
```

---

## Common Tasks

### Adding a New C2 IP

1. Edit `config/iocs.yaml`:
```yaml
network_iocs:
  malicious_ips:
    - ip: "NEW.IP.HERE"
      port: 8080
      confidence: high
      source: "Your source"
```

2. Update Terraform WAF IP set in `terraform/waf_rules.tf`:
```hcl
addresses = [
  # ... existing IPs ...
  "NEW.IP.HERE/32"
]
```

3. Update ThreatIntelSet:
```bash
python src/react2shell_detector.py --guardduty-bucket your-bucket
# OR
terraform apply -var="threat_intel_bucket=your-bucket"
```

### Testing the Detection Pipeline

```bash
# Generate sample GuardDuty finding
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty create-sample-findings \
    --detector-id $DETECTOR_ID \
    --finding-types "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom"

# Verify EventBridge triggered
aws events list-rule-names-by-target \
    --target-arn $(terraform output -raw sns_topic_arn)

# Check CloudWatch Logs
aws logs tail /aws/guardduty/react2shell-findings --follow
```

### Associating WAF with ALB

```bash
# Get WebACL ARN
WAF_ARN=$(terraform output -raw web_acl_arn)

# Associate with ALB
aws wafv2 associate-web-acl \
    --web-acl-arn $WAF_ARN \
    --resource-arn arn:aws:elasticloadbalancing:REGION:ACCOUNT:loadbalancer/app/NAME/ID
```

---

## Athena Query Categories

The `athena_queries/detection_queries.sql` contains 18 queries:

| Query # | Purpose | Priority |
|---------|---------|----------|
| 1 | C2 IP connections | CRITICAL |
| 2 | Credential reconnaissance (GetCallerIdentity) | HIGH |
| 3 | EC2 metadata harvesting | HIGH |
| 4 | Lateral movement via SSM | HIGH |
| 5 | Privilege escalation attempts | CRITICAL |
| 6 | Secrets Manager access | HIGH |
| 7 | Unusual RunInstances (cryptomining) | HIGH |
| 8 | S3 data exfiltration | HIGH |
| 9 | Security group modifications | MEDIUM |
| 10 | CloudTrail/logging tampering | CRITICAL |
| 11-15 | VPC Flow Log queries | VARIES |
| 16-18 | Aggregation/summary queries | VARIES |

---

## Error Handling

### Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| "No GuardDuty detector found" | GuardDuty not enabled | `terraform apply -var="enable_guardduty=true"` |
| "Failed to assume role" | Missing trust policy | Add calling account to role trust policy |
| "ThreatIntelSet ACTIVATING" | S3 permissions issue | Check bucket policy allows GuardDuty |
| "AccessDenied on CloudTrail" | Missing IAM permissions | Add `cloudtrail:LookupEvents` to role |
| "Rate exceeded" on org scan | Too many API calls | Reduce `max_workers` in OrganizationScanner |

---

## Security Considerations

This toolkit is for **defensive security** only. The code:

1. **DOES NOT** contain any exploitation code
2. **DOES NOT** connect to external C2 infrastructure
3. **ONLY** reads AWS logs and creates detection infrastructure
4. **REQUIRES** proper AWS authorization to function

The IOCs (IPs, domains, patterns) are **indicators of known malicious infrastructure** sourced from:
- Datadog Security Labs
- GreyNoise
- AWS Threat Intelligence
- Bitdefender

---

## Performance Notes

- **Organization scan**: Uses `ThreadPoolExecutor` with 10 workers by default
- **CloudTrail queries**: Paginated, may take several minutes for 24h+ ranges
- **VPC/WAF analysis**: Uses CloudWatch Logs Insights (charged per query)
- **Security Hub import**: Batched in groups of 100 findings (API limit)
