# React2Shell Hunter

**AWS Organization-Wide Detection Toolkit for CVE-2025-55182 & CVE-2025-66478**

A comprehensive security toolkit for detecting React2Shell exploitation attempts across AWS environments. This toolkit provides real-time detection, threat hunting capabilities, and automated response for the critical React Server Components RCE vulnerability.

---

## Table of Contents

1. [What This Toolkit Detects](#what-this-toolkit-detects)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Architecture Deep Dive](#architecture-deep-dive)
6. [Component Reference](#component-reference)
7. [Deployment Guide](#deployment-guide)
8. [IOC Reference](#ioc-reference)
9. [Troubleshooting](#troubleshooting)
10. [FAQ](#faq)

---

## What This Toolkit Detects

### CVE-2025-55182 (React Server Components)
- **CVSS Score**: 10.0 (Maximum severity)
- **Attack Vector**: Network, no authentication required
- **Root Cause**: Prototype pollution via unsafe deserialization in React's "Flight" protocol
- **Exploitation**: `__proto__:then` manipulation enables arbitrary code execution via `process.mainModule.require('child_process').execSync()`

### CVE-2025-66478 (Next.js)
- **Downstream Impact**: Next.js frameworks using vulnerable React versions
- **Affected Versions**: Next.js 15.0.4, 15.1.8, 15.2.5, 15.3.5, 15.4.7, 15.5.6, 16.0.6, and 14.3.0-canary.77+

### Attack Chain This Toolkit Detects

```
1. INITIAL ACCESS     → WAF detects Next-Action header + prototype pollution payloads
2. EXECUTION          → GuardDuty ThreatIntelSet detects C2 IP connections
3. CREDENTIAL THEFT   → CloudTrail detects GetCallerIdentity from EC2 roles
4. LATERAL MOVEMENT   → EventBridge rules detect SSM SendCommand/StartSession
5. EXFILTRATION       → DNS exfiltration to ceye.io/dnslog.cn detected
6. CRYPTOMINING       → GuardDuty detects cryptocurrency mining activity
```

---

## Prerequisites

### Required Permissions

```
# Minimum IAM permissions for the detection script
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents",
        "logs:StartQuery",
        "logs:GetQueryResults",
        "guardduty:ListDetectors",
        "guardduty:ListFindings",
        "guardduty:GetFindings",
        "guardduty:CreateThreatIntelSet",
        "guardduty:UpdateThreatIntelSet",
        "guardduty:ListThreatIntelSets",
        "guardduty:GetThreatIntelSet",
        "s3:PutObject",
        "s3:GetObject",
        "sts:GetCallerIdentity",
        "sts:AssumeRole"
      ],
      "Resource": "*"
    }
  ]
}

# For Security Hub integration, add:
"securityhub:BatchImportFindings"

# For SNS alerting, add:
"sns:Publish"

# For organization-wide scanning, add:
"organizations:ListAccounts"
```

### Software Requirements

| Software | Version | Purpose |
|----------|---------|---------|
| Python | 3.9+ | Detection script runtime |
| Terraform | 1.0+ | Infrastructure deployment |
| AWS CLI | 2.x | AWS authentication |
| boto3 | 1.34+ | AWS SDK for Python |

---

## Installation

### Step 1: Clone and Install Dependencies

```bash
# Navigate to project
cd React2Shell_Hunter

# Create virtual environment (RECOMMENDED)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Configure AWS Credentials

```bash
# Option A: Use AWS CLI profile
aws configure --profile security-scanner

# Option B: Export environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"

# Option C: Use IAM role (recommended for EC2/Lambda)
# Attach appropriate IAM role to your compute resource
```

### Step 3: Verify Installation

```bash
# Test AWS connectivity
aws sts get-caller-identity

# Test Python dependencies
python -c "import boto3, yaml; print('Dependencies OK')"

# Test IOC loading
python -c "
import yaml
with open('config/iocs.yaml') as f:
    iocs = yaml.safe_load(f)
    print(f'Loaded {len(iocs[\"network_iocs\"][\"malicious_ips\"])} malicious IPs')
"
```

---

## Quick Start

### Scan Current Account (Last 24 Hours)

```bash
python src/react2shell_detector.py --hours 24
```

**Expected Output:**
```
2025-12-06 10:00:00 - React2ShellDetector - INFO - ============================================================
2025-12-06 10:00:00 - React2ShellDetector - INFO - React2Shell IOC Detection Script
2025-12-06 10:00:00 - React2ShellDetector - INFO - CVE-2025-55182 & CVE-2025-66478
2025-12-06 10:00:00 - React2ShellDetector - INFO - ============================================================
2025-12-06 10:00:00 - React2ShellDetector - INFO - Starting single account scan...
2025-12-06 10:00:00 - React2ShellDetector - INFO - Analyzing CloudTrail logs...
2025-12-06 10:00:05 - React2ShellDetector - INFO - Checking GuardDuty findings...

Total findings: 0
  CRITICAL: 0
  HIGH: 0
  MEDIUM: 0
```

### Full Production Scan

```bash
python src/react2shell_detector.py \
    --organization \
    --role-name SecurityAuditRole \
    --security-hub \
    --guardduty-bucket my-threat-intel-bucket-12345 \
    --vpc-log-group /aws/vpc/flowlogs \
    --waf-log-group aws-waf-logs-react2shell \
    --sns-topic arn:aws:sns:us-east-1:123456789012:security-alerts \
    --output json \
    --output-file findings-$(date +%Y%m%d).json \
    --hours 72
```

---

## Architecture Deep Dive

### Critical Concept: How GuardDuty Detection Works

**YOU CANNOT CREATE CUSTOM DETECTION RULES IN GUARDDUTY.**

GuardDuty uses ML models and threat intelligence to generate findings. To detect React2Shell:

1. **ThreatIntelSet**: Upload C2 IPs to GuardDuty → Generates `MaliciousIPCaller.Custom` findings
2. **EventBridge**: Filter specific finding types → Route to SNS/Lambda/CloudWatch
3. **Response**: Receive alerts, trigger automation, investigate

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           DETECTION ARCHITECTURE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   DATA SOURCES              DETECTION ENGINE           RESPONSE              │
│   ════════════              ════════════════           ════════              │
│                                                                              │
│   ┌──────────┐             ┌─────────────────┐        ┌───────────┐         │
│   │CloudTrail│────────────>│    GuardDuty    │───────>│EventBridge│         │
│   │  Logs    │             │    Detector     │        │   Rules   │         │
│   └──────────┘             │                 │        └─────┬─────┘         │
│                            │ ┌─────────────┐ │              │               │
│   ┌──────────┐             │ │ThreatIntel  │ │              ▼               │
│   │VPC Flow  │────────────>│ │Set (C2 IPs) │ │        ┌───────────┐         │
│   │  Logs    │             │ └─────────────┘ │        │    SNS    │         │
│   └──────────┘             └─────────────────┘        │   Topic   │         │
│                                                        └─────┬─────┘         │
│   ┌──────────┐             ┌─────────────────┐              │               │
│   │DNS Query │────────────>│    Route 53     │              ▼               │
│   │  Logs    │             │    Resolver     │        ┌───────────┐         │
│   └──────────┘             └─────────────────┘        │  Lambda   │         │
│                                                        │ (Enrich)  │         │
│   ┌──────────┐             ┌─────────────────┐        └─────┬─────┘         │
│   │   WAF    │────────────>│   WAF WebACL    │              │               │
│   │  Logs    │             │  (HTTP Rules)   │              ▼               │
│   └──────────┘             └─────────────────┘        ┌───────────┐         │
│                                                        │ Security  │         │
│                                                        │    Hub    │         │
│                                                        └───────────┘         │
└─────────────────────────────────────────────────────────────────────────────┘
```

### EventBridge Rule Patterns

The Terraform creates 7 specific EventBridge rules:

| Rule | Finding Type Pattern | Severity |
|------|---------------------|----------|
| `react2shell-malicious-ip-caller` | `MaliciousIPCaller.Custom` | CRITICAL |
| `react2shell-credential-exfiltration` | `InstanceCredentialExfiltration.*` | CRITICAL |
| `react2shell-dns-exfiltration` | `DNSDataExfiltration` | HIGH |
| `react2shell-cryptocurrency-mining` | `CryptoCurrency:*` | HIGH |
| `react2shell-unusual-network-ports` | `NetworkPortUnusual` | MEDIUM |
| `react2shell-malicious-domain` | `MaliciousDomainRequest.*` | HIGH |
| `react2shell-high-severity-catchall` | Severity >= 7 | VARIES |

### WAF Protection Layers

The WAF WebACL implements 9 rules in priority order:

| Priority | Rule | Action | What It Detects |
|----------|------|--------|-----------------|
| 1 | Block Malicious IPs | BLOCK | Connections from 9 known C2 IPs |
| 2 | Next-Action Header | BLOCK | Presence of `Next-Action` header |
| 3 | RSC-Action-ID Header | BLOCK | Presence of `rsc-action-id` header |
| 4 | Prototype Pollution | BLOCK | `__proto__` or `constructor.prototype` in body |
| 5 | RCE Patterns | BLOCK | `process.mainModule.require`, `child_process`, `execSync` |
| 6 | ACTION Parameter | BLOCK | `$ACTION_0:0` or `$ACTION_REF` in POST body |
| 7 | Suspicious User-Agents | COUNT | `Go-http-client`, `Assetnote`, `python-requests` |
| 8 | AWS Known Bad Inputs | INHERIT | AWS managed rule group |
| 9 | AWS Common Rule Set | INHERIT | AWS managed rule group |

---

## Component Reference

### Project Structure

```
React2Shell_Hunter/
├── config/
│   └── iocs.yaml                    # IOC database (IPs, domains, patterns)
├── src/
│   └── react2shell_detector.py      # Main detection script (1136 lines)
├── terraform/
│   ├── guardduty.tf                 # GuardDuty + ThreatIntelSet + S3
│   ├── eventbridge_rules.tf         # 7 EventBridge rules
│   └── waf_rules.tf                 # WAF WebACL with 9 rules
├── lambda/
│   └── ioc_scanner/
│       └── handler.py               # Real-time Lambda scanner
├── athena_queries/
│   └── detection_queries.sql        # 18 threat hunting queries
├── docs/
│   ├── THREAT_INTELLIGENCE_REPORT.md
│   └── GUARDDUTY_EVENTBRIDGE_SETUP_GUIDE.md
├── requirements.txt
├── README.md
└── CLAUDE.md
```

### Python Script Classes

| Class | Purpose | Key Methods |
|-------|---------|-------------|
| `IOCLoader` | Load IOCs from YAML | `get_malicious_ips()`, `get_suspicious_ports()`, `get_malicious_domains()` |
| `CloudTrailAnalyzer` | Detect API-based IOCs | `analyze_recent_events(hours)` |
| `VPCFlowLogAnalyzer` | Detect network IOCs | `analyze_flow_logs(log_group, hours)` |
| `GuardDutyManager` | Manage threat intel | `create_threat_intel_set(bucket)`, `get_relevant_findings(hours)` |
| `WAFLogAnalyzer` | Detect HTTP IOCs | `analyze_waf_logs(log_group, hours)` |
| `OrganizationScanner` | Cross-account scanning | `scan_organization(hours, role_name)` |
| `SecurityHubReporter` | Import findings | `import_findings(findings)` |
| `SNSAlerter` | Send alerts | `send_alert(findings)` |

### CLI Arguments Reference

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--config` | string | `config/iocs.yaml` | Path to IOC configuration file |
| `--hours` | int | 24 | Hours of logs to analyze |
| `--organization` | flag | false | Scan entire AWS Organization |
| `--role-name` | string | `OrganizationAccountAccessRole` | Role to assume in member accounts |
| `--sns-topic` | string | none | SNS topic ARN for alerts |
| `--security-hub` | flag | false | Import findings to Security Hub |
| `--guardduty-bucket` | string | none | S3 bucket for GuardDuty threat intel |
| `--vpc-log-group` | string | none | VPC Flow Logs CloudWatch log group |
| `--waf-log-group` | string | none | WAF logs CloudWatch log group |
| `--output` | enum | `text` | Output format: `json`, `text`, `csv` |
| `--output-file` | string | none | Output file path |
| `--debug` | flag | false | Enable debug logging |

---

## Deployment Guide

### Step 1: Deploy Terraform Infrastructure

```bash
cd terraform

# Initialize Terraform
terraform init

# Preview changes (ALWAYS DO THIS FIRST)
terraform plan \
    -var="threat_intel_bucket=react2shell-threat-intel-$(aws sts get-caller-identity --query Account --output text)" \
    -var="enable_guardduty=true" \
    -var="enable_waf=true" \
    -var="waf_scope=REGIONAL"

# Apply changes
terraform apply \
    -var="threat_intel_bucket=react2shell-threat-intel-$(aws sts get-caller-identity --query Account --output text)"
```

**Terraform Variables:**

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `threat_intel_bucket` | YES | - | S3 bucket name for threat intel files |
| `enable_guardduty` | no | true | Enable GuardDuty detector |
| `enable_waf` | no | true | Create WAF WebACL |
| `waf_scope` | no | REGIONAL | `REGIONAL` or `CLOUDFRONT` |
| `block_mode` | no | BLOCK | `BLOCK` or `COUNT` |
| `enable_lambda_automation` | no | false | Enable Lambda for automated response |

### Step 2: Associate WAF with Resources

The WAF WebACL must be associated with your resources:

```bash
# Associate with ALB
aws wafv2 associate-web-acl \
    --web-acl-arn $(terraform output -raw web_acl_arn) \
    --resource-arn arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890

# Associate with API Gateway
aws wafv2 associate-web-acl \
    --web-acl-arn $(terraform output -raw web_acl_arn) \
    --resource-arn arn:aws:apigateway:us-east-1::/restapis/abc123/stages/prod
```

### Step 3: Subscribe to SNS Alerts

```bash
# Get SNS topic ARN
SNS_TOPIC=$(terraform output -raw sns_topic_arn)

# Subscribe email
aws sns subscribe \
    --topic-arn $SNS_TOPIC \
    --protocol email \
    --notification-endpoint your-security-team@example.com

# Subscribe Slack webhook (via Lambda)
aws sns subscribe \
    --topic-arn $SNS_TOPIC \
    --protocol lambda \
    --notification-endpoint arn:aws:lambda:us-east-1:123456789012:function:slack-notifier
```

### Step 4: Create Athena Tables

```bash
# Open Athena console or use AWS CLI
# Run the CREATE TABLE statements from athena_queries/detection_queries.sql

# CloudTrail table
aws athena start-query-execution \
    --query-string "CREATE EXTERNAL TABLE cloudtrail_logs ..." \
    --work-group primary \
    --query-execution-context Database=default
```

---

## IOC Reference

### Malicious IP Addresses

| IP Address | Port | Confidence | Context | Source |
|------------|------|------------|---------|--------|
| 93.123.109.247 | 8000 | HIGH | Primary C2 Server | Datadog |
| 45.77.33.136 | 8080 | HIGH | Primary C2 Server | Datadog |
| 194.246.84.13 | 2045 | HIGH | Primary C2 Server | Datadog |
| 141.11.240.103 | 45178 | HIGH | Primary C2 Server | Datadog |
| 23.235.188.3 | 652 | HIGH | PowerShell Stager | GreyNoise |
| 46.36.37.85 | 12000 | HIGH | Payload Staging | GreyNoise |
| 144.202.115.234 | 80 | MEDIUM | Payload Hosting | Datadog |
| 162.215.170.26 | 3000 | MEDIUM | Secondary Payload | GreyNoise |
| 45.32.158.54 | - | MEDIUM | Scanner | GreyNoise |

### Malicious Domains

| Domain | Category | Confidence |
|--------|----------|------------|
| ceye.io | DNS Exfiltration | HIGH |
| dnslog.cn | DNS Exfiltration | HIGH |
| *.oastify.com | Burp Collaborator | MEDIUM |
| sapo.shk0x.net | C2 | HIGH |
| xwpoogfunv.zaza.eu.org | C2 | HIGH |
| *.c3pool.com | Cryptomining | HIGH |

### Suspicious Ports

| Port | Usage |
|------|-------|
| 652 | PowerShell stager |
| 2045 | Custom C2 |
| 8000, 8080 | Alternative HTTP C2 |
| 12000, 45178 | Custom C2 |
| 3333, 5555, 14433, 14444 | Cryptomining |

### HTTP Indicators

| Pattern | Severity | Description |
|---------|----------|-------------|
| `Next-Action: *` | CRITICAL | RSC exploitation header |
| `rsc-action-id: *` | CRITICAL | RSC action identifier |
| `$ACTION_0:0` | CRITICAL | RSC action parameter |
| `__proto__:then` | CRITICAL | Prototype pollution |
| `process.mainModule.require` | CRITICAL | Node.js RCE |
| `child_process` | CRITICAL | Command execution |
| `Go-http-client/1.1` | MEDIUM | Scanner user agent |

---

## Troubleshooting

### Common Issues

#### "No GuardDuty detector found"

```bash
# Check if GuardDuty is enabled
aws guardduty list-detectors

# If empty, enable GuardDuty
aws guardduty create-detector --enable

# Or use Terraform
terraform apply -var="enable_guardduty=true"
```

#### "Failed to assume role in member account"

```bash
# Verify role exists in target account
aws iam get-role --role-name SecurityAuditRole

# Verify trust policy allows your account
aws iam get-role --role-name SecurityAuditRole --query 'Role.AssumeRolePolicyDocument'

# Test role assumption
aws sts assume-role \
    --role-arn arn:aws:iam::TARGET_ACCOUNT:role/SecurityAuditRole \
    --role-session-name test
```

#### "ThreatIntelSet stuck in ACTIVATING"

```bash
# Check ThreatIntelSet status
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty list-threat-intel-sets --detector-id $DETECTOR_ID

# Verify S3 bucket permissions
aws s3api get-bucket-policy --bucket your-threat-intel-bucket

# Verify IP list format (one IP per line, no CIDR)
aws s3 cp s3://your-bucket/threat-intel/react2shell-ips.txt -
```

#### "WAF rule not blocking"

```bash
# Check if WebACL is associated
aws wafv2 list-resources-for-web-acl \
    --web-acl-arn $(terraform output -raw web_acl_arn)

# Check sampled requests
aws wafv2 get-sampled-requests \
    --web-acl-arn $(terraform output -raw web_acl_arn) \
    --rule-metric-name React2Shell-Malicious-IP-Blocked \
    --scope REGIONAL \
    --time-window StartTime=2025-12-06T00:00:00Z,EndTime=2025-12-06T23:59:59Z \
    --max-items 10
```

#### "No findings generated"

```bash
# Generate sample findings to test pipeline
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty create-sample-findings \
    --detector-id $DETECTOR_ID \
    --finding-types "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom"

# Check EventBridge rule invocations
aws cloudwatch get-metric-statistics \
    --namespace AWS/Events \
    --metric-name Invocations \
    --dimensions Name=RuleName,Value=react2shell-malicious-ip-caller \
    --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%SZ) \
    --period 300 \
    --statistics Sum
```

---

## FAQ

### Q: Does this replace patching?

**NO.** This is a detection toolkit, not a prevention solution. You MUST patch:
- React: 19.0.1, 19.1.2, or 19.2.1
- Next.js: 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, or 16.0.7

### Q: Will this detect all React2Shell attacks?

**No detection is 100%.** This toolkit detects:
- Connections to known C2 IPs (if attacker uses new IPs, won't detect)
- Known payload patterns (if attacker obfuscates, may evade WAF)
- Post-exploitation behavior (credential theft, lateral movement)

### Q: How often should I run the scanner?

Recommended schedule:
- **Continuous**: GuardDuty + EventBridge (real-time)
- **Hourly**: Python script with `--hours 1`
- **Daily**: Full Athena threat hunt queries

### Q: How do I add new IOCs?

Edit `config/iocs.yaml` and add to appropriate sections:

```yaml
network_iocs:
  malicious_ips:
    - ip: "NEW.IP.ADDRESS.HERE"
      port: 8080
      context: "Description"
      confidence: high
      source: "Your source"
```

Then update ThreatIntelSet:

```bash
python src/react2shell_detector.py --guardduty-bucket your-bucket
```

---

## References

- [CVE-2025-55182 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- [React2Shell Official Site](https://react2shell.com/)
- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components/)
- [AWS Security Blog](https://aws.amazon.com/blogs/security/china-nexus-cyber-threat-groups-rapidly-exploit-react2shell-vulnerability-cve-2025-55182/)
- [Datadog IOC Repository](https://github.com/DataDog/indicators-of-compromise/tree/main/react-CVE-2025-55182)

---

**Disclaimer:** This toolkit is for defensive security purposes only. Ensure you have proper authorization before scanning systems.
