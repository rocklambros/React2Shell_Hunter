# GuardDuty + EventBridge Setup Guide for React2Shell Detection

**CVE-2025-55182 & CVE-2025-66478 Detection Configuration**

This guide provides step-by-step instructions for configuring AWS GuardDuty and EventBridge to detect React2Shell exploitation attempts across your AWS environment.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Step 1: Enable GuardDuty](#step-1-enable-guardduty)
4. [Step 2: Create ThreatIntelSet with C2 IPs](#step-2-create-threatintelset-with-c2-ips)
5. [Step 3: Create SNS Topic for Alerts](#step-3-create-sns-topic-for-alerts)
6. [Step 4: Create EventBridge Rules](#step-4-create-eventbridge-rules)
7. [Step 5: Configure Lambda for Enhanced Processing](#step-5-configure-lambda-for-enhanced-processing)
8. [Step 6: Enable Security Hub Integration](#step-6-enable-security-hub-integration)
9. [Complete IOC Reference](#complete-ioc-reference)
10. [Verification & Testing](#verification--testing)
11. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         AWS Environment                              │
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │  CloudTrail  │───>│  GuardDuty   │───>│  EventBridge Rules   │  │
│  │  VPC Flows   │    │  (Detector)  │    │  (Pattern Matching)  │  │
│  │  DNS Logs    │    │              │    │                      │  │
│  └──────────────┘    │ ThreatIntel  │    └──────────┬───────────┘  │
│                      │    Set       │               │              │
│                      └──────────────┘               │              │
│                                                     ▼              │
│                      ┌──────────────────────────────────────────┐  │
│                      │              Targets                      │  │
│                      │  ┌─────────┐  ┌────────┐  ┌───────────┐ │  │
│                      │  │   SNS   │  │ Lambda │  │CloudWatch │ │  │
│                      │  │  Topic  │  │Function│  │   Logs    │ │  │
│                      │  └────┬────┘  └────┬───┘  └─────┬─────┘ │  │
│                      └───────┼────────────┼────────────┼───────┘  │
│                              │            │            │          │
│                              ▼            ▼            ▼          │
│                         ┌─────────────────────────────────────┐   │
│                         │  Email/Slack  Security Hub  SIEM    │   │
│                         └─────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

**Key Concept**: GuardDuty generates findings based on its ML models and ThreatIntelSets. You cannot create custom detection rules within GuardDuty itself. Instead, you use EventBridge to filter specific finding types and route them to appropriate targets.

---

## Prerequisites

- AWS Account with administrative access
- GuardDuty permissions: `guardduty:*`
- EventBridge permissions: `events:*`
- SNS permissions: `sns:*`
- S3 permissions (for ThreatIntelSet): `s3:*`
- Optional: Lambda permissions for enhanced processing

---

## Step 1: Enable GuardDuty

### Console Method

1. Navigate to **GuardDuty** in AWS Console
2. Click **Get Started**
3. Click **Enable GuardDuty**
4. Enable all data sources:
   - **S3 Protection**: Enabled
   - **EKS Protection**: Enabled (if using EKS)
   - **Malware Protection**: Enabled
   - **RDS Protection**: Enabled (if using RDS)
   - **Lambda Protection**: Enabled
   - **Runtime Monitoring**: Enabled

### AWS CLI Method

```bash
# Enable GuardDuty detector
aws guardduty create-detector \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES \
  --data-sources '{
    "S3Logs": {"Enable": true},
    "Kubernetes": {"AuditLogs": {"Enable": true}},
    "MalwareProtection": {"ScanEc2InstanceWithFindings": {"EbsVolumes": true}}
  }'

# Get detector ID
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
echo "Detector ID: $DETECTOR_ID"
```

---

## Step 2: Create ThreatIntelSet with C2 IPs

### 2.1 Create S3 Bucket for Threat Intel

```bash
# Create bucket
aws s3 mb s3://react2shell-threat-intel-$(aws sts get-caller-identity --query Account --output text)

# Set bucket name variable
BUCKET_NAME="react2shell-threat-intel-$(aws sts get-caller-identity --query Account --output text)"
```

### 2.2 Create the IP List File

Create a file named `react2shell-c2-ips.txt` with the following content:

```
# React2Shell C2 Infrastructure - CVE-2025-55182 / CVE-2025-66478
# Last Updated: 2025-12-06
# Source: Datadog Security Labs, GreyNoise, AWS Threat Intelligence

# Primary C2 Servers (HIGH Confidence)
93.123.109.247
45.77.33.136
194.246.84.13
141.11.240.103
23.235.188.3

# Payload Staging/Secondary (MEDIUM-HIGH Confidence)
46.36.37.85
144.202.115.234
162.215.170.26

# Known Scanners (MEDIUM Confidence)
45.32.158.54

# Additional IOCs from GreyNoise
# Add new IPs as they are identified
```

### 2.3 Upload to S3

```bash
# Upload the IP list
aws s3 cp react2shell-c2-ips.txt s3://$BUCKET_NAME/react2shell-c2-ips.txt

# Verify upload
aws s3 ls s3://$BUCKET_NAME/
```

### 2.4 Create ThreatIntelSet in GuardDuty

```bash
# Get detector ID
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

# Create ThreatIntelSet
aws guardduty create-threat-intel-set \
  --detector-id $DETECTOR_ID \
  --name "React2Shell-C2-IPs" \
  --format TXT \
  --location "s3://$BUCKET_NAME/react2shell-c2-ips.txt" \
  --activate

# Verify creation
aws guardduty list-threat-intel-sets --detector-id $DETECTOR_ID
```

### Console Method

1. Navigate to **GuardDuty** → **Settings** → **Lists**
2. Click **Add a trusted IP list** or **Add a threat list**
3. Select **Add a threat list**
4. Configure:
   - **List name**: `React2Shell-C2-IPs`
   - **Location**: `s3://your-bucket/react2shell-c2-ips.txt`
   - **Format**: Plaintext
5. Click **Add list**
6. Toggle the list to **Active**

---

## Step 3: Create SNS Topic for Alerts

### 3.1 Create SNS Topic

```bash
# Create topic
aws sns create-topic --name react2shell-guardduty-alerts

# Get topic ARN
TOPIC_ARN=$(aws sns list-topics --query "Topics[?contains(TopicArn, 'react2shell-guardduty-alerts')].TopicArn" --output text)
echo "Topic ARN: $TOPIC_ARN"

# Subscribe email
aws sns subscribe \
  --topic-arn $TOPIC_ARN \
  --protocol email \
  --notification-endpoint your-security-team@example.com
```

### 3.2 Create SNS Access Policy for EventBridge

```bash
# Get account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Create policy document
cat > sns-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowEventBridgePublish",
      "Effect": "Allow",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Action": "sns:Publish",
      "Resource": "$TOPIC_ARN",
      "Condition": {
        "ArnLike": {
          "aws:SourceArn": "arn:aws:events:*:$ACCOUNT_ID:rule/*"
        }
      }
    }
  ]
}
EOF

# Apply policy
aws sns set-topic-attributes \
  --topic-arn $TOPIC_ARN \
  --attribute-name Policy \
  --attribute-value file://sns-policy.json
```

---

## Step 4: Create EventBridge Rules

This is the critical step where you define the "detection logic" by filtering specific GuardDuty finding types.

### 4.1 Rule 1: ThreatIntelSet IP Matches (CRITICAL)

This rule catches when GuardDuty detects traffic from/to your ThreatIntelSet IPs.

```bash
# Create the rule
aws events put-rule \
  --name "React2Shell-ThreatIntelSet-Match" \
  --description "Detects API calls from React2Shell C2 IPs via ThreatIntelSet" \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "type": [{
        "prefix": "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom"
      }]
    }
  }' \
  --state ENABLED

# Add SNS target
aws events put-targets \
  --rule "React2Shell-ThreatIntelSet-Match" \
  --targets "Id"="1","Arn"="$TOPIC_ARN"
```

### 4.2 Rule 2: Credential Exfiltration (CRITICAL)

Detects when EC2 instance credentials are used from outside AWS - common post-exploitation behavior.

```bash
aws events put-rule \
  --name "React2Shell-Credential-Exfiltration" \
  --description "Detects EC2 instance credential theft and exfiltration" \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "type": [
        {"prefix": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"},
        {"prefix": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS"}
      ]
    }
  }' \
  --state ENABLED

aws events put-targets \
  --rule "React2Shell-Credential-Exfiltration" \
  --targets "Id"="1","Arn"="$TOPIC_ARN"
```

### 4.3 Rule 3: DNS Data Exfiltration (HIGH)

Detects DNS-based exfiltration to domains like ceye.io, dnslog.cn.

```bash
aws events put-rule \
  --name "React2Shell-DNS-Exfiltration" \
  --description "Detects DNS-based data exfiltration patterns" \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "type": [
        {"prefix": "Trojan:EC2/DNSDataExfiltration"},
        {"prefix": "Backdoor:EC2/DenialOfService.Dns"}
      ]
    }
  }' \
  --state ENABLED

aws events put-targets \
  --rule "React2Shell-DNS-Exfiltration" \
  --targets "Id"="1","Arn"="$TOPIC_ARN"
```

### 4.4 Rule 4: Cryptomining Detection (HIGH)

Attackers often deploy cryptominers after initial compromise.

```bash
aws events put-rule \
  --name "React2Shell-Cryptomining" \
  --description "Detects cryptocurrency mining activity post-exploitation" \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "type": [
        {"prefix": "CryptoCurrency:EC2/BitcoinTool"},
        {"prefix": "CryptoCurrency:Runtime/BitcoinTool"},
        {"prefix": "CryptoCurrency:Lambda/BitcoinTool"}
      ]
    }
  }' \
  --state ENABLED

aws events put-targets \
  --rule "React2Shell-Cryptomining" \
  --targets "Id"="1","Arn"="$TOPIC_ARN"
```

### 4.5 Rule 5: Unusual Network Ports (MEDIUM)

Detects C2 communication on unusual ports (652, 2045, 12000, 45178).

```bash
aws events put-rule \
  --name "React2Shell-Unusual-Ports" \
  --description "Detects network communication on unusual C2 ports" \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "type": [
        {"prefix": "Behavior:EC2/NetworkPortUnusual"},
        {"prefix": "Trojan:EC2/BlackholeTraffic"}
      ]
    }
  }' \
  --state ENABLED

aws events put-targets \
  --rule "React2Shell-Unusual-Ports" \
  --targets "Id"="1","Arn"="$TOPIC_ARN"
```

### 4.6 Rule 6: Malicious Domain Requests (MEDIUM-HIGH)

Catches requests to known malicious domains.

```bash
aws events put-rule \
  --name "React2Shell-Malicious-Domains" \
  --description "Detects requests to known malicious domains" \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "type": [
        {"prefix": "Trojan:EC2/DGADomainRequest"},
        {"prefix": "Trojan:EC2/DriveBySourceTraffic"},
        {"prefix": "Trojan:EC2/DropPoint"},
        {"prefix": "Trojan:EC2/PhishingDomainRequest"},
        {"prefix": "Backdoor:EC2/C&CActivity"}
      ]
    }
  }' \
  --state ENABLED

aws events put-targets \
  --rule "React2Shell-Malicious-Domains" \
  --targets "Id"="1","Arn"="$TOPIC_ARN"
```

### 4.7 Rule 7: High Severity Catch-All (CRITICAL)

Catches any HIGH or CRITICAL severity finding.

```bash
aws events put-rule \
  --name "React2Shell-High-Severity-All" \
  --description "Catches all high/critical severity GuardDuty findings" \
  --event-pattern '{
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "severity": [
        {"numeric": [">=", 7]}
      ]
    }
  }' \
  --state ENABLED

aws events put-targets \
  --rule "React2Shell-High-Severity-All" \
  --targets "Id"="1","Arn"="$TOPIC_ARN"
```

### Console Method for EventBridge Rules

1. Navigate to **Amazon EventBridge** → **Rules**
2. Click **Create rule**
3. Configure:
   - **Name**: `React2Shell-ThreatIntelSet-Match`
   - **Event bus**: default
   - **Rule type**: Rule with an event pattern
4. Click **Next**
5. For **Event pattern**, select:
   - **Event source**: AWS events or EventBridge partner events
   - **AWS service**: GuardDuty
   - **Event type**: GuardDuty Finding
6. Click **Edit pattern** and paste:

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "type": [{
      "prefix": "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom"
    }]
  }
}
```

7. Click **Next**
8. Select target:
   - **Target type**: AWS service
   - **Select a target**: SNS topic
   - **Topic**: react2shell-guardduty-alerts
9. Click **Next** → **Create rule**

Repeat for each rule type.

---

## Step 5: Configure Lambda for Enhanced Processing

For enriched alerts with IOC context, create a Lambda function.

### 5.1 Create Lambda Function

Create `lambda_function.py`:

```python
import json
import boto3
import os
from datetime import datetime

sns = boto3.client('sns')

# React2Shell IOCs for enrichment
REACT2SHELL_C2_IPS = {
    '93.123.109.247': {'port': 8000, 'confidence': 'HIGH', 'context': 'Primary C2'},
    '45.77.33.136': {'port': 8080, 'confidence': 'HIGH', 'context': 'Primary C2'},
    '194.246.84.13': {'port': 2045, 'confidence': 'HIGH', 'context': 'Primary C2'},
    '141.11.240.103': {'port': 45178, 'confidence': 'HIGH', 'context': 'Primary C2'},
    '23.235.188.3': {'port': 652, 'confidence': 'HIGH', 'context': 'PowerShell Stager'},
    '46.36.37.85': {'port': 12000, 'confidence': 'HIGH', 'context': 'Payload Staging'},
    '144.202.115.234': {'port': 80, 'confidence': 'MEDIUM', 'context': 'Payload Hosting'},
    '162.215.170.26': {'port': 3000, 'confidence': 'MEDIUM', 'context': 'Secondary Payload'},
    '45.32.158.54': {'port': None, 'confidence': 'MEDIUM', 'context': 'Scanner'}
}

MALICIOUS_DOMAINS = ['ceye.io', 'dnslog.cn', 'oastify.com', 'c3pool.com']

def lambda_handler(event, context):
    finding = event.get('detail', {})

    # Extract key information
    finding_type = finding.get('type', '')
    severity = finding.get('severity', 0)
    account_id = finding.get('accountId', '')
    region = finding.get('region', '')

    # Check for React2Shell IOCs
    react2shell_match = False
    ioc_details = []

    # Check remote IP
    remote_ip = finding.get('service', {}).get('action', {}).get('networkConnectionAction', {}).get('remoteIpDetails', {}).get('ipAddressV4', '')
    if remote_ip in REACT2SHELL_C2_IPS:
        react2shell_match = True
        ioc_info = REACT2SHELL_C2_IPS[remote_ip]
        ioc_details.append(f"C2 IP: {remote_ip} ({ioc_info['context']}, {ioc_info['confidence']} confidence)")

    # Check domain
    domain = finding.get('service', {}).get('action', {}).get('dnsRequestAction', {}).get('domain', '')
    for mal_domain in MALICIOUS_DOMAINS:
        if mal_domain in domain:
            react2shell_match = True
            ioc_details.append(f"Malicious Domain: {domain} (matches {mal_domain})")

    # Build enriched alert
    alert = {
        'alert_type': 'React2Shell IOC Detection' if react2shell_match else 'GuardDuty Finding',
        'cve': 'CVE-2025-55182 / CVE-2025-66478' if react2shell_match else 'N/A',
        'finding_type': finding_type,
        'severity': severity,
        'severity_label': 'CRITICAL' if severity >= 8 else 'HIGH' if severity >= 7 else 'MEDIUM' if severity >= 4 else 'LOW',
        'account_id': account_id,
        'region': region,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'react2shell_match': react2shell_match,
        'ioc_details': ioc_details,
        'resource': finding.get('resource', {}),
        'action_required': 'IMMEDIATE INVESTIGATION REQUIRED' if react2shell_match or severity >= 7 else 'Review recommended',
        'mitre_techniques': ['T1190', 'T1059.007', 'T1552.001'] if react2shell_match else []
    }

    # Publish to SNS
    topic_arn = os.environ.get('SNS_TOPIC_ARN')
    if topic_arn:
        sns.publish(
            TopicArn=topic_arn,
            Subject=f"[{alert['severity_label']}] {alert['alert_type']}: {finding_type}",
            Message=json.dumps(alert, indent=2)
        )

    return {
        'statusCode': 200,
        'body': json.dumps(alert)
    }
```

### 5.2 Create Lambda via CLI

```bash
# Create deployment package
zip lambda_function.zip lambda_function.py

# Create Lambda function
aws lambda create-function \
  --function-name React2Shell-GuardDuty-Enricher \
  --runtime python3.11 \
  --handler lambda_function.lambda_handler \
  --role arn:aws:iam::$ACCOUNT_ID:role/LambdaGuardDutyRole \
  --zip-file fileb://lambda_function.zip \
  --environment "Variables={SNS_TOPIC_ARN=$TOPIC_ARN}" \
  --timeout 30

# Add EventBridge permission
aws lambda add-permission \
  --function-name React2Shell-GuardDuty-Enricher \
  --statement-id EventBridgeInvoke \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com
```

---

## Step 6: Enable Security Hub Integration

### 6.1 Enable Security Hub

```bash
aws securityhub enable-security-hub \
  --enable-default-standards
```

### 6.2 Enable GuardDuty Integration

```bash
# GuardDuty findings are automatically sent to Security Hub when both are enabled
# Verify integration
aws securityhub get-enabled-standards
```

### Console Method

1. Navigate to **Security Hub**
2. Click **Go to Security Hub**
3. Enable **AWS Foundational Security Best Practices**
4. GuardDuty integration is automatic

---

## Complete IOC Reference

### Malicious IP Addresses

| IP Address | Port | Confidence | Context | First Seen |
|------------|------|------------|---------|------------|
| 93.123.109.247 | 8000 | HIGH | Primary C2 Server | Dec 3, 2025 |
| 45.77.33.136 | 8080 | HIGH | Primary C2 Server | Dec 3, 2025 |
| 194.246.84.13 | 2045 | HIGH | Primary C2 Server | Dec 4, 2025 |
| 141.11.240.103 | 45178 | HIGH | Primary C2 Server | Dec 4, 2025 |
| 23.235.188.3 | 652 | HIGH | PowerShell Stager | Dec 4, 2025 |
| 46.36.37.85 | 12000 | HIGH | Payload Staging | Dec 4, 2025 |
| 144.202.115.234 | 80 | MEDIUM | Payload Hosting | Dec 5, 2025 |
| 162.215.170.26 | 3000 | MEDIUM | Secondary Payload | Dec 5, 2025 |
| 45.32.158.54 | - | MEDIUM | Known Scanner | Dec 3, 2025 |

### Malicious Domains

| Domain | Category | Confidence | Usage |
|--------|----------|------------|-------|
| ceye.io | DNS Exfil | HIGH | Data exfiltration via DNS |
| dnslog.cn | DNS Exfil | HIGH | Data exfiltration via DNS |
| *.oastify.com | OOB Testing | MEDIUM | Burp Collaborator callbacks |
| sapo.shk0x.net | C2 | HIGH | Command & control |
| xwpoogfunv.zaza.eu.org | C2 | HIGH | Command & control |
| *.a02.lol | C2 | MEDIUM | Command & control |
| *.c3pool.com | Crypto | HIGH | Cryptomining pool |

### Suspicious Ports

| Port | Protocol | Usage |
|------|----------|-------|
| 652 | TCP | PowerShell stager communication |
| 2045 | TCP | Custom C2 protocol |
| 8000 | TCP | Alternative HTTP C2 |
| 8080 | TCP | Alternative HTTP C2 |
| 12000 | TCP | Custom C2 protocol |
| 45178 | TCP | Custom C2 protocol |
| 3333 | TCP | Cryptomining (XMRig) |
| 5555 | TCP | Cryptomining (XMRig) |
| 14433 | TCP | Cryptomining (XMRig TLS) |
| 14444 | TCP | Cryptomining (XMRig TLS) |

### HTTP IOCs

| Pattern | Description | Detection Point |
|---------|-------------|-----------------|
| `Next-Action: *` | RSC exploitation header | WAF / ALB Logs |
| `rsc-action-id: *` | RSC action identifier | WAF / ALB Logs |
| `$ACTION_0:0` | RSC action parameter | WAF / ALB Logs |
| `__proto__:then` | Prototype pollution | WAF / ALB Logs |
| `process.mainModule.require` | Node.js RCE | WAF / ALB Logs |
| `child_process` | Command execution | WAF / ALB Logs |
| `Go-http-client/1.1` | Primary scanner UA | WAF / ALB Logs |

### MITRE ATT&CK Techniques

| Technique | Name | React2Shell Usage |
|-----------|------|-------------------|
| T1190 | Exploit Public-Facing Application | Initial exploitation via RSC |
| T1059.007 | JavaScript | Node.js command execution |
| T1105 | Ingress Tool Transfer | Download secondary payloads |
| T1552.001 | Credentials In Files | .env file harvesting |
| T1021 | Remote Services | SSM/SSH lateral movement |
| T1078 | Valid Accounts | Use stolen credentials |
| T1496 | Resource Hijacking | Cryptominer deployment |

---

## Verification & Testing

### Verify GuardDuty

```bash
# Check detector status
aws guardduty list-detectors

# Check ThreatIntelSet
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty list-threat-intel-sets --detector-id $DETECTOR_ID

# Check for recent findings
aws guardduty list-findings --detector-id $DETECTOR_ID --max-results 10
```

### Verify EventBridge Rules

```bash
# List rules
aws events list-rules --name-prefix "React2Shell"

# Check rule targets
aws events list-targets-by-rule --rule "React2Shell-ThreatIntelSet-Match"
```

### Test SNS Notification

```bash
# Send test message
aws sns publish \
  --topic-arn $TOPIC_ARN \
  --subject "[TEST] React2Shell Detection System" \
  --message "This is a test notification from the React2Shell detection system."
```

### Generate Test Finding (GuardDuty Sample)

```bash
# Generate sample findings
aws guardduty create-sample-findings \
  --detector-id $DETECTOR_ID \
  --finding-types "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom"
```

---

## Troubleshooting

### No Findings Generated

1. Verify GuardDuty is enabled:
   ```bash
   aws guardduty get-detector --detector-id $DETECTOR_ID
   ```

2. Check ThreatIntelSet status:
   ```bash
   aws guardduty get-threat-intel-set \
     --detector-id $DETECTOR_ID \
     --threat-intel-set-id <set-id>
   ```

3. Verify S3 bucket permissions for ThreatIntelSet

### EventBridge Not Triggering

1. Check rule is enabled:
   ```bash
   aws events describe-rule --name "React2Shell-ThreatIntelSet-Match"
   ```

2. Verify event pattern syntax in console

3. Check CloudWatch Logs for EventBridge:
   ```bash
   aws logs filter-log-events \
     --log-group-name /aws/events/react2shell
   ```

### SNS Not Sending

1. Verify subscription is confirmed
2. Check SNS topic policy allows EventBridge
3. Test direct publish to topic

### Lambda Errors

1. Check CloudWatch Logs:
   ```bash
   aws logs tail /aws/lambda/React2Shell-GuardDuty-Enricher --follow
   ```

2. Verify Lambda role has required permissions
3. Check environment variables are set

---

## Multi-Account Deployment (AWS Organizations)

For organization-wide deployment:

1. **Designate GuardDuty Administrator Account**
   ```bash
   aws guardduty enable-organization-admin-account \
     --admin-account-id <admin-account-id>
   ```

2. **Enable Auto-Enable for New Accounts**
   ```bash
   aws guardduty update-organization-configuration \
     --detector-id $DETECTOR_ID \
     --auto-enable
   ```

3. **Create ThreatIntelSet in Administrator Account**
   - ThreatIntelSets are shared across member accounts

4. **Deploy EventBridge Rules via CloudFormation StackSets**
   - Use StackSets to deploy EventBridge rules to all accounts

---

## References

- [AWS GuardDuty Documentation](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html)
- [EventBridge Event Patterns](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html)
- [GuardDuty Finding Types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html)
- [React2Shell Official Site](https://react2shell.com/)
- [Datadog IOC Repository](https://github.com/DataDog/indicators-of-compromise/tree/main/react-CVE-2025-55182)

---

*Document Version: 1.0*
*Last Updated: 2025-12-06*
*Classification: TLP:WHITE*
