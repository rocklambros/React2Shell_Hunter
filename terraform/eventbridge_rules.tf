# EventBridge Rules for React2Shell GuardDuty Finding Detection
# CVE-2025-55182 & CVE-2025-66478
#
# ARCHITECTURE:
# GuardDuty generates findings → EventBridge filters by pattern → Routes to targets
#
# This is the correct approach - GuardDuty doesn't support custom detection rules,
# but it DOES support:
# 1. ThreatIntelSets (custom IP lists that generate findings when matched)
# 2. EventBridge integration for filtering and routing findings

# ============================================================================
# EVENTBRIDGE RULE 1: ThreatIntelSet Matches (React2Shell C2 IPs)
# ============================================================================
# When GuardDuty detects traffic to/from IPs in our ThreatIntelSet,
# it generates "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom" findings

resource "aws_cloudwatch_event_rule" "react2shell_malicious_ip" {
  count = var.enable_guardduty ? 1 : 0

  name        = "react2shell-malicious-ip-caller"
  description = "Detect connections to React2Shell C2 IPs via GuardDuty ThreatIntelSet"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
        "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom"
      ]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "react2shell_malicious_ip_sns" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.react2shell_malicious_ip[0].name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_alerts.arn

  input_transformer {
    input_paths = {
      severity      = "$.detail.severity"
      type          = "$.detail.type"
      title         = "$.detail.title"
      description   = "$.detail.description"
      account       = "$.detail.accountId"
      region        = "$.detail.region"
      instanceId    = "$.detail.resource.instanceDetails.instanceId"
      remoteIp      = "$.detail.service.action.networkConnectionAction.remoteIpDetails.ipAddressV4"
      remoteCountry = "$.detail.service.action.networkConnectionAction.remoteIpDetails.country.countryName"
    }
    input_template = <<-EOT
      {
        "alert": "CRITICAL: React2Shell C2 Communication Detected",
        "cve": "CVE-2025-55182 / CVE-2025-66478",
        "severity": <severity>,
        "finding_type": <type>,
        "title": <title>,
        "description": <description>,
        "account": <account>,
        "region": <region>,
        "instance_id": <instanceId>,
        "remote_ip": <remoteIp>,
        "remote_country": <remoteCountry>,
        "action_required": "IMMEDIATE: Isolate instance, rotate credentials, investigate for compromise"
      }
    EOT
  }
}

# ============================================================================
# EVENTBRIDGE RULE 2: Credential Exfiltration
# ============================================================================
# Detects stolen EC2 instance credentials being used outside AWS or in other accounts

resource "aws_cloudwatch_event_rule" "react2shell_credential_exfil" {
  count = var.enable_guardduty ? 1 : 0

  name        = "react2shell-credential-exfiltration"
  description = "Detect EC2 credential theft - key React2Shell post-exploitation indicator"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS"
      ]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "react2shell_credential_exfil_sns" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.react2shell_credential_exfil[0].name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_alerts.arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      type        = "$.detail.type"
      title       = "$.detail.title"
      description = "$.detail.description"
      account     = "$.detail.accountId"
      region      = "$.detail.region"
      principal   = "$.detail.resource.accessKeyDetails.principalId"
      userName    = "$.detail.resource.accessKeyDetails.userName"
    }
    input_template = <<-EOT
      {
        "alert": "CRITICAL: EC2 Instance Credential Exfiltration",
        "cve": "CVE-2025-55182 / CVE-2025-66478",
        "severity": <severity>,
        "finding_type": <type>,
        "title": <title>,
        "description": <description>,
        "account": <account>,
        "region": <region>,
        "principal": <principal>,
        "user_name": <userName>,
        "action_required": "CRITICAL: Credentials stolen! Revoke instance role, rotate secrets, investigate full attack chain"
      }
    EOT
  }
}

# ============================================================================
# EVENTBRIDGE RULE 3: DNS Data Exfiltration
# ============================================================================
# Detects DNS-based data exfiltration to services like ceye.io, dnslog.cn

resource "aws_cloudwatch_event_rule" "react2shell_dns_exfil" {
  count = var.enable_guardduty ? 1 : 0

  name        = "react2shell-dns-exfiltration"
  description = "Detect DNS exfiltration - React2Shell uses ceye.io/dnslog.cn for data theft"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "Trojan:EC2/DNSDataExfiltration",
        "Trojan:Runtime/DNSDataExfiltration"
      ]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "react2shell_dns_exfil_sns" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.react2shell_dns_exfil[0].name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_alerts.arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      type        = "$.detail.type"
      title       = "$.detail.title"
      description = "$.detail.description"
      account     = "$.detail.accountId"
      region      = "$.detail.region"
      instanceId  = "$.detail.resource.instanceDetails.instanceId"
      domain      = "$.detail.service.action.dnsRequestAction.domain"
    }
    input_template = <<-EOT
      {
        "alert": "HIGH: DNS Data Exfiltration Detected",
        "cve": "CVE-2025-55182 / CVE-2025-66478",
        "severity": <severity>,
        "finding_type": <type>,
        "title": <title>,
        "description": <description>,
        "account": <account>,
        "region": <region>,
        "instance_id": <instanceId>,
        "suspicious_domain": <domain>,
        "action_required": "Investigate instance for React2Shell compromise, check for .env file access"
      }
    EOT
  }
}

# ============================================================================
# EVENTBRIDGE RULE 4: Cryptocurrency Mining
# ============================================================================
# Detects cryptominer deployment - common React2Shell post-exploitation activity

resource "aws_cloudwatch_event_rule" "react2shell_crypto" {
  count = var.enable_guardduty ? 1 : 0

  name        = "react2shell-cryptocurrency-mining"
  description = "Detect cryptomining - React2Shell deploys XMRig/C3Pool miners"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "CryptoCurrency:EC2/" },
        { prefix = "CryptoCurrency:Runtime/" }
      ]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "react2shell_crypto_sns" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.react2shell_crypto[0].name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_alerts.arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      type        = "$.detail.type"
      title       = "$.detail.title"
      description = "$.detail.description"
      account     = "$.detail.accountId"
      region      = "$.detail.region"
      instanceId  = "$.detail.resource.instanceDetails.instanceId"
    }
    input_template = <<-EOT
      {
        "alert": "HIGH: Cryptocurrency Mining Detected",
        "cve": "CVE-2025-55182 / CVE-2025-66478",
        "severity": <severity>,
        "finding_type": <type>,
        "title": <title>,
        "description": <description>,
        "account": <account>,
        "region": <region>,
        "instance_id": <instanceId>,
        "action_required": "Instance likely compromised via React2Shell. Terminate miner, investigate attack chain"
      }
    EOT
  }
}

# ============================================================================
# EVENTBRIDGE RULE 5: Unusual Network Ports
# ============================================================================
# Detects connections to unusual ports (652, 2045, 12000, 45178) used by React2Shell C2

resource "aws_cloudwatch_event_rule" "react2shell_unusual_ports" {
  count = var.enable_guardduty ? 1 : 0

  name        = "react2shell-unusual-network-ports"
  description = "Detect unusual port usage - React2Shell uses ports 652, 2045, 12000, 45178"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "Behavior:EC2/NetworkPortUnusual"
      ]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "react2shell_unusual_ports_sns" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.react2shell_unusual_ports[0].name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_alerts.arn

  input_transformer {
    input_paths = {
      severity   = "$.detail.severity"
      type       = "$.detail.type"
      title      = "$.detail.title"
      account    = "$.detail.accountId"
      region     = "$.detail.region"
      instanceId = "$.detail.resource.instanceDetails.instanceId"
      localPort  = "$.detail.service.action.networkConnectionAction.localPortDetails.port"
      remotePort = "$.detail.service.action.networkConnectionAction.remotePortDetails.port"
    }
    input_template = <<-EOT
      {
        "alert": "MEDIUM: Unusual Network Port Activity",
        "cve": "CVE-2025-55182 / CVE-2025-66478",
        "severity": <severity>,
        "finding_type": <type>,
        "title": <title>,
        "account": <account>,
        "region": <region>,
        "instance_id": <instanceId>,
        "local_port": <localPort>,
        "remote_port": <remotePort>,
        "react2shell_c2_ports": "652, 2045, 8000, 8080, 12000, 45178",
        "action_required": "Check if port matches React2Shell C2 ports, investigate connection"
      }
    EOT
  }
}

# ============================================================================
# EVENTBRIDGE RULE 6: Malicious Domain Requests
# ============================================================================
# Detects connections to malicious domains (sapo.shk0x.net, etc.)

resource "aws_cloudwatch_event_rule" "react2shell_malicious_domain" {
  count = var.enable_guardduty ? 1 : 0

  name        = "react2shell-malicious-domain"
  description = "Detect malicious domain requests - React2Shell C2 domains"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "Impact:EC2/MaliciousDomainRequest.Reputation",
        "Trojan:EC2/DriveBySourceTraffic!DNS"
      ]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "react2shell_malicious_domain_sns" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.react2shell_malicious_domain[0].name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.guardduty_alerts.arn

  input_transformer {
    input_paths = {
      severity   = "$.detail.severity"
      type       = "$.detail.type"
      title      = "$.detail.title"
      account    = "$.detail.accountId"
      region     = "$.detail.region"
      instanceId = "$.detail.resource.instanceDetails.instanceId"
      domain     = "$.detail.service.action.dnsRequestAction.domain"
    }
    input_template = <<-EOT
      {
        "alert": "HIGH: Malicious Domain Request",
        "cve": "CVE-2025-55182 / CVE-2025-66478",
        "severity": <severity>,
        "finding_type": <type>,
        "title": <title>,
        "account": <account>,
        "region": <region>,
        "instance_id": <instanceId>,
        "domain": <domain>,
        "react2shell_domains": "sapo.shk0x.net, xwpoogfunv.zaza.eu.org, ceye.io, dnslog.cn",
        "action_required": "Check if domain matches React2Shell C2, investigate for compromise"
      }
    EOT
  }
}

# ============================================================================
# EVENTBRIDGE RULE 7: All High/Critical Severity Findings (Catch-All)
# ============================================================================
# Catch-all for any high severity findings that might indicate React2Shell activity

resource "aws_cloudwatch_event_rule" "react2shell_high_severity" {
  count = var.enable_guardduty ? 1 : 0

  name        = "react2shell-high-severity-catchall"
  description = "Catch-all for high/critical severity GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [
        { numeric = [">=", 7] }
      ]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "react2shell_high_severity_logs" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.react2shell_high_severity[0].name
  target_id = "SendToCloudWatchLogs"
  arn       = aws_cloudwatch_log_group.guardduty_findings.arn
}

# ============================================================================
# LAMBDA INTEGRATION (Optional - for automated response)
# ============================================================================

# IAM Role for Lambda automation
resource "aws_iam_role" "guardduty_automation" {
  count = var.enable_guardduty && var.enable_lambda_automation ? 1 : 0

  name = "react2shell-guardduty-automation"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "guardduty_automation" {
  count = var.enable_guardduty && var.enable_lambda_automation ? 1 : 0

  name = "react2shell-guardduty-automation"
  role = aws_iam_role.guardduty_automation[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:ModifyInstanceAttribute",
          "ec2:CreateSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.guardduty_alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "securityhub:BatchImportFindings"
        ]
        Resource = "*"
      }
    ]
  })
}

# Lambda function target (if Lambda exists)
resource "aws_cloudwatch_event_target" "react2shell_lambda" {
  count = var.enable_guardduty && var.enable_lambda_automation ? 1 : 0

  rule      = aws_cloudwatch_event_rule.react2shell_malicious_ip[0].name
  target_id = "SendToLambda"
  arn       = var.lambda_automation_arn

  depends_on = [aws_cloudwatch_event_rule.react2shell_malicious_ip]
}

# ============================================================================
# VARIABLES
# ============================================================================

variable "enable_lambda_automation" {
  description = "Enable Lambda automation for GuardDuty findings"
  type        = bool
  default     = false
}

variable "lambda_automation_arn" {
  description = "ARN of Lambda function for automated response"
  type        = string
  default     = ""
}

# ============================================================================
# OUTPUTS
# ============================================================================

output "eventbridge_rule_malicious_ip" {
  description = "EventBridge rule for malicious IP detection"
  value       = var.enable_guardduty ? aws_cloudwatch_event_rule.react2shell_malicious_ip[0].name : null
}

output "eventbridge_rule_credential_exfil" {
  description = "EventBridge rule for credential exfiltration"
  value       = var.enable_guardduty ? aws_cloudwatch_event_rule.react2shell_credential_exfil[0].name : null
}

output "eventbridge_rule_dns_exfil" {
  description = "EventBridge rule for DNS exfiltration"
  value       = var.enable_guardduty ? aws_cloudwatch_event_rule.react2shell_dns_exfil[0].name : null
}

output "eventbridge_rule_crypto" {
  description = "EventBridge rule for cryptocurrency mining"
  value       = var.enable_guardduty ? aws_cloudwatch_event_rule.react2shell_crypto[0].name : null
}
