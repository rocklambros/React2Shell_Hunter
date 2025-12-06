# Terraform configuration for GuardDuty React2Shell detection
# CVE-2025-55182 & CVE-2025-66478

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "enable_guardduty" {
  description = "Enable GuardDuty detector"
  type        = bool
  default     = true
}

variable "threat_intel_bucket" {
  description = "S3 bucket for threat intelligence files"
  type        = string
}

variable "enable_s3_protection" {
  description = "Enable GuardDuty S3 protection"
  type        = bool
  default     = true
}

variable "enable_kubernetes_protection" {
  description = "Enable GuardDuty Kubernetes protection"
  type        = bool
  default     = true
}

variable "enable_malware_protection" {
  description = "Enable GuardDuty Malware protection"
  type        = bool
  default     = true
}

variable "enable_rds_protection" {
  description = "Enable GuardDuty RDS protection"
  type        = bool
  default     = true
}

variable "enable_runtime_monitoring" {
  description = "Enable GuardDuty Runtime Monitoring"
  type        = bool
  default     = true
}

variable "finding_publishing_frequency" {
  description = "Frequency of findings publication"
  type        = string
  default     = "FIFTEEN_MINUTES"
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default = {
    Purpose     = "React2Shell-Detection"
    CVE         = "CVE-2025-55182,CVE-2025-66478"
    ManagedBy   = "Terraform"
  }
}

# Data source for current account
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# GuardDuty Detector
resource "aws_guardduty_detector" "main" {
  count = var.enable_guardduty ? 1 : 0

  enable                       = true
  finding_publishing_frequency = var.finding_publishing_frequency

  datasources {
    s3_logs {
      enable = var.enable_s3_protection
    }
    kubernetes {
      audit_logs {
        enable = var.enable_kubernetes_protection
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = var.enable_malware_protection
        }
      }
    }
  }

  tags = var.tags
}

# S3 bucket for threat intelligence
resource "aws_s3_bucket" "threat_intel" {
  bucket = var.threat_intel_bucket

  tags = merge(var.tags, {
    Name = "React2Shell Threat Intelligence"
  })
}

resource "aws_s3_bucket_versioning" "threat_intel" {
  bucket = aws_s3_bucket.threat_intel.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "threat_intel" {
  bucket = aws_s3_bucket.threat_intel.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "threat_intel" {
  bucket = aws_s3_bucket.threat_intel.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# React2Shell malicious IPs threat intelligence file
resource "aws_s3_object" "react2shell_ips" {
  bucket  = aws_s3_bucket.threat_intel.id
  key     = "threat-intel/react2shell-ips.txt"
  content = <<-EOT
# React2Shell (CVE-2025-55182 & CVE-2025-66478) Malicious IPs
# Last Updated: 2025-12-06
# Source: Datadog Security Labs, GreyNoise, AWS Threat Intelligence

# C2 Infrastructure
93.123.109.247
45.77.33.136
194.246.84.13
45.32.158.54
46.36.37.85
144.202.115.234
141.11.240.103
23.235.188.3
162.215.170.26
EOT

  content_type = "text/plain"

  tags = var.tags
}

# GuardDuty ThreatIntelSet for React2Shell IPs
resource "aws_guardduty_threatintelset" "react2shell" {
  count = var.enable_guardduty ? 1 : 0

  activate    = true
  detector_id = aws_guardduty_detector.main[0].id
  format      = "TXT"
  location    = "s3://${aws_s3_bucket.threat_intel.id}/${aws_s3_object.react2shell_ips.key}"
  name        = "React2Shell-CVE-2025-55182-ThreatIntelSet"

  tags = var.tags

  depends_on = [aws_s3_object.react2shell_ips]
}

# IAM role for GuardDuty to access S3
resource "aws_iam_role" "guardduty_s3_access" {
  count = var.enable_guardduty ? 1 : 0

  name = "GuardDutyThreatIntelS3Access"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "guardduty_s3_access" {
  count = var.enable_guardduty ? 1 : 0

  name = "GuardDutyThreatIntelS3Access"
  role = aws_iam_role.guardduty_s3_access[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.threat_intel.arn,
          "${aws_s3_bucket.threat_intel.arn}/*"
        ]
      }
    ]
  })
}

# S3 bucket policy for GuardDuty access
resource "aws_s3_bucket_policy" "threat_intel" {
  bucket = aws_s3_bucket.threat_intel.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGuardDutyAccess"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.threat_intel.arn,
          "${aws_s3_bucket.threat_intel.arn}/*"
        ]
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# SNS Topic for GuardDuty findings
resource "aws_sns_topic" "guardduty_alerts" {
  name = "react2shell-guardduty-alerts"

  tags = var.tags
}

resource "aws_sns_topic_policy" "guardduty_alerts" {
  arn = aws_sns_topic.guardduty_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgePublish"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.guardduty_alerts.arn
      }
    ]
  })
}

# EventBridge rule for React2Shell related GuardDuty findings
resource "aws_cloudwatch_event_rule" "react2shell_findings" {
  count = var.enable_guardduty ? 1 : 0

  name        = "react2shell-guardduty-findings"
  description = "Capture GuardDuty findings related to React2Shell exploitation"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [
        { numeric = [">=", 7] }
      ]
      type = [
        { prefix = "UnauthorizedAccess:" },
        { prefix = "CryptoCurrency:" },
        { prefix = "Trojan:" },
        { prefix = "Behavior:EC2/NetworkPortUnusual" },
        { prefix = "Impact:" }
      ]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "react2shell_sns" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.react2shell_findings[0].name
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
    }
    input_template = <<-EOT
      {
        "alert": "React2Shell Detection Alert",
        "cve": "CVE-2025-55182 / CVE-2025-66478",
        "severity": <severity>,
        "type": <type>,
        "title": <title>,
        "description": <description>,
        "account": <account>,
        "region": <region>,
        "action": "Investigate immediately for potential React2Shell exploitation"
      }
    EOT
  }
}

# CloudWatch Log Group for GuardDuty findings
resource "aws_cloudwatch_log_group" "guardduty_findings" {
  name              = "/aws/guardduty/react2shell-findings"
  retention_in_days = 90

  tags = var.tags
}

# EventBridge rule to log all high-severity findings
resource "aws_cloudwatch_event_target" "react2shell_logs" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.react2shell_findings[0].name
  target_id = "SendToCloudWatch"
  arn       = aws_cloudwatch_log_group.guardduty_findings.arn
}

resource "aws_cloudwatch_log_resource_policy" "guardduty_findings" {
  policy_name = "react2shell-guardduty-log-policy"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.guardduty_findings.arn}:*"
      }
    ]
  })
}

# Outputs
output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = var.enable_guardduty ? aws_guardduty_detector.main[0].id : null
}

output "threat_intel_set_id" {
  description = "GuardDuty ThreatIntelSet ID for React2Shell"
  value       = var.enable_guardduty ? aws_guardduty_threatintelset.react2shell[0].id : null
}

output "threat_intel_bucket" {
  description = "S3 bucket for threat intelligence"
  value       = aws_s3_bucket.threat_intel.id
}

output "sns_topic_arn" {
  description = "SNS topic ARN for GuardDuty alerts"
  value       = aws_sns_topic.guardduty_alerts.arn
}

output "cloudwatch_log_group" {
  description = "CloudWatch Log Group for findings"
  value       = aws_cloudwatch_log_group.guardduty_findings.name
}
