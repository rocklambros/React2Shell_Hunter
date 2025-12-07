# Terraform configuration for AWS WAF React2Shell protection rules
# CVE-2025-55182 & CVE-2025-66478

variable "waf_scope" {
  description = "WAF scope (REGIONAL or CLOUDFRONT)"
  type        = string
  default     = "REGIONAL"
}

variable "enable_waf" {
  description = "Enable WAF WebACL creation"
  type        = bool
  default     = true
}

variable "block_mode" {
  description = "Block or count matching requests"
  type        = string
  default     = "BLOCK"
  validation {
    condition     = contains(["BLOCK", "COUNT"], var.block_mode)
    error_message = "block_mode must be either BLOCK or COUNT"
  }
}

variable "rate_limit" {
  description = "Rate limit for suspicious requests per 5 minutes"
  type        = number
  default     = 100
}

locals {
  action = var.block_mode == "BLOCK" ? { block = {} } : { count = {} }
}

# Regex Pattern Set for React2Shell payload patterns
resource "aws_wafv2_regex_pattern_set" "react2shell_patterns" {
  count = var.enable_waf ? 1 : 0

  name        = "React2Shell-Payload-Patterns"
  description = "Regex patterns for React2Shell exploitation attempts"
  scope       = var.waf_scope

  regular_expression {
    regex_string = "process\\.mainModule\\.require"
  }

  regular_expression {
    regex_string = "child_process"
  }

  regular_expression {
    regex_string = "execSync"
  }

  regular_expression {
    regex_string = "spawnSync"
  }

  regular_expression {
    regex_string = "\\$1:__proto__"
  }

  regular_expression {
    regex_string = "__proto__:then"
  }

  regular_expression {
    regex_string = "resolved_model"
  }

  tags = var.tags
}

# IP Set for known malicious IPs
resource "aws_wafv2_ip_set" "react2shell_ips" {
  count = var.enable_waf ? 1 : 0

  name               = "React2Shell-Malicious-IPs"
  description        = "Known React2Shell C2 and scanner IPs"
  scope              = var.waf_scope
  ip_address_version = "IPV4"

  addresses = [
    "93.123.109.247/32",
    "45.77.33.136/32",
    "194.246.84.13/32",
    "45.32.158.54/32",
    "46.36.37.85/32",
    "144.202.115.234/32",
    "141.11.240.103/32",
    "23.235.188.3/32",
    "162.215.170.26/32"
  ]

  tags = var.tags
}

# WAF WebACL with React2Shell protection rules
resource "aws_wafv2_web_acl" "react2shell_protection" {
  count = var.enable_waf ? 1 : 0

  name        = "React2Shell-Protection-WebACL"
  description = "WAF rules to detect and block React2Shell exploitation (CVE-2025-55182, CVE-2025-66478)"
  scope       = var.waf_scope

  default_action {
    allow {}
  }

  # Rule 1: Block known malicious IPs
  rule {
    name     = "React2Shell-Block-Malicious-IPs"
    priority = 1

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.react2shell_ips[0].arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "React2Shell-Malicious-IP-Blocked"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2: Block Next-Action header (RSC exploitation)
  rule {
    name     = "React2Shell-NextAction-Header"
    priority = 2

    action {
      block {}
    }

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

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "React2Shell-NextAction-Header"
      sampled_requests_enabled   = true
    }
  }

  # Rule 3: Block RSC-Action-ID header
  rule {
    name     = "React2Shell-RSCActionID-Header"
    priority = 3

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            field_to_match {
              single_header {
                name = "rsc-action-id"
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
                name = "rsc-action-id"
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

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "React2Shell-RSCActionID-Header"
      sampled_requests_enabled   = true
    }
  }

  # Rule 4: Block prototype pollution attempts
  rule {
    name     = "React2Shell-Prototype-Pollution"
    priority = 4

    action {
      block {}
    }

    statement {
      or_statement {
        statement {
          byte_match_statement {
            field_to_match {
              body {
                oversize_handling = "CONTINUE"
              }
            }
            positional_constraint = "CONTAINS"
            search_string         = "__proto__"
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
            text_transformation {
              priority = 1
              type     = "LOWERCASE"
            }
          }
        }
        statement {
          byte_match_statement {
            field_to_match {
              body {
                oversize_handling = "CONTINUE"
              }
            }
            positional_constraint = "CONTAINS"
            search_string         = "constructor.prototype"
            text_transformation {
              priority = 0
              type     = "URL_DECODE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "React2Shell-Prototype-Pollution"
      sampled_requests_enabled   = true
    }
  }

  # Rule 5: Block RCE payload patterns
  rule {
    name     = "React2Shell-RCE-Patterns"
    priority = 5

    action {
      block {}
    }

    statement {
      regex_pattern_set_reference_statement {
        arn = aws_wafv2_regex_pattern_set.react2shell_patterns[0].arn
        field_to_match {
          body {
            oversize_handling = "CONTINUE"
          }
        }
        text_transformation {
          priority = 0
          type     = "URL_DECODE"
        }
        text_transformation {
          priority = 1
          type     = "JS_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "React2Shell-RCE-Patterns"
      sampled_requests_enabled   = true
    }
  }

  # Rule 6: Block ACTION parameter exploitation
  rule {
    name     = "React2Shell-ACTION-Parameter"
    priority = 6

    action {
      block {}
    }

    statement {
      and_statement {
        statement {
          byte_match_statement {
            field_to_match {
              method {}
            }
            positional_constraint = "EXACTLY"
            search_string         = "POST"
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
        statement {
          or_statement {
            statement {
              byte_match_statement {
                field_to_match {
                  body {
                    oversize_handling = "CONTINUE"
                  }
                }
                positional_constraint = "CONTAINS"
                search_string         = "$ACTION_0:0"
                text_transformation {
                  priority = 0
                  type     = "URL_DECODE"
                }
              }
            }
            statement {
              byte_match_statement {
                field_to_match {
                  body {
                    oversize_handling = "CONTINUE"
                  }
                }
                positional_constraint = "CONTAINS"
                search_string         = "$ACTION_REF"
                text_transformation {
                  priority = 0
                  type     = "URL_DECODE"
                }
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "React2Shell-ACTION-Parameter"
      sampled_requests_enabled   = true
    }
  }

  # Rule 7: Rate limit suspicious User-Agents (Count only - may have false positives)
  rule {
    name     = "React2Shell-Suspicious-UserAgents"
    priority = 7

    action {
      count {}
    }

    statement {
      rate_based_statement {
        limit              = var.rate_limit
        aggregate_key_type = "IP"

        scope_down_statement {
          or_statement {
            statement {
              byte_match_statement {
                field_to_match {
                  single_header {
                    name = "user-agent"
                  }
                }
                positional_constraint = "STARTS_WITH"
                search_string         = "Go-http-client"
                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }
            statement {
              byte_match_statement {
                field_to_match {
                  single_header {
                    name = "user-agent"
                  }
                }
                positional_constraint = "CONTAINS"
                search_string         = "Assetnote"
                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }
            statement {
              byte_match_statement {
                field_to_match {
                  single_header {
                    name = "user-agent"
                  }
                }
                positional_constraint = "CONTAINS"
                search_string         = "python-requests"
                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "React2Shell-Suspicious-UserAgents"
      sampled_requests_enabled   = true
    }
  }

  # Rule 8: Use AWS Managed Rules - Known Bad Inputs
  rule {
    name     = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
    priority = 8

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWS-KnownBadInputs"
      sampled_requests_enabled   = true
    }
  }

  # Rule 9: Use AWS Managed Rules - Common Rule Set
  rule {
    name     = "AWS-AWSManagedRulesCommonRuleSet"
    priority = 9

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWS-CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "React2Shell-Protection-WebACL"
    sampled_requests_enabled   = true
  }

  tags = var.tags
}

# CloudWatch Log Group for WAF logs
resource "aws_cloudwatch_log_group" "waf_logs" {
  count = var.enable_waf ? 1 : 0

  name              = "aws-waf-logs-react2shell"
  retention_in_days = 90

  tags = var.tags
}

# WAF Logging Configuration
resource "aws_wafv2_web_acl_logging_configuration" "react2shell" {
  count = var.enable_waf ? 1 : 0

  log_destination_configs = [aws_cloudwatch_log_group.waf_logs[0].arn]
  resource_arn            = aws_wafv2_web_acl.react2shell_protection[0].arn

  logging_filter {
    default_behavior = "KEEP"

    filter {
      behavior = "KEEP"

      condition {
        action_condition {
          action = "BLOCK"
        }
      }

      condition {
        action_condition {
          action = "COUNT"
        }
      }

      requirement = "MEETS_ANY"
    }
  }

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }
}

# CloudWatch Dashboard for WAF monitoring
resource "aws_cloudwatch_dashboard" "react2shell_waf" {
  count = var.enable_waf ? 1 : 0

  dashboard_name = "React2Shell-WAF-Monitoring"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/WAFV2", "BlockedRequests", "WebACL", "React2Shell-Protection-WebACL", "Region", data.aws_region.current.name, "Rule", "React2Shell-Block-Malicious-IPs"],
            [".", ".", ".", ".", ".", ".", ".", "React2Shell-NextAction-Header"],
            [".", ".", ".", ".", ".", ".", ".", "React2Shell-Prototype-Pollution"],
            [".", ".", ".", ".", ".", ".", ".", "React2Shell-RCE-Patterns"],
            [".", ".", ".", ".", ".", ".", ".", "React2Shell-ACTION-Parameter"]
          ]
          title  = "React2Shell Blocked Requests by Rule"
          period = 300
          stat   = "Sum"
          region = data.aws_region.current.name
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/WAFV2", "CountedRequests", "WebACL", "React2Shell-Protection-WebACL", "Region", data.aws_region.current.name, "Rule", "React2Shell-Suspicious-UserAgents"]
          ]
          title  = "Suspicious User-Agent Requests (Counted)"
          period = 300
          stat   = "Sum"
          region = data.aws_region.current.name
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 24
        height = 6
        properties = {
          metrics = [
            ["AWS/WAFV2", "AllowedRequests", "WebACL", "React2Shell-Protection-WebACL", "Region", data.aws_region.current.name],
            [".", "BlockedRequests", ".", ".", ".", "."]
          ]
          title  = "Total Allowed vs Blocked Requests"
          period = 300
          stat   = "Sum"
          region = data.aws_region.current.name
        }
      }
    ]
  })
}

# CloudWatch Alarm for high block rate
resource "aws_cloudwatch_metric_alarm" "react2shell_high_blocks" {
  count = var.enable_waf ? 1 : 0

  alarm_name          = "React2Shell-High-Block-Rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  alarm_description   = "High number of React2Shell exploitation attempts blocked"

  dimensions = {
    WebACL = "React2Shell-Protection-WebACL"
    Region = data.aws_region.current.name
    Rule   = "ALL"
  }

  alarm_actions = [aws_sns_topic.guardduty_alerts.arn]

  tags = var.tags
}

# Outputs
output "web_acl_arn" {
  description = "ARN of the React2Shell protection WebACL"
  value       = var.enable_waf ? aws_wafv2_web_acl.react2shell_protection[0].arn : null
}

output "web_acl_id" {
  description = "ID of the React2Shell protection WebACL"
  value       = var.enable_waf ? aws_wafv2_web_acl.react2shell_protection[0].id : null
}

output "ip_set_arn" {
  description = "ARN of the malicious IP set"
  value       = var.enable_waf ? aws_wafv2_ip_set.react2shell_ips[0].arn : null
}

output "waf_log_group" {
  description = "CloudWatch Log Group for WAF logs"
  value       = var.enable_waf ? aws_cloudwatch_log_group.waf_logs[0].name : null
}

output "dashboard_name" {
  description = "CloudWatch Dashboard name"
  value       = var.enable_waf ? aws_cloudwatch_dashboard.react2shell_waf[0].dashboard_name : null
}
