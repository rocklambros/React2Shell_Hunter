"""
React2Shell Real-Time IOC Scanner Lambda
CVE-2025-55182 & CVE-2025-66478

This Lambda function processes CloudTrail events in real-time via EventBridge
to detect React2Shell exploitation attempts.

Triggers:
- EventBridge rule for CloudTrail events
- Can also be invoked manually for testing

Environment Variables:
- SNS_TOPIC_ARN: SNS topic for alerts
- SECURITY_HUB_ENABLED: Enable Security Hub integration (true/false)
- MALICIOUS_IPS: Comma-separated list of malicious IPs (optional, uses defaults)
"""

import json
import logging
import os
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Set
import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
sns = boto3.client('sns')
securityhub = boto3.client('securityhub')

# Default malicious IPs
DEFAULT_MALICIOUS_IPS = {
    '93.123.109.247',
    '45.77.33.136',
    '194.246.84.13',
    '45.32.158.54',
    '46.36.37.85',
    '144.202.115.234',
    '141.11.240.103',
    '23.235.188.3',
    '162.215.170.26'
}

# Suspicious API calls
SUSPICIOUS_APIS = {
    'credential_theft': [
        'GetCallerIdentity',
        'GetSessionToken',
        'AssumeRole',
    ],
    'lateral_movement': [
        'SendCommand',
        'StartSession',
        'RunInstances',
    ],
    'privilege_escalation': [
        'CreateAccessKey',
        'AttachUserPolicy',
        'AttachRolePolicy',
        'PutRolePolicy',
    ],
    'exfiltration': [
        'GetSecretValue',
        'BatchGetSecretValue',
    ]
}


def get_malicious_ips() -> Set[str]:
    """Get malicious IPs from environment or use defaults"""
    env_ips = os.environ.get('MALICIOUS_IPS', '')
    if env_ips:
        return set(env_ips.split(','))
    return DEFAULT_MALICIOUS_IPS


def analyze_cloudtrail_event(event: Dict) -> Optional[Dict]:
    """
    Analyze a CloudTrail event for React2Shell IOCs

    Returns finding dict if IOC detected, None otherwise
    """
    malicious_ips = get_malicious_ips()

    source_ip = event.get('sourceIPAddress', '')
    event_name = event.get('eventName', '')
    user_identity = event.get('userIdentity', {})
    user_arn = user_identity.get('arn', '')
    account_id = event.get('recipientAccountId', '')
    region = event.get('awsRegion', '')
    event_time = event.get('eventTime', '')

    # Check for malicious source IP
    if source_ip in malicious_ips:
        return {
            'severity': 'CRITICAL',
            'title': 'React2Shell: API call from known C2 IP',
            'description': f'API call {event_name} detected from known React2Shell C2 IP: {source_ip}',
            'ioc_type': 'IP_ADDRESS',
            'ioc_value': source_ip,
            'mitre_technique': 'T1190',
            'account_id': account_id,
            'region': region,
            'resource_arn': user_arn,
            'event_time': event_time,
            'raw_event': event
        }

    # Check for suspicious API patterns from EC2 instances
    if user_identity.get('type') == 'AssumedRole' and 'i-' in user_arn:
        # Check each category of suspicious APIs
        for category, apis in SUSPICIOUS_APIS.items():
            if event_name in apis:
                severity = 'HIGH' if category != 'credential_theft' else 'MEDIUM'

                return {
                    'severity': severity,
                    'title': f'React2Shell: Suspicious {category} from EC2 instance',
                    'description': f'Suspicious API call {event_name} from EC2 instance role - potential post-exploitation activity',
                    'ioc_type': 'BEHAVIOR',
                    'ioc_value': f'{category}:{event_name}',
                    'mitre_technique': get_mitre_technique(category),
                    'account_id': account_id,
                    'region': region,
                    'resource_arn': user_arn,
                    'event_time': event_time,
                    'raw_event': event
                }

    return None


def get_mitre_technique(category: str) -> str:
    """Map category to MITRE ATT&CK technique"""
    mapping = {
        'credential_theft': 'T1552.001',
        'lateral_movement': 'T1021',
        'privilege_escalation': 'T1078',
        'exfiltration': 'T1537'
    }
    return mapping.get(category, 'T1190')


def generate_finding_id(finding: Dict) -> str:
    """Generate unique finding ID"""
    data = f"{finding['account_id']}-{finding['ioc_value']}-{finding['event_time']}"
    return hashlib.sha256(data.encode()).hexdigest()[:32]


def send_sns_alert(finding: Dict) -> bool:
    """Send alert to SNS topic"""
    topic_arn = os.environ.get('SNS_TOPIC_ARN')
    if not topic_arn:
        logger.warning("SNS_TOPIC_ARN not configured")
        return False

    try:
        message = {
            'alert': 'React2Shell IOC Detection',
            'cve': 'CVE-2025-55182 / CVE-2025-66478',
            'severity': finding['severity'],
            'title': finding['title'],
            'description': finding['description'],
            'ioc_type': finding['ioc_type'],
            'ioc_value': finding['ioc_value'],
            'mitre_technique': finding['mitre_technique'],
            'account': finding['account_id'],
            'region': finding['region'],
            'resource': finding['resource_arn'],
            'timestamp': finding['event_time'],
            'action_required': 'Investigate immediately for potential React2Shell exploitation'
        }

        sns.publish(
            TopicArn=topic_arn,
            Message=json.dumps(message, indent=2),
            Subject=f"[{finding['severity']}] React2Shell IOC: {finding['title']}",
            MessageAttributes={
                'severity': {
                    'DataType': 'String',
                    'StringValue': finding['severity']
                },
                'ioc_type': {
                    'DataType': 'String',
                    'StringValue': finding['ioc_type']
                }
            }
        )
        logger.info(f"SNS alert sent for finding: {finding['title']}")
        return True

    except ClientError as e:
        logger.error(f"Failed to send SNS alert: {e}")
        return False


def import_to_security_hub(finding: Dict) -> bool:
    """Import finding to AWS Security Hub"""
    if os.environ.get('SECURITY_HUB_ENABLED', 'false').lower() != 'true':
        return False

    finding_id = generate_finding_id(finding)
    account_id = finding['account_id']
    region = finding['region']

    severity_map = {
        'CRITICAL': 90,
        'HIGH': 70,
        'MEDIUM': 40,
        'LOW': 10
    }

    try:
        sh_finding = {
            'SchemaVersion': '2018-10-08',
            'Id': finding_id,
            'ProductArn': f'arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default',
            'GeneratorId': 'react2shell-ioc-scanner',
            'AwsAccountId': account_id,
            'Types': [
                'TTPs/Initial Access/T1190',
                'Software and Configuration Checks/Vulnerabilities/CVE'
            ],
            'CreatedAt': finding['event_time'],
            'UpdatedAt': datetime.utcnow().isoformat() + 'Z',
            'Severity': {
                'Label': finding['severity'],
                'Normalized': severity_map.get(finding['severity'], 50)
            },
            'Title': finding['title'],
            'Description': finding['description'],
            'Resources': [{
                'Type': 'AwsIamRole' if 'role' in finding['resource_arn'].lower() else 'Other',
                'Id': finding['resource_arn'],
                'Region': region
            }],
            'RecordState': 'ACTIVE',
            'ProductFields': {
                'ProviderName': 'React2Shell-IOC-Scanner',
                'ProviderVersion': '1.0.0',
                'IOCType': finding['ioc_type'],
                'IOCValue': finding['ioc_value'],
                'MITRETechnique': finding['mitre_technique'],
                'CVE': 'CVE-2025-55182,CVE-2025-66478'
            },
            'Vulnerabilities': [{
                'Id': 'CVE-2025-55182',
                'VulnerablePackages': [{
                    'Name': 'react-server-dom-webpack',
                    'Version': '19.0.0-19.2.0'
                }]
            }]
        }

        response = securityhub.batch_import_findings(Findings=[sh_finding])

        if response.get('SuccessCount', 0) > 0:
            logger.info(f"Finding imported to Security Hub: {finding_id}")
            return True
        else:
            logger.warning(f"Failed to import finding: {response.get('FailedFindings', [])}")
            return False

    except ClientError as e:
        logger.error(f"Security Hub import error: {e}")
        return False


def lambda_handler(event: Dict, context) -> Dict:
    """
    Main Lambda handler

    Processes CloudTrail events from EventBridge
    """
    logger.info(f"Processing event: {json.dumps(event)[:500]}...")

    findings = []
    processed = 0
    alerts_sent = 0

    # Handle EventBridge CloudTrail event
    if event.get('source') == 'aws.cloudtrail':
        detail = event.get('detail', {})
        finding = analyze_cloudtrail_event(detail)

        if finding:
            findings.append(finding)

            # Send alerts for critical/high findings
            if finding['severity'] in ['CRITICAL', 'HIGH']:
                if send_sns_alert(finding):
                    alerts_sent += 1

            # Import to Security Hub
            import_to_security_hub(finding)

        processed = 1

    # Handle batch processing (manual invocation with multiple events)
    elif 'Records' in event:
        for record in event['Records']:
            try:
                if record.get('eventSource') == 'aws:s3':
                    # Process S3 event (CloudTrail logs)
                    # This would require additional processing logic
                    pass
                else:
                    body = json.loads(record.get('body', '{}'))
                    finding = analyze_cloudtrail_event(body)

                    if finding:
                        findings.append(finding)
                        if finding['severity'] in ['CRITICAL', 'HIGH']:
                            if send_sns_alert(finding):
                                alerts_sent += 1
                        import_to_security_hub(finding)

                processed += 1

            except Exception as e:
                logger.error(f"Error processing record: {e}")

    # Handle direct invocation with CloudTrail event
    elif 'eventName' in event:
        finding = analyze_cloudtrail_event(event)

        if finding:
            findings.append(finding)
            if finding['severity'] in ['CRITICAL', 'HIGH']:
                if send_sns_alert(finding):
                    alerts_sent += 1
            import_to_security_hub(finding)

        processed = 1

    # Log summary
    summary = {
        'events_processed': processed,
        'findings_detected': len(findings),
        'alerts_sent': alerts_sent,
        'severity_breakdown': {}
    }

    for finding in findings:
        severity = finding['severity']
        summary['severity_breakdown'][severity] = summary['severity_breakdown'].get(severity, 0) + 1

    logger.info(f"Processing complete: {json.dumps(summary)}")

    return {
        'statusCode': 200,
        'body': json.dumps(summary)
    }


# For local testing
if __name__ == '__main__':
    # Test event - malicious IP
    test_event = {
        'source': 'aws.cloudtrail',
        'detail': {
            'eventName': 'GetCallerIdentity',
            'sourceIPAddress': '93.123.109.247',
            'userIdentity': {
                'type': 'AssumedRole',
                'arn': 'arn:aws:sts::123456789012:assumed-role/EC2-Role/i-1234567890abcdef0'
            },
            'recipientAccountId': '123456789012',
            'awsRegion': 'us-east-1',
            'eventTime': '2025-12-06T10:00:00Z'
        }
    }

    # Run handler
    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))
