#!/usr/bin/env python3
"""
React2Shell AWS Organization-Wide IOC Detection Script
CVE-2025-55182 & CVE-2025-66478

This script provides comprehensive detection capabilities for React2Shell
exploitation attempts across an AWS Organization.

Features:
- CloudTrail log analysis for API-based IOCs
- VPC Flow Log analysis for network IOCs
- GuardDuty threat intelligence integration
- WAF log analysis for HTTP-based IOCs
- Cross-account scanning via AWS Organizations
- Real-time alerting via SNS/Security Hub

Author: Security Operations Team
Date: 2025-12-06
"""

import boto3
import json
import yaml
import logging
import argparse
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('React2ShellDetector')


@dataclass
class Finding:
    """Represents a security finding"""
    finding_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    source: str
    account_id: str
    region: str
    resource_type: str
    resource_id: str
    ioc_type: str
    ioc_value: str
    mitre_technique: str
    timestamp: datetime
    raw_event: Dict = field(default_factory=dict)

    def to_security_hub_format(self) -> Dict:
        """Convert finding to AWS Security Hub format"""
        severity_map = {
            'CRITICAL': 90,
            'HIGH': 70,
            'MEDIUM': 40,
            'LOW': 10
        }

        return {
            'SchemaVersion': '2018-10-08',
            'Id': self.finding_id,
            'ProductArn': f'arn:aws:securityhub:{self.region}:{self.account_id}:product/{self.account_id}/default',
            'GeneratorId': 'react2shell-detector',
            'AwsAccountId': self.account_id,
            'Types': ['TTPs/Initial Access', 'Effects/Data Exfiltration'],
            'CreatedAt': self.timestamp.isoformat() + 'Z',
            'UpdatedAt': datetime.utcnow().isoformat() + 'Z',
            'Severity': {
                'Label': self.severity,
                'Normalized': severity_map.get(self.severity, 50)
            },
            'Title': self.title,
            'Description': self.description,
            'Resources': [{
                'Type': self.resource_type,
                'Id': self.resource_id,
                'Region': self.region
            }],
            'RecordState': 'ACTIVE',
            'ProductFields': {
                'IOCType': self.ioc_type,
                'IOCValue': self.ioc_value,
                'MITRETechnique': self.mitre_technique,
                'CVE': 'CVE-2025-55182,CVE-2025-66478'
            }
        }


class IOCLoader:
    """Load and manage IOCs from configuration"""

    def __init__(self, config_path: str = 'config/iocs.yaml'):
        self.config_path = config_path
        self.iocs = self._load_iocs()

    def _load_iocs(self) -> Dict:
        """Load IOCs from YAML configuration"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"IOC configuration not found: {self.config_path}")
            return self._get_default_iocs()

    def _get_default_iocs(self) -> Dict:
        """Return hardcoded IOCs as fallback"""
        return {
            'network_iocs': {
                'malicious_ips': [
                    {'ip': '93.123.109.247', 'port': 8000, 'confidence': 'high'},
                    {'ip': '45.77.33.136', 'port': 8080, 'confidence': 'high'},
                    {'ip': '194.246.84.13', 'port': 2045, 'confidence': 'high'},
                    {'ip': '45.32.158.54', 'port': None, 'confidence': 'medium'},
                    {'ip': '46.36.37.85', 'port': 12000, 'confidence': 'high'},
                    {'ip': '144.202.115.234', 'port': 80, 'confidence': 'medium'},
                    {'ip': '141.11.240.103', 'port': 45178, 'confidence': 'high'},
                    {'ip': '23.235.188.3', 'port': 652, 'confidence': 'high'},
                    {'ip': '162.215.170.26', 'port': 3000, 'confidence': 'medium'},
                ],
                'suspicious_ports': [652, 2045, 8000, 8080, 12000, 45178, 3333, 5555],
                'malicious_domains': {
                    'exfiltration_services': [
                        {'domain': 'ceye.io'},
                        {'domain': 'dnslog.cn'},
                    ],
                    'c2_domains': [
                        {'domain': 'sapo.shk0x.net'},
                        {'domain': 'xwpoogfunv.zaza.eu.org'},
                    ]
                }
            }
        }

    def get_malicious_ips(self) -> Set[str]:
        """Get set of malicious IP addresses"""
        ips = set()
        for entry in self.iocs.get('network_iocs', {}).get('malicious_ips', []):
            ips.add(entry['ip'])
        return ips

    def get_suspicious_ports(self) -> Set[int]:
        """Get set of suspicious ports"""
        return set(self.iocs.get('network_iocs', {}).get('suspicious_ports', []))

    def get_malicious_domains(self) -> Set[str]:
        """Get set of malicious domains"""
        domains = set()
        domain_config = self.iocs.get('network_iocs', {}).get('malicious_domains', {})
        for category in domain_config.values():
            if isinstance(category, list):
                for entry in category:
                    domains.add(entry.get('domain', ''))
        return domains

    def get_payload_patterns(self) -> List[Dict]:
        """Get HTTP payload patterns for detection"""
        patterns = []
        http_iocs = self.iocs.get('http_iocs', {})
        for severity, pattern_list in http_iocs.get('payload_patterns', {}).items():
            if isinstance(pattern_list, list):
                for p in pattern_list:
                    patterns.append({
                        'pattern': p.get('pattern', ''),
                        'severity': severity.upper(),
                        'description': p.get('description', '')
                    })
        return patterns


class CloudTrailAnalyzer:
    """Analyze CloudTrail logs for React2Shell IOCs"""

    def __init__(self, session: boto3.Session, ioc_loader: IOCLoader):
        self.session = session
        self.ioc_loader = ioc_loader
        self.cloudtrail = session.client('cloudtrail')
        self.athena = session.client('athena')

        # Suspicious API calls to monitor
        self.suspicious_events = {
            'credential_theft': [
                'GetCallerIdentity',
                'GetSessionToken',
                'AssumeRole',
            ],
            'reconnaissance': [
                'DescribeInstances',
                'DescribeInstanceAttribute',
                'ListBuckets',
                'ListSecrets',
            ],
            'lateral_movement': [
                'RunInstances',
                'SendCommand',
                'StartSession',
            ],
            'privilege_escalation': [
                'CreateAccessKey',
                'AttachUserPolicy',
                'AttachRolePolicy',
                'PutRolePolicy',
                'CreateRole',
            ],
            'exfiltration': [
                'GetSecretValue',
                'GetObject',
                'CopyObject',
            ]
        }

    def analyze_recent_events(self, hours: int = 24) -> List[Finding]:
        """Analyze recent CloudTrail events for IOCs"""
        findings = []
        malicious_ips = self.ioc_loader.get_malicious_ips()

        start_time = datetime.utcnow() - timedelta(hours=hours)

        try:
            paginator = self.cloudtrail.get_paginator('lookup_events')

            for event_type, event_names in self.suspicious_events.items():
                for event_name in event_names:
                    try:
                        for page in paginator.paginate(
                            LookupAttributes=[{
                                'AttributeKey': 'EventName',
                                'AttributeValue': event_name
                            }],
                            StartTime=start_time,
                            EndTime=datetime.utcnow()
                        ):
                            for event in page.get('Events', []):
                                finding = self._analyze_event(
                                    event, event_type, malicious_ips
                                )
                                if finding:
                                    findings.append(finding)
                    except ClientError as e:
                        logger.warning(f"Error querying {event_name}: {e}")

        except ClientError as e:
            logger.error(f"CloudTrail analysis error: {e}")

        return findings

    def _analyze_event(
        self,
        event: Dict,
        event_type: str,
        malicious_ips: Set[str]
    ) -> Optional[Finding]:
        """Analyze a single CloudTrail event"""
        try:
            cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
            source_ip = cloud_trail_event.get('sourceIPAddress', '')
            user_identity = cloud_trail_event.get('userIdentity', {})
            event_name = cloud_trail_event.get('eventName', '')

            # Check for malicious source IP
            if source_ip in malicious_ips:
                return Finding(
                    finding_id=f"ct-{event.get('EventId', 'unknown')}",
                    severity='CRITICAL',
                    title=f"React2Shell IOC: API call from malicious IP",
                    description=f"API call {event_name} detected from known React2Shell C2 IP: {source_ip}",
                    source='CloudTrail',
                    account_id=cloud_trail_event.get('recipientAccountId', 'unknown'),
                    region=cloud_trail_event.get('awsRegion', 'unknown'),
                    resource_type='AwsIamAccessKey',
                    resource_id=user_identity.get('arn', 'unknown'),
                    ioc_type='IP_ADDRESS',
                    ioc_value=source_ip,
                    mitre_technique=self._get_mitre_technique(event_type),
                    timestamp=event.get('EventTime', datetime.utcnow()),
                    raw_event=cloud_trail_event
                )

            # Check for EC2 instance credential usage outside expected patterns
            if (user_identity.get('type') == 'AssumedRole' and
                'EC2' in user_identity.get('arn', '')):

                # Check for suspicious patterns
                if event_type in ['credential_theft', 'lateral_movement', 'privilege_escalation']:
                    return Finding(
                        finding_id=f"ct-{event.get('EventId', 'unknown')}",
                        severity='HIGH',
                        title=f"React2Shell: Suspicious {event_type} from EC2 instance",
                        description=f"Suspicious API call {event_name} from EC2 instance role - potential post-exploitation activity",
                        source='CloudTrail',
                        account_id=cloud_trail_event.get('recipientAccountId', 'unknown'),
                        region=cloud_trail_event.get('awsRegion', 'unknown'),
                        resource_type='AwsEc2Instance',
                        resource_id=user_identity.get('principalId', 'unknown').split(':')[-1],
                        ioc_type='BEHAVIOR',
                        ioc_value=event_name,
                        mitre_technique=self._get_mitre_technique(event_type),
                        timestamp=event.get('EventTime', datetime.utcnow()),
                        raw_event=cloud_trail_event
                    )

        except json.JSONDecodeError:
            logger.warning("Failed to parse CloudTrail event")
        except Exception as e:
            logger.error(f"Error analyzing event: {e}")

        return None

    def _get_mitre_technique(self, event_type: str) -> str:
        """Map event type to MITRE ATT&CK technique"""
        mapping = {
            'credential_theft': 'T1552.001',
            'reconnaissance': 'T1087',
            'lateral_movement': 'T1021',
            'privilege_escalation': 'T1078',
            'exfiltration': 'T1537'
        }
        return mapping.get(event_type, 'T1190')


class VPCFlowLogAnalyzer:
    """Analyze VPC Flow Logs for network-based IOCs"""

    def __init__(self, session: boto3.Session, ioc_loader: IOCLoader):
        self.session = session
        self.ioc_loader = ioc_loader
        self.logs = session.client('logs')
        self.athena = session.client('athena')

    def analyze_flow_logs(
        self,
        log_group: str,
        hours: int = 24
    ) -> List[Finding]:
        """Analyze VPC Flow Logs for malicious connections"""
        findings = []
        malicious_ips = self.ioc_loader.get_malicious_ips()
        suspicious_ports = self.ioc_loader.get_suspicious_ports()

        start_time = int((datetime.utcnow() - timedelta(hours=hours)).timestamp() * 1000)
        end_time = int(datetime.utcnow().timestamp() * 1000)

        try:
            # Query CloudWatch Logs Insights
            query = """
            fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, protocol, bytes, action
            | filter action = 'ACCEPT'
            | sort @timestamp desc
            | limit 10000
            """

            response = self.logs.start_query(
                logGroupName=log_group,
                startTime=start_time,
                endTime=end_time,
                queryString=query
            )

            query_id = response['queryId']

            # Wait for query to complete
            import time
            while True:
                result = self.logs.get_query_results(queryId=query_id)
                if result['status'] == 'Complete':
                    break
                elif result['status'] == 'Failed':
                    logger.error("VPC Flow Log query failed")
                    return findings
                time.sleep(1)

            # Analyze results
            for row in result.get('results', []):
                row_dict = {field['field']: field['value'] for field in row}

                dst_addr = row_dict.get('dstAddr', '')
                dst_port = int(row_dict.get('dstPort', 0))
                src_addr = row_dict.get('srcAddr', '')

                # Check for connections to malicious IPs
                if dst_addr in malicious_ips:
                    findings.append(Finding(
                        finding_id=f"vpc-{hash(f'{src_addr}-{dst_addr}-{row_dict.get('@timestamp', '')}')}",
                        severity='CRITICAL',
                        title="React2Shell: Connection to known C2 infrastructure",
                        description=f"Outbound connection detected from {src_addr} to known React2Shell C2 IP {dst_addr}:{dst_port}",
                        source='VPCFlowLogs',
                        account_id=self.session.client('sts').get_caller_identity()['Account'],
                        region=self.session.region_name,
                        resource_type='AwsEc2NetworkInterface',
                        resource_id=src_addr,
                        ioc_type='IP_ADDRESS',
                        ioc_value=dst_addr,
                        mitre_technique='T1071',
                        timestamp=datetime.fromisoformat(row_dict.get('@timestamp', datetime.utcnow().isoformat()).replace('Z', '')),
                        raw_event=row_dict
                    ))

                # Check for connections to suspicious ports
                elif dst_port in suspicious_ports:
                    findings.append(Finding(
                        finding_id=f"vpc-{hash(f'{src_addr}-{dst_addr}-{dst_port}')}",
                        severity='HIGH',
                        title="React2Shell: Connection to suspicious port",
                        description=f"Outbound connection from {src_addr} to {dst_addr}:{dst_port} - suspicious port associated with React2Shell exploitation",
                        source='VPCFlowLogs',
                        account_id=self.session.client('sts').get_caller_identity()['Account'],
                        region=self.session.region_name,
                        resource_type='AwsEc2NetworkInterface',
                        resource_id=src_addr,
                        ioc_type='PORT',
                        ioc_value=str(dst_port),
                        mitre_technique='T1571',
                        timestamp=datetime.fromisoformat(row_dict.get('@timestamp', datetime.utcnow().isoformat()).replace('Z', '')),
                        raw_event=row_dict
                    ))

        except ClientError as e:
            logger.error(f"VPC Flow Log analysis error: {e}")
        except Exception as e:
            logger.error(f"Error analyzing flow logs: {e}")

        return findings


class GuardDutyManager:
    """Manage GuardDuty threat intelligence for React2Shell"""

    def __init__(self, session: boto3.Session, ioc_loader: IOCLoader):
        self.session = session
        self.ioc_loader = ioc_loader
        self.guardduty = session.client('guardduty')
        self.s3 = session.client('s3')

    def get_detector_id(self) -> Optional[str]:
        """Get the GuardDuty detector ID for the account"""
        try:
            response = self.guardduty.list_detectors()
            detectors = response.get('DetectorIds', [])
            return detectors[0] if detectors else None
        except ClientError as e:
            logger.error(f"Failed to list GuardDuty detectors: {e}")
            return None

    def create_threat_intel_set(
        self,
        bucket_name: str,
        detector_id: Optional[str] = None
    ) -> Optional[str]:
        """Create or update GuardDuty threat intelligence set with React2Shell IOCs"""

        if not detector_id:
            detector_id = self.get_detector_id()

        if not detector_id:
            logger.error("No GuardDuty detector found")
            return None

        # Generate IP list content
        malicious_ips = self.ioc_loader.get_malicious_ips()
        ip_list_content = '\n'.join(malicious_ips)

        # Upload to S3
        s3_key = 'threat-intel/react2shell-ips.txt'
        try:
            self.s3.put_object(
                Bucket=bucket_name,
                Key=s3_key,
                Body=ip_list_content.encode('utf-8'),
                ContentType='text/plain'
            )
            logger.info(f"Uploaded threat intel to s3://{bucket_name}/{s3_key}")
        except ClientError as e:
            logger.error(f"Failed to upload threat intel: {e}")
            return None

        # Create or update ThreatIntelSet
        s3_location = f"s3://{bucket_name}/{s3_key}"
        name = "React2Shell-CVE-2025-55182-ThreatIntelSet"

        try:
            # Check if set already exists
            existing_sets = self.guardduty.list_threat_intel_sets(
                DetectorId=detector_id
            )

            for set_id in existing_sets.get('ThreatIntelSetIds', []):
                set_info = self.guardduty.get_threat_intel_set(
                    DetectorId=detector_id,
                    ThreatIntelSetId=set_id
                )
                if set_info.get('Name') == name:
                    # Update existing set
                    self.guardduty.update_threat_intel_set(
                        DetectorId=detector_id,
                        ThreatIntelSetId=set_id,
                        Location=s3_location,
                        Activate=True
                    )
                    logger.info(f"Updated ThreatIntelSet: {set_id}")
                    return set_id

            # Create new set
            response = self.guardduty.create_threat_intel_set(
                DetectorId=detector_id,
                Name=name,
                Format='TXT',
                Location=s3_location,
                Activate=True
            )

            threat_intel_set_id = response['ThreatIntelSetId']
            logger.info(f"Created ThreatIntelSet: {threat_intel_set_id}")
            return threat_intel_set_id

        except ClientError as e:
            logger.error(f"Failed to create ThreatIntelSet: {e}")
            return None

    def get_relevant_findings(self, hours: int = 24) -> List[Finding]:
        """Get GuardDuty findings relevant to React2Shell"""
        findings = []
        detector_id = self.get_detector_id()

        if not detector_id:
            return findings

        relevant_finding_types = [
            'UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS',
            'UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS',
            'Trojan:EC2/DNSDataExfiltration',
            'CryptoCurrency:EC2/BitcoinTool.B!DNS',
            'Behavior:EC2/NetworkPortUnusual',
            'Impact:EC2/MaliciousDomainRequest.Reputation',
            'UnauthorizedAccess:EC2/TorClient',
        ]

        try:
            paginator = self.guardduty.get_paginator('list_findings')

            for page in paginator.paginate(
                DetectorId=detector_id,
                FindingCriteria={
                    'Criterion': {
                        'type': {
                            'Eq': relevant_finding_types
                        },
                        'updatedAt': {
                            'Gte': int((datetime.utcnow() - timedelta(hours=hours)).timestamp() * 1000)
                        }
                    }
                }
            ):
                finding_ids = page.get('FindingIds', [])

                if finding_ids:
                    details = self.guardduty.get_findings(
                        DetectorId=detector_id,
                        FindingIds=finding_ids
                    )

                    for gd_finding in details.get('Findings', []):
                        findings.append(self._convert_guardduty_finding(gd_finding))

        except ClientError as e:
            logger.error(f"Failed to get GuardDuty findings: {e}")

        return findings

    def _convert_guardduty_finding(self, gd_finding: Dict) -> Finding:
        """Convert GuardDuty finding to internal Finding format"""
        resource = gd_finding.get('Resource', {})
        service = gd_finding.get('Service', {})

        return Finding(
            finding_id=gd_finding.get('Id', 'unknown'),
            severity=gd_finding.get('Severity', 5) >= 7 and 'HIGH' or 'MEDIUM',
            title=f"GuardDuty: {gd_finding.get('Title', 'Unknown')}",
            description=gd_finding.get('Description', ''),
            source='GuardDuty',
            account_id=gd_finding.get('AccountId', 'unknown'),
            region=gd_finding.get('Region', 'unknown'),
            resource_type=resource.get('ResourceType', 'unknown'),
            resource_id=resource.get('InstanceDetails', {}).get('InstanceId', 'unknown'),
            ioc_type='BEHAVIOR',
            ioc_value=gd_finding.get('Type', 'unknown'),
            mitre_technique='T1190',
            timestamp=datetime.fromisoformat(gd_finding.get('UpdatedAt', datetime.utcnow().isoformat()).replace('Z', '')),
            raw_event=gd_finding
        )


class WAFLogAnalyzer:
    """Analyze WAF logs for React2Shell exploitation attempts"""

    def __init__(self, session: boto3.Session, ioc_loader: IOCLoader):
        self.session = session
        self.ioc_loader = ioc_loader
        self.logs = session.client('logs')

        # Compile regex patterns
        self.payload_patterns = []
        for pattern_info in ioc_loader.get_payload_patterns():
            try:
                compiled = re.compile(pattern_info['pattern'], re.IGNORECASE)
                self.payload_patterns.append({
                    'regex': compiled,
                    'severity': pattern_info['severity'],
                    'description': pattern_info['description']
                })
            except re.error as e:
                logger.warning(f"Invalid regex pattern: {pattern_info['pattern']}: {e}")

    def analyze_waf_logs(
        self,
        log_group: str,
        hours: int = 24
    ) -> List[Finding]:
        """Analyze WAF logs for React2Shell exploitation patterns"""
        findings = []

        start_time = int((datetime.utcnow() - timedelta(hours=hours)).timestamp() * 1000)
        end_time = int(datetime.utcnow().timestamp() * 1000)

        try:
            query = """
            fields @timestamp, httpRequest.clientIp, httpRequest.uri,
                   httpRequest.httpMethod, httpRequest.headers, action
            | filter httpRequest.httpMethod = 'POST'
            | sort @timestamp desc
            | limit 10000
            """

            response = self.logs.start_query(
                logGroupName=log_group,
                startTime=start_time,
                endTime=end_time,
                queryString=query
            )

            query_id = response['queryId']

            import time
            while True:
                result = self.logs.get_query_results(queryId=query_id)
                if result['status'] == 'Complete':
                    break
                elif result['status'] == 'Failed':
                    logger.error("WAF log query failed")
                    return findings
                time.sleep(1)

            for row in result.get('results', []):
                row_dict = {field['field']: field['value'] for field in row}
                finding = self._analyze_waf_request(row_dict)
                if finding:
                    findings.append(finding)

        except ClientError as e:
            logger.error(f"WAF log analysis error: {e}")

        return findings

    def _analyze_waf_request(self, request: Dict) -> Optional[Finding]:
        """Analyze a single WAF request for IOCs"""
        headers_str = request.get('httpRequest.headers', '{}')

        try:
            headers = json.loads(headers_str) if isinstance(headers_str, str) else headers_str
        except json.JSONDecodeError:
            headers = {}

        # Check for Next-Action header
        for header in headers if isinstance(headers, list) else []:
            if isinstance(header, dict):
                name = header.get('name', '').lower()
                if name in ['next-action', 'rsc-action-id']:
                    return Finding(
                        finding_id=f"waf-{hash(f'{request.get('httpRequest.clientIp')}-{request.get('@timestamp')}')}",
                        severity='CRITICAL',
                        title="React2Shell: Exploitation attempt detected",
                        description=f"Request with {name} header detected from {request.get('httpRequest.clientIp')} - likely React2Shell exploitation attempt",
                        source='WAFLogs',
                        account_id=self.session.client('sts').get_caller_identity()['Account'],
                        region=self.session.region_name,
                        resource_type='AwsWafWebAcl',
                        resource_id='unknown',
                        ioc_type='HTTP_HEADER',
                        ioc_value=name,
                        mitre_technique='T1190',
                        timestamp=datetime.fromisoformat(request.get('@timestamp', datetime.utcnow().isoformat()).replace('Z', '')),
                        raw_event=request
                    )

        return None


class OrganizationScanner:
    """Scan across AWS Organization for React2Shell IOCs"""

    def __init__(self, session: boto3.Session, ioc_loader: IOCLoader):
        self.session = session
        self.ioc_loader = ioc_loader
        self.orgs = session.client('organizations')
        self.sts = session.client('sts')

    def get_all_accounts(self) -> List[Dict]:
        """Get all accounts in the organization"""
        accounts = []

        try:
            paginator = self.orgs.get_paginator('list_accounts')
            for page in paginator.paginate():
                for account in page.get('Accounts', []):
                    if account.get('Status') == 'ACTIVE':
                        accounts.append({
                            'id': account['Id'],
                            'name': account.get('Name', 'Unknown'),
                            'email': account.get('Email', '')
                        })
        except ClientError as e:
            logger.error(f"Failed to list organization accounts: {e}")
            # Fall back to current account only
            current_account = self.sts.get_caller_identity()
            accounts.append({
                'id': current_account['Account'],
                'name': 'Current Account',
                'email': ''
            })

        return accounts

    def assume_role_in_account(
        self,
        account_id: str,
        role_name: str = 'OrganizationAccountAccessRole'
    ) -> Optional[boto3.Session]:
        """Assume role in target account"""
        try:
            response = self.sts.assume_role(
                RoleArn=f'arn:aws:iam::{account_id}:role/{role_name}',
                RoleSessionName='React2ShellScanner'
            )

            credentials = response['Credentials']

            return boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
        except ClientError as e:
            logger.warning(f"Failed to assume role in {account_id}: {e}")
            return None

    def scan_organization(
        self,
        hours: int = 24,
        role_name: str = 'OrganizationAccountAccessRole',
        max_workers: int = 10
    ) -> List[Finding]:
        """Scan all accounts in organization for React2Shell IOCs"""
        all_findings = []
        accounts = self.get_all_accounts()

        logger.info(f"Scanning {len(accounts)} accounts...")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}

            for account in accounts:
                future = executor.submit(
                    self._scan_account,
                    account['id'],
                    role_name,
                    hours
                )
                futures[future] = account

            for future in as_completed(futures):
                account = futures[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                    logger.info(f"Account {account['id']}: {len(findings)} findings")
                except Exception as e:
                    logger.error(f"Error scanning account {account['id']}: {e}")

        return all_findings

    def _scan_account(
        self,
        account_id: str,
        role_name: str,
        hours: int
    ) -> List[Finding]:
        """Scan a single account for IOCs"""
        findings = []

        # Get session for the account
        if account_id == self.sts.get_caller_identity()['Account']:
            account_session = self.session
        else:
            account_session = self.assume_role_in_account(account_id, role_name)
            if not account_session:
                return findings

        # Run analyzers
        try:
            # CloudTrail analysis
            ct_analyzer = CloudTrailAnalyzer(account_session, self.ioc_loader)
            findings.extend(ct_analyzer.analyze_recent_events(hours))

            # GuardDuty analysis
            gd_manager = GuardDutyManager(account_session, self.ioc_loader)
            findings.extend(gd_manager.get_relevant_findings(hours))

        except Exception as e:
            logger.error(f"Error in account {account_id}: {e}")

        return findings


class SecurityHubReporter:
    """Report findings to AWS Security Hub"""

    def __init__(self, session: boto3.Session):
        self.session = session
        self.securityhub = session.client('securityhub')

    def import_findings(self, findings: List[Finding]) -> Tuple[int, int]:
        """Import findings to Security Hub"""
        if not findings:
            return 0, 0

        success_count = 0
        failure_count = 0

        # Process in batches of 100 (Security Hub limit)
        batch_size = 100
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i+batch_size]

            try:
                sh_findings = [f.to_security_hub_format() for f in batch]

                response = self.securityhub.batch_import_findings(
                    Findings=sh_findings
                )

                success_count += response.get('SuccessCount', 0)
                failure_count += response.get('FailedCount', 0)

            except ClientError as e:
                logger.error(f"Failed to import findings batch: {e}")
                failure_count += len(batch)

        return success_count, failure_count


class SNSAlerter:
    """Send alerts via SNS"""

    def __init__(self, session: boto3.Session, topic_arn: str):
        self.session = session
        self.sns = session.client('sns')
        self.topic_arn = topic_arn

    def send_alert(self, findings: List[Finding]) -> bool:
        """Send alert for critical findings"""
        critical_findings = [f for f in findings if f.severity == 'CRITICAL']

        if not critical_findings:
            return True

        message = {
            'default': f"React2Shell Alert: {len(critical_findings)} critical findings detected",
            'email': self._format_email_message(critical_findings),
            'sms': f"ALERT: {len(critical_findings)} React2Shell critical findings detected. Check Security Hub immediately."
        }

        try:
            self.sns.publish(
                TopicArn=self.topic_arn,
                Message=json.dumps(message),
                MessageStructure='json',
                Subject='[CRITICAL] React2Shell IOC Detection Alert'
            )
            return True
        except ClientError as e:
            logger.error(f"Failed to send SNS alert: {e}")
            return False

    def _format_email_message(self, findings: List[Finding]) -> str:
        """Format findings for email notification"""
        lines = [
            "React2Shell IOC Detection Alert",
            "=" * 50,
            f"Timestamp: {datetime.utcnow().isoformat()}Z",
            f"Total Critical Findings: {len(findings)}",
            "",
            "CVE References:",
            "- CVE-2025-55182 (React Server Components)",
            "- CVE-2025-66478 (Next.js)",
            "",
            "Findings Summary:",
            "-" * 50,
        ]

        for finding in findings[:10]:  # Limit to first 10
            lines.extend([
                f"",
                f"Finding ID: {finding.finding_id}",
                f"Title: {finding.title}",
                f"Account: {finding.account_id}",
                f"Region: {finding.region}",
                f"Resource: {finding.resource_id}",
                f"IOC: {finding.ioc_type} - {finding.ioc_value}",
                f"MITRE: {finding.mitre_technique}",
            ])

        if len(findings) > 10:
            lines.append(f"\n... and {len(findings) - 10} more findings")

        lines.extend([
            "",
            "Immediate Actions Required:",
            "1. Isolate affected resources",
            "2. Rotate exposed credentials",
            "3. Check for lateral movement",
            "4. Patch affected applications",
            "",
            "Reference: https://react2shell.com"
        ])

        return '\n'.join(lines)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='React2Shell AWS IOC Detection Script'
    )
    parser.add_argument(
        '--config',
        default='config/iocs.yaml',
        help='Path to IOC configuration file'
    )
    parser.add_argument(
        '--hours',
        type=int,
        default=24,
        help='Hours of logs to analyze (default: 24)'
    )
    parser.add_argument(
        '--organization',
        action='store_true',
        help='Scan across entire AWS Organization'
    )
    parser.add_argument(
        '--role-name',
        default='OrganizationAccountAccessRole',
        help='Role name to assume in member accounts'
    )
    parser.add_argument(
        '--sns-topic',
        help='SNS topic ARN for alerts'
    )
    parser.add_argument(
        '--security-hub',
        action='store_true',
        help='Import findings to Security Hub'
    )
    parser.add_argument(
        '--guardduty-bucket',
        help='S3 bucket for GuardDuty threat intel'
    )
    parser.add_argument(
        '--vpc-log-group',
        help='VPC Flow Logs CloudWatch log group'
    )
    parser.add_argument(
        '--waf-log-group',
        help='WAF logs CloudWatch log group'
    )
    parser.add_argument(
        '--output',
        choices=['json', 'text', 'csv'],
        default='text',
        help='Output format (default: text)'
    )
    parser.add_argument(
        '--output-file',
        help='Output file path'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialize
    session = boto3.Session()
    ioc_loader = IOCLoader(args.config)

    logger.info("=" * 60)
    logger.info("React2Shell IOC Detection Script")
    logger.info("CVE-2025-55182 & CVE-2025-66478")
    logger.info("=" * 60)

    all_findings = []

    # Organization-wide scan
    if args.organization:
        logger.info("Starting organization-wide scan...")
        org_scanner = OrganizationScanner(session, ioc_loader)
        all_findings.extend(org_scanner.scan_organization(
            hours=args.hours,
            role_name=args.role_name
        ))
    else:
        # Single account scan
        logger.info("Starting single account scan...")

        # CloudTrail analysis
        logger.info("Analyzing CloudTrail logs...")
        ct_analyzer = CloudTrailAnalyzer(session, ioc_loader)
        all_findings.extend(ct_analyzer.analyze_recent_events(args.hours))

        # GuardDuty analysis
        logger.info("Checking GuardDuty findings...")
        gd_manager = GuardDutyManager(session, ioc_loader)
        all_findings.extend(gd_manager.get_relevant_findings(args.hours))

        # Update GuardDuty threat intel if bucket provided
        if args.guardduty_bucket:
            logger.info("Updating GuardDuty threat intelligence...")
            gd_manager.create_threat_intel_set(args.guardduty_bucket)

        # VPC Flow Log analysis
        if args.vpc_log_group:
            logger.info("Analyzing VPC Flow Logs...")
            vpc_analyzer = VPCFlowLogAnalyzer(session, ioc_loader)
            all_findings.extend(vpc_analyzer.analyze_flow_logs(
                args.vpc_log_group, args.hours
            ))

        # WAF Log analysis
        if args.waf_log_group:
            logger.info("Analyzing WAF logs...")
            waf_analyzer = WAFLogAnalyzer(session, ioc_loader)
            all_findings.extend(waf_analyzer.analyze_waf_logs(
                args.waf_log_group, args.hours
            ))

    # Report results
    logger.info(f"\nTotal findings: {len(all_findings)}")

    critical = len([f for f in all_findings if f.severity == 'CRITICAL'])
    high = len([f for f in all_findings if f.severity == 'HIGH'])
    medium = len([f for f in all_findings if f.severity == 'MEDIUM'])

    logger.info(f"  CRITICAL: {critical}")
    logger.info(f"  HIGH: {high}")
    logger.info(f"  MEDIUM: {medium}")

    # Security Hub integration
    if args.security_hub and all_findings:
        logger.info("\nImporting findings to Security Hub...")
        sh_reporter = SecurityHubReporter(session)
        success, failure = sh_reporter.import_findings(all_findings)
        logger.info(f"  Success: {success}, Failed: {failure}")

    # SNS alerting
    if args.sns_topic and all_findings:
        logger.info("\nSending SNS alerts...")
        alerter = SNSAlerter(session, args.sns_topic)
        alerter.send_alert(all_findings)

    # Output results
    output_data = [f.__dict__ for f in all_findings]

    # Convert datetime objects to strings for JSON serialization
    for item in output_data:
        if isinstance(item.get('timestamp'), datetime):
            item['timestamp'] = item['timestamp'].isoformat()

    if args.output == 'json':
        output = json.dumps(output_data, indent=2, default=str)
    elif args.output == 'csv':
        import csv
        import io
        output_io = io.StringIO()
        if output_data:
            writer = csv.DictWriter(output_io, fieldnames=output_data[0].keys())
            writer.writeheader()
            writer.writerows(output_data)
        output = output_io.getvalue()
    else:
        output_lines = []
        for finding in all_findings:
            output_lines.append(f"\n[{finding.severity}] {finding.title}")
            output_lines.append(f"  Source: {finding.source}")
            output_lines.append(f"  Account: {finding.account_id}")
            output_lines.append(f"  Resource: {finding.resource_id}")
            output_lines.append(f"  IOC: {finding.ioc_type} - {finding.ioc_value}")
            output_lines.append(f"  MITRE: {finding.mitre_technique}")
        output = '\n'.join(output_lines)

    if args.output_file:
        with open(args.output_file, 'w') as f:
            f.write(output)
        logger.info(f"\nResults written to {args.output_file}")
    elif all_findings:
        print(output)

    return 0 if not critical else 1


if __name__ == '__main__':
    exit(main())
