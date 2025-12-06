-- React2Shell Detection Queries for AWS Athena
-- CVE-2025-55182 & CVE-2025-66478
-- Use with CloudTrail and VPC Flow Log tables

-- ============================================================================
-- PREREQUISITES: Create tables for CloudTrail and VPC Flow Logs
-- ============================================================================

-- Create CloudTrail table (adjust S3 location)
-- CREATE EXTERNAL TABLE IF NOT EXISTS cloudtrail_logs (
--     eventversion STRING,
--     useridentity STRUCT<
--         type:STRING,
--         principalid:STRING,
--         arn:STRING,
--         accountid:STRING,
--         invokedby:STRING,
--         accesskeyid:STRING,
--         username:STRING,
--         sessioncontext:STRUCT<
--             attributes:STRUCT<mfaauthenticated:STRING, creationdate:STRING>,
--             sessionissuer:STRUCT<type:STRING, principalid:STRING, arn:STRING, accountid:STRING, username:STRING>
--         >
--     >,
--     eventtime STRING,
--     eventsource STRING,
--     eventname STRING,
--     awsregion STRING,
--     sourceipaddress STRING,
--     useragent STRING,
--     errorcode STRING,
--     errormessage STRING,
--     requestparameters STRING,
--     responseelements STRING,
--     additionaleventdata STRING,
--     requestid STRING,
--     eventid STRING,
--     resources ARRAY<STRUCT<arn:STRING, accountid:STRING, type:STRING>>,
--     eventtype STRING,
--     apiversion STRING,
--     readonly STRING,
--     recipientaccountid STRING,
--     serviceeventdetails STRING,
--     sharedeventid STRING,
--     vpcendpointid STRING
-- )
-- PARTITIONED BY (region STRING, year STRING, month STRING, day STRING)
-- ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
-- STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
-- OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
-- LOCATION 's3://YOUR-CLOUDTRAIL-BUCKET/AWSLogs/ACCOUNT-ID/CloudTrail/';

-- ============================================================================
-- CLOUDTRAIL DETECTION QUERIES
-- ============================================================================

-- Query 1: Detect API calls from known React2Shell C2 IPs
-- Priority: CRITICAL
-- MITRE: T1190 - Exploit Public-Facing Application
SELECT
    eventtime,
    sourceipaddress,
    eventname,
    eventsource,
    useridentity.arn AS caller_arn,
    useridentity.type AS identity_type,
    awsregion,
    useragent,
    recipientaccountid,
    requestparameters
FROM cloudtrail_logs
WHERE sourceipaddress IN (
    '93.123.109.247',
    '45.77.33.136',
    '194.246.84.13',
    '45.32.158.54',
    '46.36.37.85',
    '144.202.115.234',
    '141.11.240.103',
    '23.235.188.3',
    '162.215.170.26'
)
AND eventtime >= date_format(date_add('hour', -24, current_timestamp), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventtime DESC;


-- Query 2: Detect credential reconnaissance after potential compromise
-- Priority: HIGH
-- MITRE: T1552.001 - Credentials In Files
-- Description: GetCallerIdentity is typically the first API call after credential theft
SELECT
    eventtime,
    sourceipaddress,
    useridentity.arn AS caller_arn,
    useridentity.principalid AS principal_id,
    useridentity.type AS identity_type,
    awsregion,
    useragent,
    recipientaccountid
FROM cloudtrail_logs
WHERE eventname = 'GetCallerIdentity'
AND useridentity.type = 'AssumedRole'
AND useridentity.arn LIKE '%i-%'  -- EC2 instance role
AND eventtime >= date_format(date_add('hour', -24, current_timestamp), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventtime DESC;


-- Query 3: Detect EC2 instance metadata harvesting
-- Priority: HIGH
-- MITRE: T1552.005 - Cloud Instance Metadata API
SELECT
    eventtime,
    sourceipaddress,
    useridentity.arn AS caller_arn,
    eventname,
    JSON_EXTRACT_SCALAR(requestparameters, '$.attribute') AS requested_attribute,
    JSON_EXTRACT_SCALAR(requestparameters, '$.instanceId') AS target_instance,
    awsregion,
    useragent
FROM cloudtrail_logs
WHERE eventname = 'DescribeInstanceAttribute'
AND JSON_EXTRACT_SCALAR(requestparameters, '$.attribute') = 'userData'
AND eventtime >= date_format(date_add('hour', -24, current_timestamp), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventtime DESC;


-- Query 4: Detect lateral movement via SSM
-- Priority: HIGH
-- MITRE: T1021 - Remote Services
SELECT
    eventtime,
    sourceipaddress,
    useridentity.arn AS caller_arn,
    eventname,
    JSON_EXTRACT_SCALAR(requestparameters, '$.instanceIds') AS target_instances,
    JSON_EXTRACT_SCALAR(requestparameters, '$.documentName') AS document_name,
    awsregion,
    errorcode,
    errormessage
FROM cloudtrail_logs
WHERE eventname IN ('SendCommand', 'StartSession', 'StartAutomationExecution')
AND useridentity.arn LIKE '%EC2%'
AND eventtime >= date_format(date_add('hour', -24, current_timestamp), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventtime DESC;


-- Query 5: Detect privilege escalation attempts
-- Priority: CRITICAL
-- MITRE: T1078 - Valid Accounts
SELECT
    eventtime,
    sourceipaddress,
    useridentity.arn AS caller_arn,
    eventname,
    requestparameters,
    errorcode,
    awsregion,
    recipientaccountid
FROM cloudtrail_logs
WHERE eventname IN (
    'CreateAccessKey',
    'CreateLoginProfile',
    'AttachUserPolicy',
    'AttachRolePolicy',
    'AttachGroupPolicy',
    'PutUserPolicy',
    'PutRolePolicy',
    'PutGroupPolicy',
    'UpdateAssumeRolePolicy',
    'CreateRole',
    'AddUserToGroup'
)
AND eventtime >= date_format(date_add('hour', -24, current_timestamp), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventtime DESC;


-- Query 6: Detect secrets access from EC2 instances
-- Priority: HIGH
-- MITRE: T1552.001 - Credentials In Files
SELECT
    eventtime,
    sourceipaddress,
    useridentity.arn AS caller_arn,
    eventname,
    JSON_EXTRACT_SCALAR(requestparameters, '$.secretId') AS secret_accessed,
    awsregion,
    errorcode
FROM cloudtrail_logs
WHERE eventname IN ('GetSecretValue', 'BatchGetSecretValue', 'ListSecrets')
AND useridentity.type = 'AssumedRole'
AND eventtime >= date_format(date_add('hour', -24, current_timestamp), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventtime DESC;


-- Query 7: Detect unusual RunInstances activity (potential cryptomining)
-- Priority: HIGH
-- MITRE: T1496 - Resource Hijacking
SELECT
    eventtime,
    sourceipaddress,
    useridentity.arn AS caller_arn,
    eventname,
    JSON_EXTRACT_SCALAR(requestparameters, '$.instanceType') AS instance_type,
    JSON_EXTRACT_SCALAR(requestparameters, '$.minCount') AS min_count,
    JSON_EXTRACT_SCALAR(requestparameters, '$.maxCount') AS max_count,
    awsregion,
    errorcode
FROM cloudtrail_logs
WHERE eventname = 'RunInstances'
AND eventtime >= date_format(date_add('hour', -24, current_timestamp), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventtime DESC;


-- Query 8: Detect S3 data exfiltration patterns
-- Priority: HIGH
-- MITRE: T1537 - Transfer Data to Cloud Account
SELECT
    eventtime,
    sourceipaddress,
    useridentity.arn AS caller_arn,
    eventname,
    JSON_EXTRACT_SCALAR(requestparameters, '$.bucketName') AS bucket_name,
    JSON_EXTRACT_SCALAR(requestparameters, '$.key') AS object_key,
    awsregion
FROM cloudtrail_logs
WHERE eventname IN ('GetObject', 'CopyObject', 'PutObject')
AND useridentity.type = 'AssumedRole'
AND useridentity.arn LIKE '%EC2%'
AND eventtime >= date_format(date_add('hour', -24, current_timestamp), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventtime DESC
LIMIT 1000;


-- Query 9: Detect security group modifications (lateral movement prep)
-- Priority: MEDIUM
-- MITRE: T1562.007 - Disable Cloud Logs
SELECT
    eventtime,
    sourceipaddress,
    useridentity.arn AS caller_arn,
    eventname,
    JSON_EXTRACT_SCALAR(requestparameters, '$.groupId') AS security_group_id,
    requestparameters,
    awsregion,
    errorcode
FROM cloudtrail_logs
WHERE eventname IN (
    'AuthorizeSecurityGroupIngress',
    'AuthorizeSecurityGroupEgress',
    'CreateSecurityGroup',
    'ModifySecurityGroupRules'
)
AND eventtime >= date_format(date_add('hour', -24, current_timestamp), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventtime DESC;


-- Query 10: Detect CloudTrail/logging tampering
-- Priority: CRITICAL
-- MITRE: T1562.008 - Disable Cloud Logs
SELECT
    eventtime,
    sourceipaddress,
    useridentity.arn AS caller_arn,
    eventname,
    requestparameters,
    awsregion,
    errorcode
FROM cloudtrail_logs
WHERE eventname IN (
    'StopLogging',
    'DeleteTrail',
    'UpdateTrail',
    'PutEventSelectors',
    'DeleteFlowLogs',
    'DeleteLogGroup'
)
AND eventtime >= date_format(date_add('hour', -24, current_timestamp), '%Y-%m-%dT%H:%i:%sZ')
ORDER BY eventtime DESC;


-- ============================================================================
-- VPC FLOW LOG DETECTION QUERIES
-- ============================================================================

-- Create VPC Flow Logs table (adjust S3 location)
-- CREATE EXTERNAL TABLE IF NOT EXISTS vpc_flow_logs (
--     version INT,
--     account_id STRING,
--     interface_id STRING,
--     srcaddr STRING,
--     dstaddr STRING,
--     srcport INT,
--     dstport INT,
--     protocol INT,
--     packets INT,
--     bytes BIGINT,
--     start_time BIGINT,
--     end_time BIGINT,
--     action STRING,
--     log_status STRING
-- )
-- PARTITIONED BY (region STRING, day STRING)
-- ROW FORMAT DELIMITED
-- FIELDS TERMINATED BY ' '
-- LOCATION 's3://YOUR-FLOW-LOGS-BUCKET/AWSLogs/ACCOUNT-ID/vpcflowlogs/';


-- Query 11: Detect connections to known C2 IPs
-- Priority: CRITICAL
-- MITRE: T1071 - Application Layer Protocol
SELECT
    from_unixtime(start_time) AS connection_time,
    srcaddr AS source_ip,
    dstaddr AS destination_ip,
    dstport AS destination_port,
    protocol,
    bytes,
    packets,
    action,
    interface_id
FROM vpc_flow_logs
WHERE dstaddr IN (
    '93.123.109.247',
    '45.77.33.136',
    '194.246.84.13',
    '45.32.158.54',
    '46.36.37.85',
    '144.202.115.234',
    '141.11.240.103',
    '23.235.188.3',
    '162.215.170.26'
)
AND action = 'ACCEPT'
AND from_unixtime(start_time) >= date_add('hour', -24, current_timestamp)
ORDER BY start_time DESC;


-- Query 12: Detect connections to suspicious C2 ports
-- Priority: HIGH
-- MITRE: T1571 - Non-Standard Port
SELECT
    from_unixtime(start_time) AS connection_time,
    srcaddr AS source_ip,
    dstaddr AS destination_ip,
    dstport AS destination_port,
    protocol,
    bytes,
    packets,
    interface_id
FROM vpc_flow_logs
WHERE dstport IN (652, 2045, 8000, 8080, 12000, 45178)
AND action = 'ACCEPT'
AND from_unixtime(start_time) >= date_add('hour', -24, current_timestamp)
ORDER BY start_time DESC;


-- Query 13: Detect potential cryptomining traffic
-- Priority: HIGH
-- MITRE: T1496 - Resource Hijacking
SELECT
    srcaddr AS source_ip,
    dstaddr AS destination_ip,
    dstport AS destination_port,
    SUM(bytes) AS total_bytes,
    SUM(packets) AS total_packets,
    COUNT(*) AS connection_count
FROM vpc_flow_logs
WHERE dstport IN (3333, 5555, 7777, 9999, 14433, 14444, 45700)
AND action = 'ACCEPT'
AND from_unixtime(start_time) >= date_add('hour', -24, current_timestamp)
GROUP BY srcaddr, dstaddr, dstport
HAVING SUM(bytes) > 10000000  -- 10MB threshold
ORDER BY total_bytes DESC;


-- Query 14: Detect high-volume outbound data transfer (exfiltration)
-- Priority: HIGH
-- MITRE: T1048 - Exfiltration Over Alternative Protocol
SELECT
    srcaddr AS source_ip,
    dstaddr AS destination_ip,
    dstport AS destination_port,
    SUM(bytes) AS total_bytes_sent,
    COUNT(*) AS connection_count
FROM vpc_flow_logs
WHERE action = 'ACCEPT'
AND from_unixtime(start_time) >= date_add('hour', -24, current_timestamp)
GROUP BY srcaddr, dstaddr, dstport
HAVING SUM(bytes) > 100000000  -- 100MB threshold
ORDER BY total_bytes_sent DESC
LIMIT 100;


-- Query 15: Detect lateral movement within VPC
-- Priority: MEDIUM
-- MITRE: T1021 - Remote Services
SELECT
    from_unixtime(start_time) AS connection_time,
    srcaddr AS source_ip,
    dstaddr AS destination_ip,
    dstport AS destination_port,
    bytes,
    packets
FROM vpc_flow_logs
WHERE dstport IN (22, 3389, 5985, 5986)  -- SSH, RDP, WinRM
AND action = 'ACCEPT'
AND srcaddr LIKE '10.%' OR srcaddr LIKE '172.%' OR srcaddr LIKE '192.168.%'
AND dstaddr LIKE '10.%' OR dstaddr LIKE '172.%' OR dstaddr LIKE '192.168.%'
AND from_unixtime(start_time) >= date_add('hour', -24, current_timestamp)
ORDER BY start_time DESC;


-- ============================================================================
-- AGGREGATION & SUMMARY QUERIES
-- ============================================================================

-- Query 16: Daily summary of suspicious activity by source IP
SELECT
    sourceipaddress,
    COUNT(*) AS total_events,
    COUNT(DISTINCT eventname) AS unique_event_types,
    COUNT(DISTINCT recipientaccountid) AS accounts_accessed,
    ARRAY_AGG(DISTINCT eventname) AS event_names,
    MIN(eventtime) AS first_seen,
    MAX(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE eventtime >= date_format(date_add('hour', -24, current_timestamp), '%Y-%m-%dT%H:%i:%sZ')
AND eventname IN (
    'GetCallerIdentity',
    'DescribeInstances',
    'GetSecretValue',
    'CreateAccessKey',
    'SendCommand'
)
GROUP BY sourceipaddress
HAVING COUNT(*) > 5
ORDER BY total_events DESC;


-- Query 17: Compromised instance detection (EC2 roles with unusual API patterns)
SELECT
    useridentity.arn AS instance_role,
    COUNT(*) AS api_call_count,
    COUNT(DISTINCT eventname) AS unique_apis,
    COUNT(DISTINCT sourceipaddress) AS unique_source_ips,
    ARRAY_AGG(DISTINCT eventname) AS apis_called
FROM cloudtrail_logs
WHERE useridentity.type = 'AssumedRole'
AND useridentity.arn LIKE '%i-%'
AND eventtime >= date_format(date_add('hour', -24, current_timestamp), '%Y-%m-%dT%H:%i:%sZ')
GROUP BY useridentity.arn
HAVING COUNT(DISTINCT sourceipaddress) > 1  -- Same role from multiple IPs
ORDER BY api_call_count DESC;


-- Query 18: Timeline of potential attack progression
WITH attack_events AS (
    SELECT
        eventtime,
        sourceipaddress,
        useridentity.arn AS caller_arn,
        eventname,
        CASE
            WHEN eventname = 'GetCallerIdentity' THEN '1-Reconnaissance'
            WHEN eventname IN ('DescribeInstances', 'ListBuckets', 'ListSecrets') THEN '2-Discovery'
            WHEN eventname IN ('GetSecretValue', 'GetObject') THEN '3-Collection'
            WHEN eventname IN ('CreateAccessKey', 'AttachRolePolicy') THEN '4-Persistence'
            WHEN eventname IN ('SendCommand', 'StartSession') THEN '5-Lateral Movement'
            ELSE '6-Other'
        END AS attack_phase
    FROM cloudtrail_logs
    WHERE eventtime >= date_format(date_add('hour', -24, current_timestamp), '%Y-%m-%dT%H:%i:%sZ')
)
SELECT
    attack_phase,
    sourceipaddress,
    MIN(eventtime) AS first_occurrence,
    COUNT(*) AS event_count,
    ARRAY_AGG(DISTINCT eventname) AS events
FROM attack_events
GROUP BY attack_phase, sourceipaddress
ORDER BY attack_phase, first_occurrence;
