# React2Shell Threat Intelligence Report

**CVE-2025-55182 & CVE-2025-66478**
**Report Date:** 2025-12-06
**Classification:** TLP:WHITE
**Severity:** CRITICAL (CVSS 10.0)

---

## Executive Summary

React2Shell is a critical remote code execution (RCE) vulnerability affecting React Server Components and Next.js frameworks. The vulnerability (CVE-2025-55182) enables unauthenticated attackers to execute arbitrary code on vulnerable servers through unsafe deserialization of the React "Flight" protocol. Active exploitation began within hours of public disclosure on December 3, 2025, with multiple China-nexus threat groups and opportunistic attackers targeting internet-facing applications.

**Key Risk Factors:**
- CVSS Score: 10.0 (Maximum severity)
- No authentication required
- Default configurations vulnerable
- Active exploitation in the wild
- State-sponsored and criminal threat actors involved

---

## Vulnerability Details

### CVE-2025-55182 (React Server Components)

| Attribute | Value |
|-----------|-------|
| CVE ID | CVE-2025-55182 |
| CVSS Score | 10.0 Critical |
| CWE | CWE-502 (Deserialization of Untrusted Data) |
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | None |
| User Interaction | None |

**Root Cause:** Prototype pollution via unsafe deserialization in React's "Flight" protocol. The vulnerability exploits the `.then` property manipulation during object resolution, enabling arbitrary code execution through `process.mainModule.require('child_process').execSync()`.

**Affected Packages:**
- react-server-dom-webpack: 19.0.0, 19.1.0, 19.1.1, 19.2.0
- react-server-dom-parcel: 19.0.0, 19.1.0, 19.1.1, 19.2.0
- react-server-dom-turbopack: 19.0.0, 19.1.0, 19.1.1, 19.2.0

### CVE-2025-66478 (Next.js)

| Attribute | Value |
|-----------|-------|
| CVE ID | CVE-2025-66478 |
| CVSS Score | 10.0 Critical |
| Relationship | Downstream impact of CVE-2025-55182 |

**Affected Versions:**
- Next.js 15.0.4, 15.1.8, 15.2.5, 15.3.5, 15.4.7, 15.5.6, 16.0.6
- Next.js 14.3.0-canary.77 and later canary builds

---

## Threat Actor Attribution

### Earth Lamia (China-nexus)
- **First Observed:** December 3, 2025 (within hours of disclosure)
- **Attribution:** China state-nexus
- **Tactics:** Automated scanning with rapid exploitation
- **Source:** AWS Threat Intelligence

### Jackpot Panda (China-nexus)
- **First Observed:** December 3, 2025
- **Attribution:** China state-nexus
- **Tactics:** Systematic scanning of internet-facing targets
- **Source:** AWS Threat Intelligence

### Ransomware-as-a-Service Operators
- **First Observed:** December 5, 2025
- **Attribution:** Criminal enterprises
- **Tactics:** Webshell deployment for later ransomware staging
- **Expected Breakout Time:** 2-14 days post-compromise

---

## Indicators of Compromise

### Network Indicators

#### Malicious IP Addresses (C2 Infrastructure)

| IP Address | Port | Context | Confidence |
|------------|------|---------|------------|
| 93.123.109.247 | 8000 | C2 Server | High |
| 45.77.33.136 | 8080 | C2 Server | High |
| 194.246.84.13 | 2045 | C2 Server | High |
| 45.32.158.54 | - | Scanner | Medium |
| 46.36.37.85 | 12000 | Payload Staging | High |
| 144.202.115.234 | 80 | Payload Hosting | Medium |
| 141.11.240.103 | 45178 | C2 Server | High |
| 23.235.188.3 | 652 | PowerShell Stager | High |
| 162.215.170.26 | 3000 | Secondary Payload | Medium |

#### Malicious Domains

| Domain | Category | Confidence |
|--------|----------|------------|
| ceye.io | DNS Exfiltration | High |
| dnslog.cn | DNS Exfiltration | High |
| *.oastify.com | Burp Collaborator | Medium |
| sapo.shk0x.net | C2 | High |
| xwpoogfunv.zaza.eu.org | C2 | High |
| *.a02.lol | C2 | Medium |
| *.c3pool.com | Cryptomining Pool | High |

#### Suspicious Ports

| Port | Usage |
|------|-------|
| 652 | PowerShell stager |
| 2045 | Custom C2 |
| 8000/8080 | Alternative HTTP C2 |
| 12000/45178 | Custom C2 |
| 3333/5555/14433/14444 | Cryptomining |

### HTTP Indicators

#### Malicious Headers
- `Next-Action: *` - RSC exploitation attempt
- `rsc-action-id: *` - RSC action identifier

#### Payload Patterns
- `$ACTION_0:0` - RSC action parameter exploitation
- `$ACTION_REF_0` - RSC action reference
- `__proto__:then` - Prototype pollution
- `process.mainModule.require` - Node.js module access
- `child_process` / `execSync` - Command execution
- `resolved_model` - Flight protocol indicator

#### User Agents
- `Go-http-client/1.1` - Primary scanner
- `Assetnote/1.0.0` - Security scanner
- `aiohttp` / `python-requests` - Automated tools

### Host-Based Indicators

#### Process Execution Patterns
```
# Windows
node.exe → powershell.exe (with -enc flag)
node.exe → cmd.exe

# Linux
node → sh/bash/dash
curl|sh or wget|bash patterns
```

#### File System Indicators
- `/tmp/*.sh` - Shell scripts
- `/tmp/xmrig*` - Cryptominer
- `/_bk` - React2Shell webshell
- `.env*` file access - Credential harvesting

#### Environment Variables Targeted
- `*KEY*`, `*SECRET*`, `*TOKEN*`
- `*PASSWORD*`, `*PASS*`
- `*DATABASE*`
- `AWS_*`, `AZURE_*`, `GCP_*`

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Usage |
|-------------|------|--------|-------|
| T1190 | Exploit Public-Facing Application | Initial Access | Primary exploitation vector |
| T1059.007 | JavaScript | Execution | Node.js command execution |
| T1105 | Ingress Tool Transfer | Command & Control | Download secondary payloads |
| T1552.001 | Credentials In Files | Credential Access | .env file harvesting |
| T1021 | Remote Services | Lateral Movement | SSM, SSH access |
| T1078 | Valid Accounts | Persistence | Stolen credential use |
| T1496 | Resource Hijacking | Impact | Cryptomining deployment |
| T1486 | Data Encrypted for Impact | Impact | Ransomware (expected) |

---

## Attack Timeline

| Date/Time (UTC) | Event |
|-----------------|-------|
| Nov 29, 2025 | Responsible disclosure to React Team |
| Dec 3, 2025 ~10:00 | Public disclosure and patch release |
| Dec 3, 2025 ~22:00 | First scanning activity detected |
| Dec 4, 2025 early | Non-functional PoC released |
| Dec 4, 2025 ~21:04 | Working PoC published |
| Dec 4, 2025 ~23:00 | Sustained scanning/exploitation begins |
| Dec 5, 2025 | Official PoC released, 800+ scanning IPs observed |
| Dec 5, 2025 | Fastly reports 2,775% increase in attack traffic |

---

## Post-Exploitation Indicators

### Immediate Actions (Automated Phase)
1. Environment variable exfiltration via `wget --post-data`
2. DNS exfiltration to ceye.io/dnslog.cn
3. Credential harvesting from .env files
4. Webshell installation at `/_bk` endpoint
5. Cryptominer deployment (XMRig/C3Pool)

### Expected Manual Phase (2-14 days)
1. C2 connection via webshell
2. Lateral movement using stolen credentials
3. Privilege escalation
4. Data exfiltration
5. Ransomware deployment

---

## AWS-Specific Detection

### CloudTrail Events to Monitor
- `GetCallerIdentity` - First recon after cred theft
- `DescribeInstanceAttribute` (userData) - Metadata harvesting
- `SendCommand` / `StartSession` - Lateral movement
- `CreateAccessKey` - Persistence
- `GetSecretValue` - Secrets access

### GuardDuty Findings
- `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`
- `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS`
- `Trojan:EC2/DNSDataExfiltration`
- `CryptoCurrency:EC2/BitcoinTool.B!DNS`
- `Behavior:EC2/NetworkPortUnusual`

### AWS WAF Protection
- Enable `AWSManagedRulesKnownBadInputsRuleSet` (v1.24+)
- Custom rules for `Next-Action` header blocking
- Prototype pollution pattern detection

---

## Remediation

### Immediate Actions (Priority 0)

1. **Patch Applications**
   - React: Update to 19.0.1, 19.1.2, or 19.2.1
   - Next.js: Update to 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, or 16.0.7

2. **Enable WAF Protection**
   - AWS WAF: Enable managed rules
   - Cloudflare: Automatic protection enabled
   - Custom rules for header blocking

3. **Network Controls**
   - Block known C2 IPs
   - Implement egress filtering
   - Isolate DMZ servers

### Short-Term Actions (24-48 hours)

1. **Threat Hunting**
   - Review logs for IOCs
   - Check for webshell indicators
   - Verify credential integrity

2. **Credential Rotation**
   - Rotate all exposed secrets
   - Review IAM access patterns
   - Check for new access keys

3. **Enhanced Monitoring**
   - Enable GuardDuty (if not enabled)
   - Deploy custom detection rules
   - Increase log retention

---

## References

- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components/)
- [AWS Security Blog](https://aws.amazon.com/blogs/security/china-nexus-cyber-threat-groups-rapidly-exploit-react2shell-vulnerability-cve-2025-55182/)
- [GreyNoise Blog](https://www.greynoise.io/blog/cve-2025-55182-react2shell-opportunistic-exploitation-in-the-wild-what-the-greynoise-observation-grid-is-seeing-so-far)
- [Bitdefender Advisory](https://www.bitdefender.com/en-us/blog/businessinsights/advisory-react2shell-critical-unauthenticated-rce-in-react-cve-2025-55182)
- [Tenable FAQ](https://www.tenable.com/blog/react2shell-cve-2025-55182-react-server-components-rce)
- [Official React2Shell Site](https://react2shell.com/)
- [Datadog IOC Repository](https://github.com/DataDog/indicators-of-compromise/tree/main/react-CVE-2025-55182)

---

*Report prepared by Security Operations Team*
*For internal use - TLP:WHITE for external sharing*
