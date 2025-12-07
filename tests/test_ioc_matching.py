"""IOC pattern matching tests."""
import re
import pytest


class TestNetworkIOCs:
    """Test network IOC patterns."""

    def test_malicious_ips_valid_format(self, ioc_config):
        """Verify all IPs are valid IPv4 format."""
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        for entry in ioc_config['network_iocs']['malicious_ips']:
            ip = entry['ip']
            assert ip_pattern.match(ip), f"Invalid IP format: {ip}"

    def test_known_c2_ips_present(self, ioc_config):
        """Verify known C2 IPs are in the list."""
        ips = [e['ip'] for e in ioc_config['network_iocs']['malicious_ips']]
        known_c2 = ['93.123.109.247', '45.77.33.136', '194.246.84.13']
        for ip in known_c2:
            assert ip in ips, f"Known C2 IP {ip} not in IOC list"


class TestHTTPIOCs:
    """Test HTTP IOC patterns."""

    def test_header_names_lowercase(self, ioc_config):
        """Verify header names are lowercase for consistency."""
        headers = ioc_config['http_iocs']['headers']
        for header in headers:
            name = header['name']
            assert name == name.lower(), f"Header should be lowercase: {name}"

    def test_payload_patterns_compile(self, ioc_config):
        """Verify all regex patterns compile."""
        for severity in ['critical', 'high']:
            patterns = ioc_config['http_iocs']['payload_patterns'].get(severity, [])
            for p in patterns:
                try:
                    re.compile(p['pattern'])
                except re.error as e:
                    pytest.fail(f"Invalid regex '{p['pattern']}': {e}")

    def test_critical_patterns_detect_exploit(self, ioc_config):
        """Verify critical patterns match known exploits."""
        critical = ioc_config['http_iocs']['payload_patterns']['critical']
        patterns = [re.compile(p['pattern'], re.IGNORECASE) for p in critical]

        exploits = [
            '__proto__:then',
            'process.mainModule.require',
            'child_process',
            'execSync',
        ]

        for exploit in exploits:
            matched = any(p.search(exploit) for p in patterns)
            assert matched, f"No pattern matched exploit: {exploit}"
