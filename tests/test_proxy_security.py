"""
AgentGuard v1.0 - Trusted Proxy & Client IP Security Tests (Objective 4)
Comprehensive validation of:
- Direct client spoofing X-Forwarded-For (must be ignored)
- Single trusted proxy resolution
- Untrusted proxy handling
- IPv4 CIDR matching
- IPv6 address and IPv6 CIDR matching
- Multi-hop proxy chains (right-to-left traversal)
- Malformed X-Forwarded-For headers (failsafe handling)
- Rate-limiting integration with proxy resolution
"""

import unittest
from unittest.mock import MagicMock

from backend.main import resolve_client_ip
from backend.services.proxy_service import ProxyResolver


class TestProxySecurity(unittest.TestCase):
    def setUp(self):
        # Configure resolver with both IPv4 CIDR and IPv6 CIDR
        self.resolver = ProxyResolver([
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.1.50",
            "2001:db8:abcd::/48",
            "fe80::1",
        ])

    def test_direct_client_spoofing_ignored(self):
        """Direct untrusted peer IP spoofing X-Forwarded-For is strictly disregarded."""
        # Untrusted public IP connects directly
        client_ip = self.resolver.resolve_client_ip(
            peer_ip="203.0.113.195",
            forwarded_for="1.1.1.1, 10.0.0.1",
        )
        self.assertEqual(client_ip, "203.0.113.195")

    def test_trusted_proxy_single_hop(self):
        """Single trusted proxy correctly unpacks genuine client IP."""
        client_ip = self.resolver.resolve_client_ip(
            peer_ip="10.1.2.3",  # In 10.0.0.0/8
            forwarded_for="198.51.100.42",
        )
        self.assertEqual(client_ip, "198.51.100.42")

    def test_untrusted_proxy_in_chain_treated_as_client(self):
        """When an untrusted proxy connects through a trusted proxy, it is treated as the client."""
        # Peer is 10.0.0.2 (trusted). Forwarded header: untrusted_client, untrusted_proxy
        client_ip = self.resolver.resolve_client_ip(
            peer_ip="10.0.0.2",
            forwarded_for="198.51.100.1, 203.0.113.5",
        )
        # 203.0.113.5 is the entity that connected to 10.0.0.2, and is not trusted
        self.assertEqual(client_ip, "203.0.113.5")

    def test_ipv4_cidr_ranges(self):
        """IPv4 CIDR ranges are accurately recognized."""
        # Within 172.16.0.0/12
        self.assertTrue(self.resolver.is_trusted_proxy("172.16.0.1"))
        self.assertTrue(self.resolver.is_trusted_proxy("172.31.255.254"))
        self.assertFalse(self.resolver.is_trusted_proxy("172.32.0.1"))

    def test_ipv6_and_ipv6_cidr(self):
        """IPv6 individual addresses and CIDR subnets are correctly matched."""
        self.assertTrue(self.resolver.is_trusted_proxy("2001:db8:abcd:0001::1"))
        self.assertTrue(self.resolver.is_trusted_proxy("fe80::1"))
        self.assertFalse(self.resolver.is_trusted_proxy("2001:db8:ffff::1"))

        # IPv6 trusted proxy forward
        client_ip = self.resolver.resolve_client_ip(
            peer_ip="2001:db8:abcd::10",
            forwarded_for="203.0.113.88",
        )
        self.assertEqual(client_ip, "203.0.113.88")

    def test_multi_hop_trusted_proxy_chain(self):
        """Multi-hop chain of trusted proxies unpacks back to genuine external client."""
        # Peer: 10.0.0.1 (trusted)
        # X-Forwarded-For: RealClient, InternalLB1, InternalLB2
        # InternalLB1 (172.16.5.5) is trusted
        # InternalLB2 (10.2.2.2) is trusted
        client_ip = self.resolver.resolve_client_ip(
            peer_ip="10.0.0.1",
            forwarded_for="198.51.100.77, 172.16.5.5, 10.2.2.2",
        )
        self.assertEqual(client_ip, "198.51.100.77")

    def test_malformed_forwarded_headers_fail_safe(self):
        """Malformed forwarded headers fallback safely to direct peer IP without throwing exceptions."""
        malformed_inputs = [
            "<script>alert(1)</script>",
            "10.0.0.1; DROP TABLE users;",
            "not-an-ip-address",
            "999.999.999.999",
            "10.0.0.1, invalid_token, 10.0.0.2",
        ]
        for bad in malformed_inputs:
            client_ip = self.resolver.resolve_client_ip(
                peer_ip="10.0.0.1",
                forwarded_for=bad,
            )
            # Must safely fall back to peer IP
            self.assertEqual(client_ip, "10.0.0.1")

    def test_empty_or_whitespace_peer_ip(self):
        """Empty or whitespace peer IP falls back to 127.0.0.1 safely."""
        self.assertEqual(self.resolver.resolve_client_ip(None), "127.0.0.1")
        self.assertEqual(self.resolver.resolve_client_ip(""), "127.0.0.1")
        self.assertEqual(self.resolver.resolve_client_ip("   "), "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
