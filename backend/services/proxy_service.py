"""
AgentGuard Trusted Proxy & Client IP Resolution Service (v1.0)
Provides robust, deterministic client IP resolution using standard ipaddress primitives.

SECURITY INVARIANTS:
1. Headers (X-Forwarded-For, X-Forwarded-Proto, Forwarded) are NEVER trusted unless
   the immediate peer IP belongs to the configured set of trusted proxies.
2. Direct client spoofing of X-Forwarded-For is strictly thwarted: when the direct peer
   is not in the trusted proxy set, the peer IP itself is returned as the client IP.
3. Supports individual IPv4, IPv4 CIDR, individual IPv6, and IPv6 CIDR ranges.
4. Deterministic proxy chain traversal: traverses right-to-left from the trusted perimeter,
   stopping at the first untrusted IP (the genuine client IP).
5. Malformed forwarded headers fail safe without crashing, falling back to the direct peer IP.
"""

import ipaddress
import logging
from typing import List, Optional, Set, Union

logger = logging.getLogger("agentguard.proxy")


class ProxyResolver:
    """
    Evaluates peer IP addresses against configured trusted proxy networks and safely
    resolves the true client IP from forwarded header chains.
    """

    def __init__(self, trusted_proxies: Optional[List[str]] = None):
        self.trusted_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        self._raw_proxies = trusted_proxies or []
        self._compile_trusted_proxies(self._raw_proxies)

    def _compile_trusted_proxies(self, proxies: List[str]) -> None:
        """Parses individual IPs and CIDR blocks into ipaddress Network objects."""
        self.trusted_networks = []
        for entry in proxies:
            entry = entry.strip()
            if not entry:
                continue
            try:
                # strict=False allows host bits set in CIDR notations like 192.168.1.5/24
                net = ipaddress.ip_network(entry, strict=False)
                self.trusted_networks.append(net)
            except ValueError as exc:
                logger.warning("Invalid trusted proxy definition '%s' disregarded: %s", entry, exc)

    def is_trusted_proxy(self, ip_str: Optional[str]) -> bool:
        """
        Returns True if ip_str is a valid IP address belonging to any configured trusted network.
        """
        if not ip_str or not self.trusted_networks:
            return False
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            return any(ip_obj in net for net in self.trusted_networks)
        except ValueError:
            return False

    def resolve_client_ip(
        self,
        peer_ip: Optional[str],
        forwarded_for: Optional[str] = None,
    ) -> str:
        """
        Resolves the genuine client IP address.

        Trust Model:
        - If peer_ip is None or empty: defaults to '127.0.0.1'.
        - If peer_ip is NOT a trusted proxy: returns peer_ip directly. Any X-Forwarded-For
          header is completely discarded as untrusted client data.
        - If peer_ip IS a trusted proxy:
          - Inspects X-Forwarded-For header containing 'client, proxy1, proxy2'.
          - Traverses the chain from right to left (closest proxy to outermost client).
          - Skips intermediate IPs that also belong to the trusted proxy set.
          - The first untrusted IP encountered is returned as the genuine client IP.
          - If all IPs in the chain are trusted, the leftmost valid IP is returned.
          - If the header is malformed, returns peer_ip.
        """
        safe_peer = peer_ip.strip() if (peer_ip and peer_ip.strip()) else "127.0.0.1"

        # Step 1: Direct peer is not trusted -> header must be ignored
        if not self.is_trusted_proxy(safe_peer):
            return safe_peer

        # Step 2: Peer is trusted -> safely inspect X-Forwarded-For
        if not forwarded_for or not forwarded_for.strip():
            return safe_peer

        # Parse hops: X-Forwarded-For: client, proxy1, proxy2
        raw_hops = [h.strip() for h in forwarded_for.split(",") if h.strip()]
        if not raw_hops:
            return safe_peer

        # Step 3: Traverse right-to-left
        # In a valid chain, the direct peer connected to us; the preceding proxy connected to it.
        # We traverse backwards looking for the first IP outside the trusted network perimeter.
        valid_hops: List[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for hop in raw_hops:
            try:
                valid_hops.append(ipaddress.ip_address(hop))
            except ValueError:
                logger.warning("Malformed IP in X-Forwarded-For discarded: '%s'", hop)
                # Malformed IP detected in chain: stop and fall back safely
                return safe_peer

        # Right-to-left traversal
        for hop_ip in reversed(valid_hops):
            is_hop_trusted = any(hop_ip in net for net in self.trusted_networks)
            if not is_hop_trusted:
                return str(hop_ip)

        # If all hops in X-Forwarded-For were trusted, the outermost client is the first hop
        return str(valid_hops[0])


def get_default_proxies() -> List[str]:
    try:
        from backend.config import TRUSTED_PROXIES
        return TRUSTED_PROXIES
    except Exception:
        return ["127.0.0.1", "::1"]


# Global default instance
proxy_resolver = ProxyResolver(get_default_proxies())


def configure_trusted_proxies(proxies: List[str]) -> ProxyResolver:
    """Configures and returns the global ProxyResolver instance."""
    global proxy_resolver
    proxy_resolver = ProxyResolver(proxies)
    return proxy_resolver
