"""SSRF defense and destination connection security for MCP endpoints.
Blocks private networks, loopback addresses, cloud metadata endpoints, and DNS rebinding attacks.
"""

import ipaddress
import socket
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from app.core.config import settings
from app.core.exceptions import MCPSSRFError

FORBIDDEN_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "169.254.169.254",
    "instance-data",
}

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),  # Current network
    ipaddress.ip_network("10.0.0.0/8"),  # Private-use (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),  # Shared Address Space (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback (RFC 1122)
    ipaddress.ip_network("169.254.0.0/16"),  # Link-Local (RFC 3927) & Cloud Metadata
    ipaddress.ip_network("172.16.0.0/12"),  # Private-use (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),  # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.168.0.0/16"),  # Private-use (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),  # Network benchmark tests
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast (RFC 5771)
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    # IPv6 blocks
    ipaddress.ip_network("::/128"),  # Unspecified
    ipaddress.ip_network("::1/128"),  # Loopback
    ipaddress.ip_network("fc00::/7"),  # Unique Local (RFC 4193)
    ipaddress.ip_network("fe80::/10"),  # Link-Local Unicast (RFC 4291)
    ipaddress.ip_network("ff00::/8"),  # Multicast (RFC 4291)
]


class MCPDestinationValidator:
    """Validates remote MCP server URLs against SSRF, internal network scans, and DNS rebinding."""

    def __init__(self, allow_loopback_in_test: bool = False):
        self.allow_loopback_in_test = allow_loopback_in_test

    def validate_url(self, url: str) -> Tuple[str, List[str]]:
        """
        Validates an MCP endpoint destination.
        Returns (canonical_url, resolved_ips).
        Raises MCPSSRFError if target points to forbidden, private, or metadata networks.
        """
        if not url or not isinstance(url, str):
            raise MCPSSRFError(destination=str(url), reason="URL cannot be empty.")

        parsed = urlparse(url.strip())
        scheme = parsed.scheme.lower()

        # Enforce HTTPS outside local dev
        if scheme not in ("http", "https"):
            raise MCPSSRFError(
                destination=url, reason=f"Unsupported protocol scheme '{scheme}'. Only HTTP/HTTPS supported."
            )

        hostname = parsed.hostname
        if not hostname:
            raise MCPSSRFError(destination=url, reason="URL does not contain a valid hostname.")

        hostname_lower = hostname.lower()

        # Check explicit forbidden hostnames
        if hostname_lower in FORBIDDEN_HOSTNAMES:
            if not self.allow_loopback_in_test or hostname_lower != "localhost":
                raise MCPSSRFError(
                    destination=url, reason=f"Hostname '{hostname}' is a protected internal destination."
                )

        # Check suffix patterns
        if any(hostname_lower.endswith(suffix) for suffix in (".internal", ".local", ".corp", ".lan")):
            if not self.allow_loopback_in_test:
                raise MCPSSRFError(destination=url, reason=f"Internal domain TLD '{hostname}' is blocked.")

        # Check if hostname itself is directly a raw IP literal
        try:
            ip_literal = ipaddress.ip_address(hostname_lower)
            self._verify_ip(ip_literal, url)
            return url, [str(ip_literal)]
        except ValueError:
            # Not an IP literal, proceed to DNS resolution
            pass

        # DNS Resolution Validation
        port = parsed.port or (443 if scheme == "https" else 80)
        try:
            addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise MCPSSRFError(destination=url, reason=f"DNS resolution failed for hostname '{hostname}': {str(e)}")

        resolved_ips: List[str] = []
        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip_str = sockaddr[0]
            resolved_ips.append(ip_str)
            ip_obj = ipaddress.ip_address(ip_str)
            self._verify_ip(ip_obj, url)

        if not resolved_ips:
            raise MCPSSRFError(destination=url, reason="No IP addresses resolved for hostname.")

        return url, resolved_ips

    def _verify_ip(self, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, original_url: str) -> None:
        """Verifies an individual IP address against blocked CIDR blocks."""
        if self.allow_loopback_in_test and (ip_obj.is_loopback or str(ip_obj) == "127.0.0.1"):
            return

        # Check native attributes
        if ip_obj.is_loopback:
            raise MCPSSRFError(destination=original_url, reason=f"Resolved IP {ip_obj} is a loopback address.")
        if ip_obj.is_private:
            raise MCPSSRFError(destination=original_url, reason=f"Resolved IP {ip_obj} is a private network address.")
        if ip_obj.is_link_local:
            raise MCPSSRFError(
                destination=original_url, reason=f"Resolved IP {ip_obj} is a link-local / cloud metadata address."
            )
        if ip_obj.is_multicast:
            raise MCPSSRFError(destination=original_url, reason=f"Resolved IP {ip_obj} is a multicast address.")
        if ip_obj.is_reserved or ip_obj.is_unspecified:
            raise MCPSSRFError(
                destination=original_url, reason=f"Resolved IP {ip_obj} is a reserved/unspecified address."
            )

        # Check against comprehensive CIDRs
        for net in BLOCKED_IP_NETWORKS:
            if ip_obj in net:
                raise MCPSSRFError(
                    destination=original_url, reason=f"Resolved IP {ip_obj} falls in blocked CIDR {net}."
                )


# Global validator instances
destination_validator = MCPDestinationValidator(allow_loopback_in_test=False)
test_destination_validator = MCPDestinationValidator(allow_loopback_in_test=True)
