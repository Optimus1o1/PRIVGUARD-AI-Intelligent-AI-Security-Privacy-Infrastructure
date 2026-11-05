"""Unit tests for PRIVGUARD MCP SSRF Defense and Destination Connection Security."""

import pytest
from app.core.exceptions import MCPSSRFError
from app.mcp.ssrf import destination_validator


def test_ssrf_rejects_localhost_and_loopback():
    """Verifies that 127.0.0.1, localhost, 0.0.0.0, and ::1 are blocked."""
    blocked_urls = [
        "http://127.0.0.1:8000/mcp",
        "http://127.0.1.1:3000",
        "http://localhost:8080/mcp",
        "http://[::1]:5000/mcp",
        "http://0.0.0.0:8000",
    ]
    for url in blocked_urls:
        with pytest.raises(MCPSSRFError) as exc_info:
            destination_validator.validate_url(url)
        assert "blocked" in str(exc_info.value).lower() or "loopback" in str(exc_info.value).lower()


def test_ssrf_rejects_private_ipv4():
    """Verifies RFC 1918 private IPv4 address blocks."""
    private_urls = [
        "http://10.0.0.1/mcp",
        "http://10.254.10.1:9090",
        "http://172.16.0.10:8000",
        "http://172.31.255.254:4000",
        "http://192.168.1.1/mcp",
        "http://192.168.0.100:8080",
    ]
    for url in private_urls:
        with pytest.raises(MCPSSRFError) as exc_info:
            destination_validator.validate_url(url)
        assert "private" in str(exc_info.value).lower() or "blocked" in str(exc_info.value).lower()


def test_ssrf_rejects_cloud_metadata():
    """Verifies that AWS/GCP/Azure link-local metadata addresses are strictly blocked."""
    metadata_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://[fd00:ec2::254]/latest/meta-data/",
    ]
    for url in metadata_urls:
        with pytest.raises(MCPSSRFError) as exc_info:
            destination_validator.validate_url(url)
        assert "metadata" in str(exc_info.value).lower() or "link-local" in str(exc_info.value).lower() or "blocked" in str(exc_info.value).lower()


def test_ssrf_rejects_invalid_schemes():
    """Verifies that schemes other than http and https are rejected."""
    invalid_schemes = [
        "file:///etc/passwd",
        "ftp://ftp.example.com/data",
        "gopher://example.com",
        "dict://example.com",
        "ldap://127.0.0.1",
    ]
    for url in invalid_schemes:
        with pytest.raises(MCPSSRFError) as exc_info:
            destination_validator.validate_url(url)
        assert "scheme" in str(exc_info.value).lower()


def test_ssrf_accepts_valid_public_destinations():
    """Verifies that public, routable destinations are permitted."""
    from unittest.mock import patch
    import socket

    valid_urls = [
        "https://api.github.com/mcp",
        "https://mcp.weather-service.org/rpc",
        "https://tool-server.moon-sanctum.com/v1/mcp",
        "https://93.184.216.34/mcp",
    ]
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        for url in valid_urls:
            normalized, ips = destination_validator.validate_url(url)
            assert normalized.startswith("https://")
            assert len(ips) >= 1

