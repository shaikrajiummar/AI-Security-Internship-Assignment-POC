"""
ASI02 Mitigation: ToolJail
Defense against Tool Misuse (Confused Deputy, Path Traversal, SSRF).
Techniques:
1. Canonical Path Jail (enforcing path stays within sandbox boundary)
2. SSRF Protection (RFC1918, RFC3927 cloud metadata, loopback IP filtering)
3. Outbound domain allowlisting
"""
import os
import ipaddress
import urllib.parse
from pathlib import Path
from typing import Tuple, Dict, Any

class ToolJail:
    ALLOWED_EMAIL_DOMAINS = ["ygf-ngo.fake", "ygf-ngo.org"]
    ALLOWED_HTTP_DOMAINS = ["api.ygf-ngo.org", "weather-service.fake", "reliefweb.fake"]

    @classmethod
    def validate_file_path(cls, requested_path: str, base_dir: Path) -> Tuple[bool, str]:
        """
        Ensures requested file path does not escape base directory.
        """
        try:
            resolved = (base_dir / requested_path).resolve()
            resolved.relative_to(base_dir.resolve())
            return True, str(resolved)
        except ValueError:
            return False, f"Path traversal attack detected: '{requested_path}' escapes jail '{base_dir}'."

    @classmethod
    def validate_http_url(cls, url: str) -> Tuple[bool, str]:
        """
        Validates outbound URL against SSRF and metadata attacks.
        """
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""

        if not hostname:
            return False, "Invalid URL: missing hostname."

        # Check metadata & loopback directly
        if hostname in ["169.254.169.254", "localhost", "127.0.0.1", "::1"]:
            return False, f"SSRF blocked: Access to internal/metadata target '{hostname}' forbidden."

        # Check IP range
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False, f"SSRF blocked: IP '{hostname}' belongs to restricted network space."
        except ValueError:
            # Domain check
            if hostname not in cls.ALLOWED_HTTP_DOMAINS:
                return False, f"Access blocked: Hostname '{hostname}' not in HTTP allowlist."

        return True, "URL validated."

    @classmethod
    def validate_email_recipient(cls, recipient: str) -> Tuple[bool, str]:
        """
        Validates recipient domain against authorized NGO domains.
        """
        domain = recipient.split("@")[-1].lower() if "@" in recipient else ""
        if domain not in cls.ALLOWED_EMAIL_DOMAINS:
            return False, f"Outbound email to domain '{domain}' is unauthorized."
        return True, "Recipient validated."
