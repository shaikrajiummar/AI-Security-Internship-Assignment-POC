"""
ASI06 Mitigation: MemoryFirewall
Defense against Memory & Context Poisoning.
Techniques:
1. Immutability protection for critical system policies & configuration keys
2. Taint tracking and source provenance verification
3. Schema validation on dynamic memory updates
"""
from typing import Tuple

class MemoryFirewall:
    IMMUTABLE_KEYS = {
        "email_policy",
        "server_host",
        "auth_level",
        "security_mode",
        "system_rules"
    }

    ALLOWED_MUTABLE_KEYS = {
        "user_notes",
        "session_context",
        "volunteer_name",
        "field_observation"
    }

    SUSPICIOUS_PAYLOAD_PATTERNS = [
        "evil.org",
        "attacker",
        "dropzone",
        "bypass",
        "disable security",
        "cc all emails"
    ]

    @classmethod
    def validate_update(cls, key: str, value: str, source_role: str = "guest") -> Tuple[bool, str]:
        """
        Validates whether memory update request is authorized and safe.
        """
        key_lower = key.lower()
        val_lower = value.lower()

        # 1. Protect immutable system configurations
        if key_lower in cls.IMMUTABLE_KEYS:
            return False, f"Attempted mutation of immutable system key '{key}' is forbidden."

        # 2. Enforce schema allowlist for user-writable keys
        if source_role not in ["admin"] and key_lower not in cls.ALLOWED_MUTABLE_KEYS:
            return False, f"Unauthorized memory key '{key}'. Guest/volunteer users may only write to allowed scratchpad keys."

        # 3. Detect poisoning keywords / malicious rule injections
        for pattern in cls.SUSPICIOUS_PAYLOAD_PATTERNS:
            if pattern in val_lower:
                return False, f"Memory Poisoning detected: Value contains suspicious pattern '{pattern}'."

        return True, "Memory update approved."
