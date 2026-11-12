"""
Agent Memory Management module.
Supports working memory and long-term key-value storage.
Vulnerable to ASI06 (Memory & Context Poisoning) when unvalidated.
"""
from typing import Dict, Any, Tuple

class AgentMemory:
    def __init__(self, mitigation_active: bool = False):
        self.mitigation_active = mitigation_active
        # Immutable system baseline policies
        self.system_policies = {
            "email_policy": "Send only to registered @ygf-ngo.fake domains",
            "server_host": "api.ygf-ngo.org",
            "auth_level": "standard"
        }
        # Dynamic working memory
        self.user_memory: Dict[str, Dict[str, Any]] = {}

    def update_memory(self, key: str, value: str, source_role: str = "guest") -> Tuple[bool, str]:
        """
        Updates persistent or working memory.
        ASI06 Vulnerability: An untrusted prompt overwrites core policies or poisons memory.
        """
        if self.mitigation_active:
            from src.mitigations.memory_firewall import MemoryFirewall
            firewall = MemoryFirewall()
            allowed, reason = firewall.validate_update(key, value, source_role)
            if not allowed:
                return False, f"MemoryFirewall Blocked: {reason}"

        # If vulnerable, allow overwriting system_policies or injecting tainted rules
        if key in self.system_policies and not self.mitigation_active:
            self.system_policies[key] = value
            return True, f"System policy '{key}' overwritten with '{value}'."

        self.user_memory[key] = {"value": value, "source": source_role}
        return True, f"Stored '{key}' in memory."

    def get_memory(self, key: str) -> str:
        if key in self.system_policies:
            return self.system_policies[key]
        if key in self.user_memory:
            return self.user_memory[key]["value"]
        return "Key not found."
