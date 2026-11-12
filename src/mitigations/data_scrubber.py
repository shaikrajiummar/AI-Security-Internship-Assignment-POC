"""
LLM02 Mitigation: DataScrubber
Defense against Sensitive Information Disclosure.
Techniques:
1. Regex pattern scrubbing for PII, credit cards, and API keys
2. Canary token & CTF flag neutralization (e.g., SECRET-FLAG-123, FLAG{...})
3. System prompt secret containment
"""
import re
from src.config import CANARY_TOKEN, DONOR_FLAG, INTERNAL_API_KEY

class DataScrubber:
    SENSITIVE_PATTERNS = [
        # Credit Card Numbers
        (r"\b(?:\d{4}[ -]?){3}\d{4}\b", "[REDACTED_PAYMENT_CARD]"),
        # API Keys & Secret Variables
        (r"ygf_secret_api_key_[a-zA-Z0-9]+", "[REDACTED_API_KEY]"),
        (r"k8s_secret_[a-zA-Z0-9_]+", "[REDACTED_INFRA_SECRET]"),
        (r"ENV_VAR_VAULT_KEY=[^\s]+", "ENV_VAR_VAULT_KEY=[REDACTED]"),
        # Canary Tokens & Flags
        (re.escape(CANARY_TOKEN), "[REDACTED_CANARY_TOKEN]"),
        (r"FLAG\{[a-zA-Z0-9_]+\}", "[REDACTED_CONFIDENTIAL_FLAG]"),
        (re.escape(INTERNAL_API_KEY), "[REDACTED_API_KEY]"),
    ]

    @classmethod
    def scrub(cls, text: str) -> str:
        """
        Scans and sanitizes outgoing text to prevent disclosure of secrets.
        """
        scrubbed = text
        for pattern, replacement in cls.SENSITIVE_PATTERNS:
            scrubbed = re.sub(pattern, replacement, scrubbed)
        return scrubbed
