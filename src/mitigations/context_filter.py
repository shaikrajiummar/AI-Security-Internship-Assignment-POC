"""
LLM08 Mitigation: ContextFilter
Defense against Hidden Context Exposure.
Techniques:
1. Strips HTML/Markdown developer comments (<!-- ... -->)
2. Redacts internal RAG chunk IDs, tenant identifiers, and internal tags
3. Enforces metadata minimization prior to prompt assembly
"""
import re

class ContextFilter:
    METADATA_PATTERNS = [
        # HTML/XML comment tags (often holding developer notes or hidden prompts)
        r"<!--[\s\S]*?-->",
        # Internal chunk identifiers
        r"CHUNK-[0-9A-Za-z_-]+",
        # Developer annotations
        r"(?i)DEVELOPER_NOTE_INTERNAL_ONLY:.*",
        r"(?i)CONFIDENTIAL.*MERGER.*",
        # Internal environment variable declarations in knowledge snippets
        r"ENV_VAR_[A-Za-z0-9_]+=[^\s\n]+",
    ]

    @classmethod
    def sanitize_context(cls, raw_context: str) -> str:
        """
        Cleans retrieved RAG snippets of internal comments and hidden metadata.
        """
        cleaned = raw_context
        for pattern in cls.METADATA_PATTERNS:
            cleaned = re.sub(pattern, "", cleaned)
        
        # Clean up multi-line whitespace
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
        return cleaned.strip()
