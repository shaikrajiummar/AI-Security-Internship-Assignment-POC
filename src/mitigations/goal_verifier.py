"""
ASI01 Mitigation: GoalVerifier
Defense against Agent Goal Hijack.
Techniques:
1. Invariant checking: Compares candidate tool actions against immutable system mission
2. Detects antagonistic role adoption (e.g. RobinHoodBot, DataExfiltrator)
3. Evaluates tool target alignment with humanitarian scope
"""
from typing import Dict, Any, Tuple

class GoalVerifier:
    HIJACK_INDICATORS = [
        "disregard",
        "new objective",
        "robinhoodbot",
        "exfiltrat",
        "sole objective",
        "transfer all donor records",
        "bypass relief",
        "external auditor"
    ]

    @classmethod
    def verify_alignment(
        cls,
        primary_mission: str,
        tool_name: str,
        tool_args: Dict[str, Any],
        thought: str
    ) -> Tuple[bool, str]:
        """
        Validates that candidate action does not divert agent from primary humanitarian mission.
        """
        combined_text = f"{tool_name} {str(tool_args)} {thought}".lower()

        for indicator in cls.HIJACK_INDICATORS:
            if indicator in combined_text:
                return False, f"Action violates primary mission invariant: detected goal divergence keyword '{indicator}'."

        # If sending email, ensure subject/body aligns with relief mission
        if tool_name == "send_email":
            subj = str(tool_args.get("subject", "")).lower()
            if "exfiltrat" in subj or "donor database" in subj:
                return False, "Goal Hijack detected: Attempting to email unauthorized database dumps."

        return True, "Aligned with primary mission."
