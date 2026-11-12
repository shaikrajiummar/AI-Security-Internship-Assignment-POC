"""
LLM03 Mitigation: HITLGate
Defense against Excessive Agency.
Techniques:
1. Human-In-The-Loop approval requirement for high-impact actions
2. Scope limiting on autonomous tool execution
3. Interception of irreversible operations (mass communication, storage wiping)
"""
from typing import Dict, Any, Tuple

class HITLGate:
    HIGH_IMPACT_ACTIONS = [
        "delete_storage",
        "mass_email",
        "external_transfer",
        "permission_grant",
        "rmtree"
    ]

    @classmethod
    def check_authorization(
        cls,
        action_name: str,
        action_args: Dict[str, Any],
        is_human_approved: bool = False
    ) -> Tuple[bool, str]:
        """
        Enforces human verification before allowing irreversible or excessive actions.
        """
        # Detect high impact characteristics
        is_high_impact = False

        if action_name in cls.HIGH_IMPACT_ACTIONS:
            is_high_impact = True

        if action_name == "send_email":
            rec = str(action_args.get("recipient", "")).lower()
            if not rec.endswith("@ygf-ngo.fake") and not rec.endswith("@ygf-ngo.org"):
                is_high_impact = True

        if action_name == "execute_script":
            code = str(action_args.get("code", "")).lower()
            if any(term in code for term in ["shutil", "rmtree", "delete", "unlink", "drop table"]):
                is_high_impact = True

        if is_high_impact and not is_human_approved:
            return False, f"Autonomous execution blocked: '{action_name}' requires Human-In-The-Loop approval."

        return True, "Authorized"
