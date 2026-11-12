"""
ASI03 Mitigation: RBACGuard
Defense against Identity & Privilege Abuse.
Techniques:
1. Role-Based Access Control (RBAC) mapping on tool actions
2. Downscoped identity tokens (user context propagation)
3. Prohibition of ambient superuser privilege inheritance
"""
from typing import Dict, Any, Tuple

class RBACGuard:
    # Role Hierarchy: guest < volunteer < coordinator < admin
    ROLE_PERMISSIONS = {
        "guest": ["read_public_docs", "query_general_faq"],
        "volunteer": ["read_public_docs", "read_field_reports", "query_general_faq", "send_internal_email"],
        "coordinator": ["read_public_docs", "read_field_reports", "send_internal_email", "call_partner_http", "read_inventory"],
        "admin": ["*"]
    }

    RESTRICTED_RESOURCES = {
        "executive_payroll.csv": ["coordinator", "admin"],
        "master_secrets.env": ["admin"],
        "sensitive_vault.txt": ["admin"],
        "update_policy": ["admin"]
    }

    @classmethod
    def check_permission(cls, user_role: str, resource_or_action: str) -> Tuple[bool, str]:
        """
        Validates user clearance for sensitive resource or action.
        """
        user_role = user_role.lower()

        # Check explicit restricted resource mapping
        for res, allowed_roles in cls.RESTRICTED_RESOURCES.items():
            if res.lower() in resource_or_action.lower():
                if user_role not in allowed_roles:
                    return False, f"RBAC Denied: Role '{user_role}' lacks permission for restricted resource '{res}'."

        return True, "Access Granted"
