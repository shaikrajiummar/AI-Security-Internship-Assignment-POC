"""
Centralized Mitigation Manager.
Allows toggling individual mitigations or collective defense layers.
"""
from typing import Dict, Any
from src.mitigations.prompt_guard import PromptGuard
from src.mitigations.data_scrubber import DataScrubber
from src.mitigations.hitl_gate import HITLGate
from src.mitigations.context_filter import ContextFilter
from src.mitigations.output_encoder import OutputEncoder
from src.mitigations.goal_verifier import GoalVerifier
from src.mitigations.tool_jail import ToolJail
from src.mitigations.rbac_guard import RBACGuard
from src.mitigations.code_sandbox import CodeSandbox
from src.mitigations.memory_firewall import MemoryFirewall

class MitigationManager:
    def __init__(self, all_enabled: bool = False):
        self.flags = {
            "LLM01": all_enabled,
            "LLM02": all_enabled,
            "LLM03": all_enabled,
            "LLM08": all_enabled,
            "LLM10": all_enabled,
            "ASI01": all_enabled,
            "ASI02": all_enabled,
            "ASI03": all_enabled,
            "ASI05": all_enabled,
            "ASI06": all_enabled,
        }

    def set_all(self, enabled: bool):
        for k in self.flags:
            self.flags[k] = enabled

    def set_risk(self, risk_id: str, enabled: bool):
        if risk_id in self.flags:
            self.flags[risk_id] = enabled

    def is_enabled(self, risk_id: str) -> bool:
        return self.flags.get(risk_id, False)

    def get_status_summary(self) -> Dict[str, bool]:
        return dict(self.flags)
