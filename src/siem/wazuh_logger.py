"""
Wazuh SIEM Event Exporter for LLM and Agentic AI Security Alerts.
Converts evaluation events and runtime violations into Wazuh/OSSEC JSON schema.
"""
import json
import time
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from src.config import LOGS_DIR, SUBMISSIONS_DIR

class WazuhSecurityLogger:
    RULE_MAPPING = {
        "LLM01": {"rule_id": 100101, "level": 10, "desc": "OWASP LLM01: Prompt Injection Attempt Detected", "mitre": "T1059"},
        "LLM02": {"rule_id": 100102, "level": 9,  "desc": "OWASP LLM02: Sensitive Information Disclosure Probing", "mitre": "T1005"},
        "LLM03": {"rule_id": 100103, "level": 11, "desc": "OWASP LLM03: Excessive Agency / Autonomous High-Impact Action", "mitre": "T1078"},
        "LLM08": {"rule_id": 100108, "level": 8,  "desc": "OWASP LLM08: Hidden Context / Metadata Exposure", "mitre": "T1592"},
        "LLM10": {"rule_id": 100110, "level": 9,  "desc": "OWASP LLM10: Improper Output Handling (XSS/Markdown Injection)", "mitre": "T1189"},
        "ASI01": {"rule_id": 100201, "level": 12, "desc": "OWASP ASI01: Agent Goal Hijack Attempt", "mitre": "T1566"},
        "ASI02": {"rule_id": 100202, "level": 11, "desc": "OWASP ASI02: Agent Tool Misuse (Traversal/SSRF/Data Exfiltration)", "mitre": "T1055"},
        "ASI03": {"rule_id": 100203, "level": 10, "desc": "OWASP ASI03: Identity & Privilege Abuse / Elevation", "mitre": "T1068"},
        "ASI05": {"rule_id": 100205, "level": 13, "desc": "OWASP ASI05: Unexpected Code Execution / RCE in Sandbox", "mitre": "T1203"},
        "ASI06": {"rule_id": 100206, "level": 10, "desc": "OWASP ASI06: Memory & Context Poisoning Attempt", "mitre": "T1565"},
    }

    def __init__(self, log_path: Optional[Path] = None):
        self.log_path = log_path or (LOGS_DIR / "wazuh_alerts.json")
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.alerts = []

    def log_event(
        self,
        risk_id: str,
        test_id: str,
        model_name: str,
        result_status: str,
        prompt: str,
        evidence: str,
        blocked_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Formats a security event as a Wazuh JSON alert.
        """
        rule_meta = self.RULE_MAPPING.get(risk_id, {
            "rule_id": 100999, "level": 5, "desc": f"OWASP Risk Detected: {risk_id}", "mitre": "T1000"
        })

        timestamp = datetime.now(timezone.utc).isoformat()

        alert = {
            "timestamp": timestamp,
            "agent": {
                "id": "007",
                "name": "ygf-llm-security-node",
                "ip": "10.0.1.50"
            },
            "manager": {
                "name": "wazuh.ygf-ngo.internal"
            },
            "rule": {
                "id": str(rule_meta["rule_id"]),
                "level": rule_meta["level"] if result_status == "Succeeded" else max(3, rule_meta["level"] - 4),
                "description": f"{rule_meta['desc']} [{result_status}]",
                "groups": ["owasp", "llm_security", "agentic_security"],
                "mitre": {
                    "id": [rule_meta["mitre"]],
                    "tactic": ["Defense Evasion", "Initial Access", "Execution"]
                }
            },
            "data": {
                "risk_id": risk_id,
                "test_id": test_id,
                "model_tested": model_name,
                "outcome": result_status,
                "blocked_by": blocked_by or "N/A",
                "prompt_snippet": prompt[:120],
                "evidence_summary": evidence[:120],
                "framework_version": "OWASP-LLM-2026 / OWASP-ASI-2026"
            }
        }

        self.alerts.append(alert)

        # Append JSON lines to file
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert) + "\n")

        return alert

    def export_summary(self, target_path: Optional[Path] = None):
        """Exports all recorded alerts as a JSON array."""
        dest = target_path or (SUBMISSIONS_DIR / "wazuh_alerts.json")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(self.alerts, f, indent=2)
        print(f"[WazuhLogger] Exported {len(self.alerts)} alerts to {dest}")
