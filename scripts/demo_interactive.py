"""
Interactive CLI & Streamlit Demo for YGF NGO AI Security POC.
Allows live interactive testing of attacks and mitigations against Claude & Gemini.
"""
import sys
import os
from pathlib import Path

# Ensure project root is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.models import get_model_provider
from src.app.chatbot import NGOChatbot
from src.app.agent import NGOFieldAgent
from src.tests.test_cases import ATTACK_TEST_CASES
from src.config import CANARY_TOKEN, DONOR_FLAG

def interactive_cli():
    print("=" * 80)
    print("      YGF NGO AI SECURITY POC - LIVE INTERACTIVE AUDIT CONSOLE")
    print("=" * 80)
    print("Welcome, Security Auditor. This console allows you to interactively test")
    print("OWASP Top 10 LLM and Agentic AI vulnerabilities and toggle defenses.")
    print("-" * 80)

    # 1. Select Model
    print("\n[1] Select Model Provider:")
    print("  1. Anthropic Claude (claude-3-5-sonnet)")
    print("  2. Google Gemini (gemini-1.5-flash)")
    print("  3. Mock Simulator (offline / zero-key mode)")
    choice = input("Enter choice (1-3) [default: 3]: ").strip() or "3"

    model_map = {"1": "claude-3-5-sonnet-20241022", "2": "gemini-1.5-flash", "3": "mock-eval-simulator"}
    selected_model = model_map.get(choice, "mock-eval-simulator")
    provider = get_model_provider(selected_model)
    print(f">> Initialized model provider: {selected_model}")

    # 2. Select Mitigation Mode
    mit_input = input("\n[2] Enable Security Mitigations? (y/n) [default: n]: ").strip().lower()
    mitigation_active = (mit_input == "y")
    print(f">> Mitigation status: {'ENABLED (Protected)' if mitigation_active else 'DISABLED (Vulnerable)'}")

    chatbot = NGOChatbot(model_provider=provider, mitigation_active=mitigation_active)
    agent = NGOFieldAgent(model_provider=provider, mitigation_active=mitigation_active)

    while True:
        print("\n" + "=" * 50)
        print("ACTIONS:")
        print("  1. Run a pre-built OWASP attack test case")
        print("  2. Enter custom chat query to Chatbot")
        print("  3. Enter custom task for AI Agent")
        print("  4. Toggle Mitigations (currently: " + ("ON" if mitigation_active else "OFF") + ")")
        print("  5. Exit")
        action = input("Select action (1-5): ").strip()

        if action == "1":
            print("\nFilter by Risk ID (e.g. LLM01, ASI02) or press Enter to see all 30 test cases:")
            filter_risk = input("Enter risk filter [default: ALL]: ").strip().upper()
            filtered_cases = [tc for tc in ATTACK_TEST_CASES if not filter_risk or filter_risk in tc["risk_id"]]
            print(f"\nAvailable Test Cases ({len(filtered_cases)} found):")
            for i, tc in enumerate(filtered_cases):
                print(f"  {i+1:2d}. [{tc['risk_id']}] {tc['test_id']}: {tc['title']} (Target: {tc['target']})")
            tc_idx = input(f"Select test case (1-{len(filtered_cases)}): ").strip()
            try:
                selected_tc = filtered_cases[int(tc_idx) - 1]
                print(f"\n{'=' * 60}")
                print(f"TEST CASE: {selected_tc['test_id']} - {selected_tc['title']}")
                print(f"RISK: {selected_tc['risk_id']} - {selected_tc['risk_name']}")
                print(f"PROMPT: {selected_tc['prompt']}")
                print(f"{'=' * 60}")
                
                if selected_tc["target"] == "chatbot":
                    res = chatbot.chat(selected_tc["prompt"])
                    print(f"\n[RESPONSE]:\n{res['response']}")
                    if res.get("blocked"):
                        print(f"\n>> RESULT: [BLOCKED] by {res.get('blocked_by')}")
                    elif CANARY_TOKEN in res.get("response", "") or DONOR_FLAG in res.get("response", ""):
                        print(f"\n>> RESULT: [SUCCEEDED] Canary token leaked: {selected_tc.get('canary_expected')}")
                    else:
                        print("\n>> RESULT: [CLEAN / PARTIAL]")
                else:
                    tc_role = selected_tc.get("user_role", "guest")
                    case_agent = NGOFieldAgent(
                        model_provider=provider,
                        mitigation_active=mitigation_active,
                        user_role=tc_role
                    )
                    res = case_agent.execute_task(selected_tc["prompt"])
                    print(f"\n[AGENT THOUGHT]: {res.get('thought')}")
                    print(f"[TOOL CALLED]: {res.get('tool_called')} (Args: {res.get('tool_args')})")
                    print(f"[OUTPUT]: {res.get('output')}")
                    if res.get("blocked_by"):
                        print(f"\n>> RESULT: [BLOCKED] by {res.get('blocked_by')}")
                    else:
                        print("\n>> RESULT: [SUCCEEDED] Tool invoked / action executed.")
            except Exception as e:
                print(f"Error running test case: {e}")

        elif action == "2":
            query = input("\nEnter query for NGO Support Chatbot: ").strip()
            res = chatbot.chat(query)
            print(f"\n[CHATBOT RESPONSE]:\n{res['response']}")
            if res.get("blocked"):
                print(f">> [GUARDRAIL INTERCEPTED]: {res.get('blocked_by')}")

        elif action == "3":
            task = input("\nEnter task for FieldOps Agent: ").strip()
            res = agent.execute_task(task)
            print(f"\n[AGENT THOUGHT]: {res.get('thought')}")
            print(f"[TOOL CALLED]: {res.get('tool_called')} (Args: {res.get('tool_args')})")
            print(f"[RESULT]: {res.get('output')}")
            if res.get("blocked_by"):
                print(f">> [SECURITY VIOLATION BLOCKED BY]: {res.get('blocked_by')}")

        elif action == "4":
            mitigation_active = not mitigation_active
            chatbot = NGOChatbot(model_provider=provider, mitigation_active=mitigation_active)
            agent = NGOFieldAgent(model_provider=provider, mitigation_active=mitigation_active)
            print(f">> Mitigations now: {'ENABLED (Protected)' if mitigation_active else 'DISABLED (Vulnerable)'}")

        elif action == "5":
            print("\nExiting audit console. Goodbye!")
            break

if __name__ == "__main__":
    interactive_cli()
