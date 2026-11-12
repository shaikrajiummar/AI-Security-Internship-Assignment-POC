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
            print("\nAvailable OWASP Test Cases:")
            for i, tc in enumerate(ATTACK_TEST_CASES[:10]):
                print(f"  {i+1}. [{tc['risk_id']}] {tc['title']} ({tc['target']})")
            tc_idx = input(f"Select test case (1-{len(ATTACK_TEST_CASES[:10])}): ").strip()
            try:
                selected_tc = ATTACK_TEST_CASES[int(tc_idx) - 1]
                print(f"\n[ATTACK] Prompt: {selected_tc['prompt']}")
                if selected_tc["target"] == "chatbot":
                    res = chatbot.chat(selected_tc["prompt"])
                    print(f"\n[RESPONSE]:\n{res['response']}")
                    if res.get("blocked"):
                        print(f">> Status: [BLOCKED] by {res.get('blocked_by')}")
                    elif CANARY_TOKEN in res.get("response", "") or DONOR_FLAG in res.get("response", ""):
                        print(">> Status: [SUCCEEDED] Canary token leaked!")
                    else:
                        print(">> Status: Clean / Protected")
                else:
                    res = agent.execute_task(selected_tc["prompt"])
                    print(f"\n[AGENT ACTION]: Tool Called: {res.get('tool_called')}")
                    print(f"[AGENT THOUGHT]: {res.get('thought')}")
                    print(f"[OUTPUT]: {res.get('output')}")
                    if res.get("blocked_by"):
                        print(f">> Status: [BLOCKED] by {res.get('blocked_by')}")
                    else:
                        print(">> Status: [EXECUTED] Tool invoked.")
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
