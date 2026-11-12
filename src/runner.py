"""
Main Benchmark Runner CLI.
Executes the full suite of 30 attack test cases across Claude and Gemini,
evaluating pre-mitigation and post-mitigation defense outcomes.
Generates results.csv, results.json, and Wazuh SIEM alerts.
"""
import os
import sys
import csv
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any

from src.config import (
    MODEL_CLAUDE_DEFAULT, MODEL_GEMINI_DEFAULT,
    SUBMISSIONS_DIR, STATUS_BLOCKED, STATUS_PARTIAL, STATUS_SUCCEEDED
)
from src.models import get_model_provider
from src.tests.test_cases import ATTACK_TEST_CASES
from src.tests.evaluator import SecurityEvaluator
from src.siem.wazuh_logger import WazuhSecurityLogger

def run_benchmark(
    models: List[str],
    mitigation_modes: List[bool],
    target_risks: List[str] = None,
    wazuh_enabled: bool = True
) -> List[Dict[str, Any]]:
    wazuh_logger = WazuhSecurityLogger() if wazuh_enabled else None
    all_results = []

    print("=" * 80)
    print("  YGF NGO AI SECURITY POC BENCHMARK RUNNER")
    print("  OWASP Top 10 for LLM & OWASP Top 10 for Agentic AI (2026)")
    print("=" * 80)
    print(f"Models to test: {', '.join(models)}")
    print(f"Mitigation phases: {[ 'POST-FIX (Protected)' if m else 'PRE-FIX (Vulnerable)' for m in mitigation_modes ]}")
    print(f"Target risks: {target_risks or 'ALL 10 RISKS'}")
    print("-" * 80)

    for model_name in models:
        provider = get_model_provider(model_name)
        model_display = "Anthropic Claude" if "claude" in model_name.lower() else ("Google Gemini" if "gemini" in model_name.lower() else "Mock Simulator")

        for mitigation_active in mitigation_modes:
            phase_label = "POST-FIX (Mitigated)" if mitigation_active else "PRE-FIX (Vulnerable)"
            print(f"\n>>> Running Phase: [{phase_label}] on Model: [{model_display}] ({model_name})")

            for tc in ATTACK_TEST_CASES:
                if target_risks and tc["risk_id"] not in target_risks:
                    continue

                eval_record = SecurityEvaluator.evaluate_test_case(
                    test_case=tc,
                    model_provider=provider,
                    mitigation_active=mitigation_active
                )

                eval_record["model_name"] = model_name
                eval_record["model_display"] = model_display
                eval_record["phase"] = phase_label

                all_results.append(eval_record)

                # Log to Wazuh SIEM
                if wazuh_logger:
                    wazuh_logger.log_event(
                        risk_id=tc["risk_id"],
                        test_id=tc["test_id"],
                        model_name=model_name,
                        result_status=eval_record["result"],
                        prompt=tc["prompt"],
                        evidence=eval_record["evidence"],
                        blocked_by=eval_record.get("blocked_by")
                    )

                status_col = (
                    "[BLOCKED]" if eval_record["result"] == STATUS_BLOCKED
                    else ("[SUCCEEDED]" if eval_record["result"] == STATUS_SUCCEEDED else "[PARTIAL]")
                )
                print(f"  {tc['test_id']} | {tc['risk_id']} | {tc['title'][:32]:<32} | {status_col:<11} | {eval_record['evidence'][:40]}")

    if wazuh_logger:
        wazuh_logger.export_summary(SUBMISSIONS_DIR / "wazuh_alerts.json")

    return all_results

def export_results_csv(results: List[Dict[str, Any]], filepath: Path):
    filepath.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "Risk ID", "Risk Name", "Test ID", "Test Title", "Model",
        "Mitigation Status", "Prompt", "Result", "Evidence", "Blocked By"
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "Risk ID": r["risk_id"],
                "Risk Name": r["risk_name"],
                "Test ID": r["test_id"],
                "Test Title": r["title"],
                "Model": r["model_display"],
                "Mitigation Status": r["phase"],
                "Prompt": r["prompt"],
                "Result": r["result"],
                "Evidence": r["evidence"],
                "Blocked By": r.get("blocked_by") or "N/A"
            })
    print(f"\n[+] Results CSV exported to: {filepath}")

def export_results_json(results: List[Dict[str, Any]], filepath: Path):
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Results JSON exported to: {filepath}")

def print_summary_table(results: List[Dict[str, Any]]):
    print("\n" + "=" * 80)
    print("                      BENCHMARK EXECUTIVE SUMMARY TABLE")
    print("=" * 80)

    # Group by Risk ID, Model, and Mitigation Phase
    summary = {}
    for r in results:
        key = (r["risk_id"], r["model_display"], r["mitigation_active"])
        if key not in summary:
            summary[key] = {"total": 0, "blocked": 0, "succeeded": 0, "partial": 0}
        summary[key]["total"] += 1
        if r["result"] == STATUS_BLOCKED:
            summary[key]["blocked"] += 1
        elif r["result"] == STATUS_SUCCEEDED:
            summary[key]["succeeded"] += 1
        else:
            summary[key]["partial"] += 1

    header = f"{'Risk ID':<8} | {'Model':<18} | {'Mitigation':<16} | {'Total':<6} | {'Blocked':<8} | {'Succeeded':<10} | {'Efficacy %'}"
    print(header)
    print("-" * len(header))

    for (risk_id, model, mit_active), stats in sorted(summary.items()):
        phase = "POST-FIX (On)" if mit_active else "PRE-FIX (Off)"
        efficacy = (stats["blocked"] / stats["total"]) * 100.0
        print(f"{risk_id:<8} | {model:<18} | {phase:<16} | {stats['total']:<6} | {stats['blocked']:<8} | {stats['succeeded']:<10} | {efficacy:>6.1f}%")

    print("=" * 80)

def main():
    parser = argparse.ArgumentParser(description="OWASP LLM & Agentic AI Benchmark Runner")
    parser.add_argument("--model", choices=["claude", "gemini", "mock", "both"], default="both",
                        help="Target model(s) to evaluate")
    parser.add_argument("--mitigations", choices=["off", "on", "both"], default="both",
                        help="Evaluate pre-mitigation (off), post-mitigation (on), or before-and-after (both)")
    parser.add_argument("--risks", type=str, default="",
                        help="Comma-separated risk IDs to filter (e.g. LLM01,ASI02)")
    parser.add_argument("--wazuh", action="store_true", default=True,
                        help="Stream alerts to Wazuh SIEM JSON log")
    args = parser.parse_args()

    models = []
    if args.model == "both":
        models = [MODEL_CLAUDE_DEFAULT, MODEL_GEMINI_DEFAULT]
    elif args.model == "claude":
        models = [MODEL_CLAUDE_DEFAULT]
    elif args.model == "gemini":
        models = [MODEL_GEMINI_DEFAULT]
    else:
        models = ["mock-eval-simulator"]

    mit_modes = []
    if args.mitigations == "both":
        mit_modes = [False, True]
    elif args.mitigations == "off":
        mit_modes = [False]
    else:
        mit_modes = [True]

    target_risks = [r.strip().upper() for r in args.risks.split(",") if r.strip()] if args.risks else None

    results = run_benchmark(
        models=models,
        mitigation_modes=mit_modes,
        target_risks=target_risks,
        wazuh_enabled=args.wazuh
    )

    export_results_csv(results, SUBMISSIONS_DIR / "results.csv")
    export_results_json(results, SUBMISSIONS_DIR / "results.json")
    print_summary_table(results)

if __name__ == "__main__":
    main()
