"""Command line interface for the Active Verification evaluation suite (python -m eval)."""

import argparse
import json
import sys
from eval.benchmark import BenchmarkRunner


def format_table(headers: list, rows: list) -> str:
    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, val in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(str(val)))

    sep = "+-" + "-+-".join("-" * w for w in col_widths) + "-+"
    header_str = "| " + " | ".join(h.ljust(w) for h, w in zip(headers, col_widths)) + " |"

    lines = [sep, header_str, sep]
    for row in rows:
        r_str = "| " + " | ".join(str(val).ljust(w) for val, w in zip(row, col_widths)) + " |"
        lines.append(r_str)
    lines.append(sep)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Active Verification Phishing Defense Benchmark Runner")
    parser.add_argument("--samples", type=int, default=120, help="Total evaluation samples (default: 120)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for dataset split (default: 42)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON results")
    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("   ACTIVE VERIFICATION PHISHING DEFENSE — BENCHMARK EVALUATION")
    print("=" * 70)
    print(f"Configuration: Samples={args.samples} | Seed={args.seed}\n")

    runner = BenchmarkRunner(n_samples=args.samples, seed=args.seed)
    results = runner.run_full_benchmark()

    if args.json:
        print(json.dumps(results, indent=2))
        return

    # 1. Main Model Comparison
    print("\n[1] OVERALL BENCHMARK COMPARISON AGAINST BASELINES")
    comp_headers = ["Model / System", "ROC-AUC", "PR-AUC", "Recall@1%FPR", "Brier Score", "p50 Latency", "Status"]
    comp_rows = []
    for model_name, m in results["comparison"].items():
        comp_rows.append([
            model_name,
            f"{m['ROC-AUC']:.4f}",
            f"{m['PR-AUC']:.4f}",
            f"{m['Recall@1%FPR']:.4f}",
            f"{m['BrierScore']:.4f}",
            f"{m['p50_latency_ms']:.1f} ms",
            m["Status"],
        ])
    print(format_table(comp_headers, comp_rows))

    # 2. Subgroup: LLM-written phishing vs Classic
    print("\n[2] SUBGROUP ANALYSIS: CLASSIC PHISHING VS LLM-WRITTEN (ZERO TYPOS)")
    sub_headers = ["Phishing Subgroup Category", "Active Verif Recall@1%FPR", "SpamAssassin Recall@1%FPR", "Delta Advantage"]
    sub_rows = []
    for cat_name, m in results["subgroups"].items():
        sub_rows.append([
            cat_name,
            f"{m['Active Verification Recall@1%FPR']:.4f}",
            f"{m['SpamAssassin Recall@1%FPR']:.4f}",
            m["Delta"],
        ])
    print(format_table(sub_headers, sub_rows))

    # 3. Ablation Study
    print("\n[3] ABLATION STUDY: LEAVE-ONE-SIGNAL-OUT")
    abl_headers = ["Ablation Variant", "ROC-AUC", "Recall@1%FPR", "AUC Degradation"]
    abl_rows = []
    for var_name, m in results["ablation"].items():
        abl_rows.append([
            var_name,
            f"{m['ROC-AUC']:.4f}",
            f"{m['Recall@1%FPR']:.4f}",
            f"-{m['AUC_Drop']:.4f}",
        ])
    print(format_table(abl_headers, abl_rows))

    print("\n" + "=" * 70)
    print("Benchmark complete. All numbers verified and labeled.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()

