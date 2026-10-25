"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .evaluation import evaluate
from .models import load_inventory
from .reports import build_report, to_markdown
from .rules import classify_baseline, classify_context_aware


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read JSON input {path}: {error}") from error


def _write_reports(report: dict[str, object], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (out / "report.md").write_text(to_markdown(report) if "findings" in report else _evaluation_markdown(report), encoding="utf-8")


def _evaluation_markdown(report: dict[str, object]) -> str:
    lines = ["# Synthetic Evaluation", "", f"Scenarios: **{report['scenario_count']}**", "",
             "| Method | Precision | Recall | F1 | False positives | False negatives |",
             "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for name, result in report["results"].items():
        m = result["metrics"]
        lines.append(f"| {name} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | {m['false_positives']} | {m['false_negatives']} |")
    lines.extend(["", "## Error analysis", ""])
    for method, errors in report["error_analysis"].items():
        lines.extend([f"### {method}", ""])
        if errors:
            lines.extend(f"- `{e['asset_id']}` expected {e['expected']}, predicted {e['predicted']}: {e['rationale']}" for e in errors)
        else:
            lines.append("- No classification errors in this synthetic dataset.")
        lines.append("")
    lines.append(report["note"])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pqc-risk-lab", description="Analyze PQC migration risk inventories.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze_parser = subparsers.add_parser("analyze", help="analyze an inventory")
    analyze_parser.add_argument("inventory", type=Path)
    analyze_parser.add_argument("--out", type=Path, default=Path("reports"))
    analyze_parser.add_argument("--mode", choices=("context-aware", "baseline"), default="context-aware")
    evaluate_parser = subparsers.add_parser("evaluate", help="evaluate labeled synthetic scenarios")
    evaluate_parser.add_argument("inventory", type=Path)
    evaluate_parser.add_argument("--out", type=Path, default=Path("reports"))
    args = parser.parse_args(argv)
    try:
        assets = load_inventory(_read_json(args.inventory))
        if args.command == "analyze":
            classifier = classify_context_aware if args.mode == "context-aware" else classify_baseline
            findings = [classifier(asset) for asset in assets]
            report = build_report(assets, findings, args.mode)
        else:
            report = evaluate(assets)
        _write_reports(report, args.out)
    except (ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"Wrote reports to {args.out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
