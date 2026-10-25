"""Reproducible synthetic evaluation for the name-only and context-aware rules."""

from __future__ import annotations

from .models import Asset
from .rules import Finding, classify_baseline, classify_context_aware

POSITIVE = "MIGRATE"


def binary_metrics(actual: list[str], predicted: list[str]) -> dict[str, float | int]:
    tp = sum(a == POSITIVE and p == POSITIVE for a, p in zip(actual, predicted, strict=True))
    fp = sum(a != POSITIVE and p == POSITIVE for a, p in zip(actual, predicted, strict=True))
    fn = sum(a == POSITIVE and p != POSITIVE for a, p in zip(actual, predicted, strict=True))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
            "false_positives": fp, "false_negatives": fn, "true_positives": tp}


def evaluate(assets: list[Asset]) -> dict[str, object]:
    labeled = [asset for asset in assets if asset.label]
    if len(labeled) != len(assets):
        raise ValueError("evaluation input requires a label on every asset")
    actual = [asset.label or "UNKNOWN" for asset in labeled]
    runs: dict[str, list[Finding]] = {
        "baseline": [classify_baseline(asset) for asset in labeled],
        "context_aware": [classify_context_aware(asset) for asset in labeled],
    }
    results = {name: {"metrics": binary_metrics(actual, [f.category for f in findings]),
                      "predictions": [{"asset_id": a.asset_id, "expected": a.label,
                                       "predicted": f.category}
                                      for a, f in zip(labeled, findings, strict=True)],
                      "errors": [{"asset_id": a.asset_id, "expected": a.label,
                                  "predicted": f.category, "algorithm": f.algorithm,
                                  "purpose": f.purpose, "rationale": f.rationale}
                                 for a, f in zip(labeled, findings, strict=True)
                                 if a.label != f.category]}
               for name, findings in runs.items()}
    return {"report_version": "1.0", "positive_class": POSITIVE,
            "scenario_count": len(labeled), "results": results,
            "note": "Metrics treat MIGRATE as the positive class; other categories are non-positive.",
            "error_analysis": {name: result["errors"] for name, result in results.items()}}
