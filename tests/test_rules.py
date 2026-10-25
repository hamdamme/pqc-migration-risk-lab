import json
from pathlib import Path

from pqc_risk_lab.evaluation import binary_metrics, evaluate
from pqc_risk_lab.models import Asset, load_inventory
from pqc_risk_lab.reports import build_report
from pqc_risk_lab.rules import classify_context_aware, normalize_algorithm

ROOT = Path(__file__).parents[1]


def inventory(name: str, purpose: str, state: str = "observed") -> Asset:
    return Asset("a", "component", name, purpose, "test fixture", state, "medium", "unknown")


def test_aliases_and_unknown_names():
    assert normalize_algorithm(" RSA-2048 ") == "RSA"
    assert normalize_algorithm("sha_256") == "SHA-256"
    assert normalize_algorithm("MysteryAlgo") is None


def test_observed_legacy_key_establishment_is_migrate():
    finding = classify_context_aware(inventory("ECDH", "key exchange"))
    assert finding.category == "MIGRATE"
    assert "ML-KEM" in finding.recommendation


def test_detected_dependency_is_review_not_proven_active():
    assert classify_context_aware(inventory("RSA", "key establishment", "detected")).category == "REVIEW"


def test_hash_password_note_is_separate_from_pqc_category():
    finding = classify_context_aware(inventory("SHA-256", "password storage"))
    assert finding.category == "NO_PQC_ACTION"
    assert finding.general_misuse


def test_signature_migration_does_not_recommend_kem():
    finding = classify_context_aware(inventory("ECDSA", "digital signature"))
    assert finding.category == "MIGRATE"
    assert "ML-DSA" in finding.recommendation
    assert "ML-KEM" not in finding.recommendation


def test_evaluation_has_at_least_20_labeled_records_and_phase_report():
    assets = load_inventory(json.loads((ROOT / "examples/ground_truth.json").read_text()))
    assert len(assets) >= 20
    report = evaluate(assets)
    assert set(report["results"]) == {"baseline", "context_aware"}
    assert report["results"]["context_aware"]["metrics"]["false_positives"] < report["results"]["baseline"]["metrics"]["false_positives"]
    findings = [classify_context_aware(asset) for asset in assets]
    phases = build_report(assets, findings, "context-aware")["migration_phases"]
    assert len(phases) == 6
    assert all(phase["status"] == "evidence_summary" for phase in phases)


def test_metric_edge_cases():
    assert binary_metrics(["REVIEW"], ["MIGRATE"])["false_positives"] == 1
    assert binary_metrics(["MIGRATE"], ["REVIEW"])["false_negatives"] == 1


def test_inventory_rejects_duplicate_ids():
    record = {"asset_id":"same", "component":"x", "algorithm":"RSA", "purpose":"key establishment",
              "evidence_source":"x", "usage_state":"observed", "business_criticality":"low", "migration_status":"unknown"}
    try:
        load_inventory({"assets": [record, record]})
    except ValueError as error:
        assert "unique" in str(error)
    else:
        raise AssertionError("duplicate ids should be rejected")
