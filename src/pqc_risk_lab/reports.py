"""JSON and Markdown report generation, including six-phase evidence mapping."""

from __future__ import annotations

from .models import Asset
from .rules import Finding

PHASES = [
    "Vulnerability Evaluation", "Algorithm Maturation", "Standards and Implementation",
    "Solution Development", "Deployment and Adoption", "Phase-Out",
]


def phase_mapping(assets: list[Asset], findings: list[Finding]) -> list[dict[str, object]]:
    categories = {finding.asset_id: finding.category for finding in findings}
    total = len(assets)
    known = sum(categories.get(asset.asset_id) != "UNKNOWN" for asset in assets)
    active = sum(asset.usage_state.lower() == "observed" for asset in assets)
    pqc_records = sum(f.algorithm in {"ML-KEM", "ML-DSA", "SLH-DSA"} for f in findings)
    migration_records = sum(a.migration_status.lower() not in {"not_started", "unknown", ""} for a in assets)
    completed = sum(a.migration_status.lower() in {"retired", "decommissioned"} for a in assets)
    evidence = [
        f"{known} of {total} records have a recognized algorithm." if total else "No inventory records supplied.",
        f"{pqc_records} records name a NIST-standardized PQC algorithm; suitability still needs evaluation.",
        f"{pqc_records} records reference a standardized PQC family; implementation validation evidence is not asserted by algorithm name.",
        f"{migration_records} records contain a non-default migration status; status values are user-supplied, not independently verified.",
        f"{active} records are marked observed in use; observation alone does not establish production deployment.",
        f"{completed} records are marked retired or decommissioned; retirement needs independent supporting evidence.",
    ]
    return [{"phase": phase, "evidence": evidence[index], "status": "evidence_summary"}
            for index, phase in enumerate(PHASES)]


def build_report(assets: list[Asset], findings: list[Finding], analysis: str) -> dict[str, object]:
    return {
        "report_version": "1.0", "analysis": analysis,
        "summary": {category: sum(f.category == category for f in findings)
                    for category in ("MIGRATE", "REVIEW", "NO_PQC_ACTION", "UNKNOWN")},
        "findings": [finding.to_dict() for finding in findings],
        "migration_phases": phase_mapping(assets, findings),
        "limitations": [
            "This deterministic prototype is not a certified security assessment or a substitute for expert review.",
            "An algorithm's presence in a library does not prove active use; only the supplied usage_state is considered.",
            "The report does not verify implementation conformance, production deployment, or migration completion.",
        ],
    }


def to_markdown(report: dict[str, object]) -> str:
    summary = report["summary"]
    lines = ["# PQC Migration Risk Assessment", "", f"Analysis: **{report['analysis']}**", "",
             "## Summary", "", "| Category | Count |", "| --- | ---: |"]
    assert isinstance(summary, dict)
    lines.extend(f"| {key} | {value} |" for key, value in summary.items())
    lines.extend(["", "## Findings", ""])
    for finding in report["findings"]:
        lines.extend([f"### {finding['asset_id']} — {finding['category']}", "",
                      f"- **Algorithm / purpose:** {finding['algorithm'] or 'unrecognized'} / {finding['purpose']}",
                      f"- **Why:** {finding['rationale']}", f"- **Recommendation:** {finding['recommendation']}"])
        for item in finding["general_misuse"]:
            lines.append(f"- **Separate cryptographic hygiene note:** {item}")
        lines.append("")
    lines.extend(["## Six migration phases", "", "These are ecosystem phases, not per-asset states.",
                  "", "| Phase | Evidence summary |", "| --- | --- |"])
    lines.extend(f"| {phase['phase']} | {phase['evidence']} |" for phase in report["migration_phases"])
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines) + "\n"
