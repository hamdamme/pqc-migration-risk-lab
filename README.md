
# PQC Migration Risk Lab

A small Python CLI research prototype for assessing cryptographic inventory records in the context of post-quantum migration. It compares a simple algorithm-name baseline with deterministic rules that also consider purpose and evidence of use.

The project focuses on actionable triage, not source-code scanning. It accepts structured JSON so inventories can be collected by other tools, including CBOM producers. A dependency or configuration finding alone is not treated as proof of active use.

## Quick start

Requires Python 3.12 or newer. No runtime dependencies are required.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
pqc-risk-lab analyze examples/inventory.json --out reports/
pqc-risk-lab analyze examples/inventory.json --mode baseline --out reports/baseline/
pqc-risk-lab evaluate examples/ground_truth.json --out reports/evaluation/
```

Each command writes `report.json` and `report.md`. You can also run from a source checkout with `PYTHONPATH=src python -m pqc_risk_lab ...`.

## Classification

- **MIGRATE** — observed RSA/ECDH key establishment or RSA/ECDSA signatures are migration candidates.
- **REVIEW** — purpose is unclear or unsuitable, an algorithm is only detected/configured, or PQC use is not evidenced in operation.
- **NO_PQC_ACTION** — no automatic PQC migration action is implied by this record. This does not mean the system is secure.
- **UNKNOWN** — algorithm is not represented in the prototype's explicit rule table.

The analyzer keeps ordinary cryptographic hygiene separate from quantum migration. For example, direct SHA-256 password storage receives a separate password-hashing note while its PQC category remains `NO_PQC_ACTION`. ML-KEM is considered for key establishment; ML-DSA and SLH-DSA are considered for signatures.

## Input

See [`examples/inventory.json`](examples/inventory.json). Each asset includes an identifier, component, algorithm, purpose, evidence source, usage state (`detected`, `configured`, `observed`, or `unknown`), business criticality, and migration status. The evaluation file adds a ground-truth `label` to each of 24 synthetic scenarios.

## Evaluation

The included experiment treats `MIGRATE` as the positive class and compares precision, recall, F1, false positives, and false negatives. It reports classification errors per method. The synthetic labels are illustrative and are not measured ground truth for real systems; do not interpret the scores as external validation.

## Research question

Can context-aware risk assessment produce more accurate and actionable migration recommendations than algorithm-name-only detection? Version 1 gives a reproducible baseline experiment, not a publishable empirical claim. Follow [`docs/research-methodology.md`](docs/research-methodology.md) before extending the evaluation.

## Project boundaries

- No cryptographic algorithms are implemented here.
- No source scanner, web interface, database, cloud service, or machine learning is included.
- This is not a certified security assessment tool, compliance determination, or migration-completion verifier.
- Findings depend on the inventory supplied; verify implementation, protocol, and deployment evidence with qualified reviewers.

See [`docs/architecture.md`](docs/architecture.md), [`docs/limitations.md`](docs/limitations.md), and [`docs/references.md`](docs/references.md). MIT licensed.
