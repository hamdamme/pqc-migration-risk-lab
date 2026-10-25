# Research methodology

## Question and hypothesis

Question: can purpose and evidence context reduce incorrect migration alerts compared with algorithm-name-only rules while retaining detection of observed legacy public-key uses?

The testable hypothesis is that context-aware rules reduce false-positive `MIGRATE` classifications on synthetic records where a legacy algorithm is merely detected, used for another purpose, or lacks sufficient evidence. Version 1 is a mechanics demonstration; it does not establish the hypothesis for real inventories.

## Comparison

- **Baseline:** labels RSA, ECDSA, and ECDH as `MIGRATE` from the normalized algorithm name alone; other supported algorithms receive `NO_PQC_ACTION`, and unsupported names receive `UNKNOWN`.
- **Context-aware:** additionally considers the cryptographic purpose, whether use is observed versus only detected/configured, and compatibility between the algorithm family and purpose.
- **Positive class:** `MIGRATE`. The evaluator reports precision, recall, F1, false-positive and false-negative counts, predictions, and per-scenario errors.

The 24 records in `examples/ground_truth.json` are synthetic and manually labeled. They are not a representative sample, independently adjudicated labels, or a benchmark. Scores are reproducible for this fixture but should not be generalized.

## Evidence and future work

For stronger research, define a documented sampling protocol, collect de-identified real inventory records with permission, use multiple independent reviewers, report agreement and confidence intervals, and pre-register decision thresholds. Consider CBOM exchange as an input format only after the JSON semantics and evaluation design are stable. Keep algorithm identification separate from proof of runtime use and deployment.

## Migration phases

Reports map inventory evidence to the six phases described in the MITRE migration presentation: vulnerability evaluation; algorithm maturation; standards and implementation; solution development; deployment and adoption; phase-out. These are overlapping ecosystem activities, not six automatic states per asset.
