# Architecture

The package has four small layers:

1. `models.py` validates JSON asset records and preserves supplied evidence.
2. `rules.py` normalizes supported names and provides the name-only baseline and context-aware classifier.
3. `reports.py` builds JSON findings, Markdown output, and evidence summaries for the six migration phases.
4. `evaluation.py` compares predictions against synthetic labels using `MIGRATE` as the positive class; `cli.py` wires the commands to input and report files.

The core is deterministic and uses only the Python standard library. Unknown names remain unknown rather than being inferred from fuzzy matches. Context-aware classification considers algorithm, purpose, and usage state. It does not inspect source code, test cryptographic implementations, or independently validate evidence sources.

```text
JSON inventory ──> validation/normalization ──> baseline or context-aware rules
                                              ├─> JSON + Markdown assessment
Labeled synthetic inventory ─────────────────└─> metrics + error analysis
```

## Finding semantics

`MIGRATE` signals an observed legacy asymmetric use with a compatible purpose. `REVIEW` signals uncertainty, mismatched purpose, or evidence short of observed use. `NO_PQC_ACTION` means this record alone does not produce a PQC migration warning. `UNKNOWN` means the algorithm is outside the explicit rule table. General misuse notes are an independent field and do not change the PQC category.

The six phases are ecosystem-level migration phases. Reports summarize supplied evidence under each phase; they are not workflow states and never assert completion based only on an algorithm name.
