# Limitations

- The rule table is intentionally small and does not cover all algorithms, protocols, parameter sets, libraries, or deployment models.
- Name normalization uses explicit aliases; an unknown name stays `UNKNOWN` and may require manual mapping.
- `observed` is a user-supplied evidence label. The tool does not confirm that evidence is reliable, recent, or production-derived.
- A dependency scan or configuration can indicate exposure but does not establish active use. This tool places such legacy uses in `REVIEW`.
- A standardized PQC algorithm name does not prove a conforming implementation, validated module, secure configuration, interoperability, or production deployment.
- The phase report summarizes supplied records and status strings. It does not verify phase completion or organizational readiness.
- The synthetic evaluation is small and constructed to exercise rules. Its metrics do not establish effectiveness on real systems.
- `NO_PQC_ACTION` is narrow: no automatic PQC action is inferred from the supplied record. It is not a general security approval.
- Password storage misuse is surfaced as a separate hygiene note. This prototype does not assess password KDF parameters or suggest a complete remediation design.

Use the findings as triage prompts and obtain a qualified cryptographic review before making migration or security decisions.
