"""Transparent, deterministic baseline and context-aware classification rules."""

from __future__ import annotations

from dataclasses import dataclass

from .models import Asset

MIGRATE = "MIGRATE"
REVIEW = "REVIEW"
NO_PQC_ACTION = "NO_PQC_ACTION"
UNKNOWN = "UNKNOWN"

ALIASES = {
    "rsa": "RSA", "rsa-2048": "RSA", "rsa-3072": "RSA", "rsa-4096": "RSA",
    "ecdsa": "ECDSA", "ecdsa-p256": "ECDSA", "ecdsap-256": "ECDSA",
    "ecdsa-p384": "ECDSA", "ecdsap-384": "ECDSA",
    "ecdh": "ECDH", "ecdh-p256": "ECDH", "ecdhp-256": "ECDH",
    "ecdh-p384": "ECDH", "ecdhp-384": "ECDH",
    "sha256": "SHA-256", "sha-256": "SHA-256", "sha_256": "SHA-256",
    "sha-384": "SHA-384", "sha384": "SHA-384", "sha-512": "SHA-512",
    "sha512": "SHA-512", "aes": "AES", "aes-128": "AES", "aes-256": "AES",
    "chacha20": "CHACHA20", "ml-kem": "ML-KEM", "mlkem": "ML-KEM",
    "ml-kem-512": "ML-KEM", "ml-kem-768": "ML-KEM", "ml-kem-1024": "ML-KEM",
    "kyber": "ML-KEM", "ml-dsa": "ML-DSA", "mldsa": "ML-DSA",
    "dilithium": "ML-DSA", "slh-dsa": "SLH-DSA", "slhdsa": "SLH-DSA",
    "sphincs+": "SLH-DSA", "sphincsplus": "SLH-DSA",
}
ASYMMETRIC_LEGACY = {"RSA", "ECDSA", "ECDH"}
HASHES = {"SHA-256", "SHA-384", "SHA-512"}
SYMMETRIC = {"AES", "CHACHA20"}
PQC_SIGNATURES = {"ML-DSA", "SLH-DSA"}
PQC_ALGORITHMS = {"ML-KEM", *PQC_SIGNATURES}


def normalize_algorithm(name: str) -> str | None:
    key = "".join(name.strip().lower().split())
    return ALIASES.get(key)


def normalize_purpose(name: str) -> str:
    key = name.strip().lower().replace("_", " ").replace("-", " ")
    aliases = {
        "key establishment": "key_establishment", "key exchange": "key_establishment",
        "key encapsulation": "key_establishment", "key wrapping": "key_establishment",
        "digital signature": "digital_signature", "signing": "digital_signature",
        "signature": "digital_signature", "hashing": "hashing", "hash": "hashing",
        "password storage": "password_storage", "password hashing": "password_storage",
        "encryption": "encryption", "data encryption": "encryption",
        "authentication": "authentication", "unknown": "unknown",
    }
    return aliases.get(key, key.replace(" ", "_"))


@dataclass(frozen=True)
class Finding:
    asset_id: str
    algorithm: str | None
    purpose: str
    category: str
    rationale: str
    recommendation: str
    general_misuse: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "asset_id": self.asset_id, "algorithm": self.algorithm, "purpose": self.purpose,
            "category": self.category, "rationale": self.rationale,
            "recommendation": self.recommendation, "general_misuse": list(self.general_misuse),
        }


def classify_baseline(asset: Asset) -> Finding:
    """Algorithm-name-only baseline. It deliberately ignores use and evidence."""
    algorithm = normalize_algorithm(asset.algorithm)
    purpose = normalize_purpose(asset.purpose)
    if algorithm is None:
        category, rationale = UNKNOWN, "Algorithm name is not in the prototype's rule table."
    elif algorithm in ASYMMETRIC_LEGACY:
        category, rationale = MIGRATE, f"{algorithm} is a legacy public-key algorithm in the baseline."
    else:
        category, rationale = NO_PQC_ACTION, f"{algorithm} is not a public-key quantum migration trigger here."
    misuse = _misuse(algorithm, purpose)
    return Finding(asset.asset_id, algorithm, purpose, category, rationale,
                   _recommendation(category, algorithm, purpose), misuse)


def classify_context_aware(asset: Asset) -> Finding:
    algorithm = normalize_algorithm(asset.algorithm)
    purpose = normalize_purpose(asset.purpose)
    state = asset.usage_state.strip().lower()
    misuse = _misuse(algorithm, purpose)
    if algorithm is None:
        category, rationale = UNKNOWN, "Algorithm name is not recognized; verify the inventory entry."
    elif algorithm in ASYMMETRIC_LEGACY:
        compatible = ((algorithm in {"RSA", "ECDH"} and purpose == "key_establishment") or
                      (algorithm in {"RSA", "ECDSA"} and purpose == "digital_signature"))
        if not compatible:
            category = REVIEW
            rationale = f"{algorithm} can be quantum-vulnerable, but its recorded purpose needs verification."
        elif state == "observed":
            category = MIGRATE
            rationale = f"Observed {algorithm} use for {purpose.replace('_', ' ')} is a PQC migration candidate."
        else:
            category = REVIEW
            rationale = (f"{algorithm} is recorded as {state}; active use is not established by this evidence."
                         if state in {"detected", "configured"} else
                         "Usage state is not recognized; confirm whether this algorithm is active.")
    elif algorithm == "ML-KEM" or algorithm in PQC_SIGNATURES:
        expected = "key_establishment" if algorithm == "ML-KEM" else "digital_signature"
        if purpose != expected:
            category = REVIEW
            rationale = f"{algorithm} is a standardized PQC algorithm for {expected.replace('_', ' ')}, not {purpose.replace('_', ' ')}."
        elif state == "observed":
            category = NO_PQC_ACTION
            rationale = f"Observed {algorithm} use matches its standardized PQC purpose; validate deployment independently."
        else:
            category = REVIEW
            rationale = f"{algorithm} is recorded as {state}; this does not establish deployed use."
    elif algorithm in HASHES | SYMMETRIC:
        category = NO_PQC_ACTION
        rationale = f"{algorithm} use does not by itself trigger a PQC migration finding."
    else:
        category = UNKNOWN
        rationale = "The prototype has no rule for this algorithm."
    return Finding(asset.asset_id, algorithm, purpose, category, rationale,
                   _recommendation(category, algorithm, purpose), misuse)


def _misuse(algorithm: str | None, purpose: str) -> tuple[str, ...]:
    if algorithm in HASHES and purpose == "password_storage":
        return ("Direct use of a general-purpose hash is not a password-hashing scheme; assess a dedicated password KDF.",)
    return ()


def _recommendation(category: str, algorithm: str | None, purpose: str) -> str:
    if category == MIGRATE:
        target = "ML-KEM" if purpose == "key_establishment" else "ML-DSA or SLH-DSA"
        return f"Plan a standards-based migration for this use; evaluate {target} and interoperability requirements."
    if category == REVIEW:
        return "Collect implementation and runtime evidence, confirm the purpose, and record an owner and next review date."
    if category == UNKNOWN:
        return "Verify the algorithm name and purpose with the component owner; do not infer safety."
    if algorithm in PQC_ALGORITHMS:
        return "Retain evidence for implementation validation, interoperability, and production deployment review."
    return "No automatic PQC migration action from this record; continue ordinary cryptographic maintenance."
