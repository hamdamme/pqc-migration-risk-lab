"""Input and finding models with lightweight JSON validation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Asset:
    asset_id: str
    component: str
    algorithm: str
    purpose: str
    evidence_source: str
    usage_state: str
    business_criticality: str
    migration_status: str
    label: str | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Asset:
        required = (
            "asset_id", "component", "algorithm", "purpose", "evidence_source",
            "usage_state", "business_criticality", "migration_status",
        )
        missing = [key for key in required if key not in value]
        if missing:
            raise ValueError(f"asset is missing required fields: {', '.join(missing)}")
        strings = {key: value[key] for key in required}
        if any(not isinstance(item, str) or not item.strip() for item in strings.values()):
            raise ValueError("required asset fields must be non-empty strings")
        if value.get("label") is not None and not isinstance(value["label"], str):
            raise ValueError("label must be a string when supplied")
        return cls(**strings, label=value.get("label"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_inventory(value: Any) -> list[Asset]:
    """Read either {assets:[...]} or a bare list of asset objects."""
    records = value.get("assets") if isinstance(value, dict) else value
    if not isinstance(records, list):
        raise ValueError("inventory must be a JSON list or an object with an 'assets' list")
    assets = [Asset.from_dict(item) if isinstance(item, dict) else _invalid_record() for item in records]
    ids = [asset.asset_id for asset in assets]
    if len(set(ids)) != len(ids):
        raise ValueError("asset_id values must be unique")
    return assets


def _invalid_record() -> Asset:
    raise ValueError("each inventory asset must be a JSON object")
