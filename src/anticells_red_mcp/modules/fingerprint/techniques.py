"""Fingerprint technique catalog — 30+ LLM probing techniques."""

from typing import Any, Dict, List
from ...catalog.runtime import snapshot_for


class FingerprintTechniques:
    """Catalog of LLM fingerprinting probe techniques."""

    def __init__(self):
        self._catalog = snapshot_for()

    def get_techniques(self) -> List[Dict[str, Any]]:
        return self._catalog.techniques('fingerprint.techniques')

    def get_by_category(self, category: str) -> List[Dict[str, Any]]:
        return [t for t in self._catalog.techniques('fingerprint.techniques') if t["category"] == category]

    def get_categories(self) -> List[str]:
        return sorted(set(t["category"] for t in self._catalog.techniques('fingerprint.techniques')))