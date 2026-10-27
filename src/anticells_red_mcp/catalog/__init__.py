"""Database-backed, versioned research content. No runtime seed fallback."""

from .model import CatalogError, CatalogSnapshot
from .runtime import bootstrap, snapshot_for, using_snapshot

__all__ = ["CatalogError", "CatalogSnapshot", "bootstrap", "snapshot_for", "using_snapshot"]
