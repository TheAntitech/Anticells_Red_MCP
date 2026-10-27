import json
import os
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional


class AttackTracker:
    MAX_HISTORY = 10000

    def __init__(self, storage_path: Optional[str] = None):
        self._lock = threading.Lock()
        self._history: List[Dict[str, Any]] = []
        self._storage_path = storage_path

    def record_attempt(self, result: Any) -> Dict[str, Any]:
        # Accept both dict and AttackResult dataclass
        if hasattr(result, '__dataclass_fields__'):
            # AttackResult object
            entry = {
                "id": len(self._history) + 1,
                "timestamp": datetime.now().isoformat(),
                "module": getattr(result, "module", "unknown"),
                "technique": getattr(result, "technique", "unknown"),
                "attack_id": getattr(result, "attack_id", ""),
                "success": getattr(result, "success", False),
                "response_time": getattr(result, "metadata", {}).get("response_time_ms") if hasattr(result, "metadata") else None,
                "payload_preview": self._truncate(getattr(result, "payload", ""), 200),
                "indicators": getattr(result, "indicators", []),
                "confidence": getattr(result, "confidence", 0.0),
                "fingerprint": getattr(result, "metadata", {}).get("fingerprint") if hasattr(result, "metadata") else None,
                "metadata": getattr(result, "metadata", {}),
            }
        else:
            # Dict fallback
            entry = {
                "id": len(self._history) + 1,
                "timestamp": datetime.now().isoformat(),
                "module": result.get("module", "unknown"),
                "technique": result.get("technique", "unknown"),
                "success": result.get("success", False),
                "response_time": result.get("response_time"),
                "payload_preview": self._truncate(result.get("payload", ""), 200),
                "indicators": result.get("indicators", {}),
                "confidence": result.get("confidence"),
                "fingerprint": result.get("fingerprint"),
                "metadata": result.get("metadata", {}),
            }

        with self._lock:
            self._history.append(entry)
            if len(self._history) > self.MAX_HISTORY:
                self._history = self._history[-self.MAX_HISTORY:]

        return entry

    def _truncate(self, text: Any, max_len: int) -> str:
        s = str(text)
        if len(s) > max_len:
            return s[:max_len] + "..."
        return s

    def get_history(
        self, module: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        with self._lock:
            entries = self._history
            if module is not None:
                entries = [e for e in entries if e.get("module") == module]
            return entries[-limit:]

    def get_successful_chains(self) -> List[List[Dict[str, Any]]]:
        with self._lock:
            chains: List[List[Dict[str, Any]]] = []
            current_chain: List[Dict[str, Any]] = []
            consecutive_failures = 0

            for entry in self._history:
                if entry["success"]:
                    current_chain.append(entry)
                    consecutive_failures = 0
                else:
                    consecutive_failures += 1
                    if consecutive_failures >= 3 and current_chain:
                        if len(current_chain) >= 2:
                            chains.append(list(current_chain))
                        current_chain = []
                        consecutive_failures = 0

            if len(current_chain) >= 2:
                chains.append(current_chain)

            return chains

    def export_to_json(self, filepath: str):
        with self._lock:
            data = {
                "exported_at": datetime.now().isoformat(),
                "total_entries": len(self._history),
                "history": self._history,
            }

        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    def clear(self):
        with self._lock:
            self._history.clear()