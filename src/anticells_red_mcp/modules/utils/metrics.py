import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional


class MetricsCollector:
    def __init__(self):
        self._lock = threading.Lock()

        self._attacks_per_module: Dict[str, int] = defaultdict(int)
        self._successes_per_module: Dict[str, int] = defaultdict(int)
        self._failures_per_module: Dict[str, int] = defaultdict(int)

        self._response_times: Dict[str, List[float]] = defaultdict(list)
        self._technique_scores: Dict[str, List[float]] = defaultdict(list)
        self._technique_success_count: Dict[str, int] = defaultdict(int)
        self._technique_total_count: Dict[str, int] = defaultdict(int)

    def record(
        self,
        module_name: str,
        success: bool,
        response_time: Optional[float] = None,
        technique: Optional[str] = None,
    ):
        with self._lock:
            self._attacks_per_module[module_name] += 1
            if success:
                self._successes_per_module[module_name] += 1
            else:
                self._failures_per_module[module_name] += 1

            if response_time is not None:
                self._response_times[module_name].append(response_time)

            if technique:
                score = 1.0 if success else 0.0
                self._technique_scores[technique].append(score)
                self._technique_total_count[technique] += 1
                if success:
                    self._technique_success_count[technique] += 1

    def _avg(self, values: List[float]) -> float:
        return sum(values) / len(values) if values else 0.0

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            total_attacks = sum(self._attacks_per_module.values())
            total_successes = sum(self._successes_per_module.values())
            total_failures = sum(self._failures_per_module.values())
            overall_rate = (total_successes / total_attacks * 100) if total_attacks > 0 else 0.0

            module_stats = {}
            for module in self._attacks_per_module:
                attempts = self._attacks_per_module[module]
                successes = self._successes_per_module[module]
                module_stats[module] = {
                    "attempts": attempts,
                    "successes": successes,
                    "failures": self._failures_per_module[module],
                    "success_rate": (successes / attempts * 100) if attempts > 0 else 0.0,
                    "avg_response_time": self._avg(self._response_times.get(module, [])),
                }

            return {
                "total_attacks": total_attacks,
                "total_successes": total_successes,
                "total_failures": total_failures,
                "overall_success_rate": round(overall_rate, 2),
                "modules": module_stats,
                "top_techniques": self.get_top_techniques(),
            }

    def get_top_techniques(self, n: int = 10) -> List[Dict[str, Any]]:
        ranked = []
        for technique in self._technique_scores:
            scores = self._technique_scores[technique]
            effectiveness = self._avg(scores)
            attempts = self._technique_total_count[technique]
            successes = self._technique_success_count[technique]
            ranked.append({
                "technique": technique,
                "effectiveness": round(effectiveness, 4),
                "attempts": attempts,
                "successes": successes,
                "success_rate": round((successes / attempts * 100) if attempts > 0 else 0.0, 2),
            })

        ranked.sort(key=lambda x: x["effectiveness"], reverse=True)
        return ranked[:n]

    def reset(self):
        with self._lock:
            self._attacks_per_module.clear()
            self._successes_per_module.clear()
            self._failures_per_module.clear()
            self._response_times.clear()
            self._technique_scores.clear()
            self._technique_success_count.clear()
            self._technique_total_count.clear()