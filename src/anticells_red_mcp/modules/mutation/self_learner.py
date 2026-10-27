"""Self-learner engine — learns from success/failure patterns to improve attack strategies over time."""

import asyncio
import json
import random
import uuid
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import httpx
from ..utils.safe_http import make_http_client

from ...mcp_server.config import MCPConfig
from ...mcp_server.engine import AttackResult
from ...catalog.runtime import snapshot_for
from ...catalog.model import CatalogError


class SelfLearner:
    """Learns from attack outcomes to generate improved strategies."""

    def __init__(self, config: Optional[MCPConfig] = None):
        self.config = config or MCPConfig()
        self._catalog = snapshot_for(self.config)
        self._http_client: Optional[httpx.AsyncClient] = None
        self.attempts: List[Dict[str, Any]] = []
        self.patterns: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"success": 0, "failure": 0, "responses": []})
        self.effective_words: Dict[str, float] = defaultdict(float)
        self.ineffective_words: Dict[str, float] = defaultdict(float)
        self.learning_rate = 0.1

    def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = make_http_client(timeout=60.0)
        return self._http_client

    async def close(self):
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    def record_attempt(self, technique: str, payload: str, success: bool, response: str = "", confidence: float = 0.0):
        """Record an attack attempt for learning."""
        entry = {
            "technique": technique,
            "payload": payload,
            "success": success,
            "response": response[:500],
            "confidence": confidence,
        }
        self.attempts.append(entry)
        self.patterns[technique]["success" if success else "failure"] += 1
        if response:
            self.patterns[technique]["responses"].append(response[:200])

        words = payload.lower().split()
        for word in words:
            word = word.strip(".,!?\"'():;[]{}")
            if success:
                self.effective_words[word] += self.learning_rate
            else:
                self.ineffective_words[word] += self.learning_rate

    def get_technique_effectiveness(self, technique: str) -> Tuple[float, int]:
        """Get success rate and total attempts for a technique."""
        pat = self.patterns[technique]
        total = pat["success"] + pat["failure"]
        if total == 0:
            return 0.0, 0
        return pat["success"] / total, total

    def get_best_techniques(self, n: int = 5) -> List[Tuple[str, float, int]]:
        """Return top N techniques by success rate."""
        scored = []
        for tech, pat in self.patterns.items():
            total = pat["success"] + pat["failure"]
            if total > 0:
                rate = pat["success"] / total
                scored.append((tech, rate, total))
        scored.sort(key=lambda x: (x[1], x[2]), reverse=True)
        return scored[:n]

    def get_worst_techniques(self, n: int = 5) -> List[Tuple[str, float, int]]:
        scored = []
        for tech, pat in self.patterns.items():
            total = pat["success"] + pat["failure"]
            if total > 0:
                rate = pat["success"] / total
                scored.append((tech, rate, total))
        scored.sort(key=lambda x: (x[1], x[2]))
        return scored[:n]

    def get_effective_words(self, n: int = 20) -> List[Tuple[str, float]]:
        sorted_words = sorted(
            self.effective_words.items(), key=lambda x: x[1], reverse=True
        )
        return sorted_words[:n]

    def generate_improved_payload(self, base_payload: str, boost_effective: bool = True) -> str:
        """Generate an improved payload by promoting effective words, demoting ineffective ones."""
        words = base_payload.split()
        effective = set(w for w, s in self.get_effective_words(20) if s > 0.3)
        ineffective = set(w for w, s in self.ineffective_words.items() if s > 0.5 and w not in effective)

        improved = []
        for word in words:
            clean = word.strip(".,!?\"'():;[]{}").lower()
            if boost_effective and clean in ineffective:
                if random.random() < 0.5:
                    replacement = random.choice(list(effective)) if effective else clean.upper()
                    improved.append(replacement)
                else:
                    improved.append(word)
            elif clean in effective:
                improved.append(word.upper() if random.random() < 0.3 else word)
            else:
                improved.append(word)
        return " ".join(improved)

    def suggest_next_technique(self) -> Optional[Dict[str, Any]]:
        """Suggest the next technique to try based on learning history."""
        if not self.attempts:
            return None
        best = self.get_best_techniques(3)
        if not best:
            return None
        tech_name = best[0][0]
        related = [a for a in self.attempts if a["technique"] == tech_name and a["success"]]
        if related:
            base = max(related, key=lambda x: x["confidence"])
            improved = self.generate_improved_payload(base["payload"])
            return {
                "technique": f"improved_{tech_name}",
                "payload": improved,
                "base_confidence": base["confidence"],
                "suggested_by": "self_learner",
            }
        return None

    def get_learning_stats(self) -> Dict[str, Any]:
        """Get overall learning statistics."""
        total = len(self.attempts)
        successes = sum(1 for a in self.attempts if a["success"])
        return {
            "total_attempts": total,
            "successes": successes,
            "success_rate": successes / total if total > 0 else 0.0,
            "techniques_tested": len(self.patterns),
            "best_techniques": [(t, round(r, 3), c) for t, r, c in self.get_best_techniques(5)],
            "top_effective_words": [w for w, _ in self.get_effective_words(10)],
        }

    async def suggest_via_llm(self) -> Optional[str]:
        """Use LLM to analyze patterns and suggest next attack strategy."""
        try:
            stats = self.get_learning_stats()
            best = self.get_best_techniques(5)
            worst = self.get_worst_techniques(3)
            effective = self.get_effective_words(15)

            prompt = (
                self._catalog.render('mutation.self_learner/suggest_via_llm_001', value0=f"{stats['total_attempts']}", value1=f"{stats['success_rate']:.2%}", value2=f"{[(t, f'{r:.0%}') for t, r, _ in best]}", value3=f"{[(t, f'{r:.0%}') for t, r, _ in worst]}", value4=f'{[w for w, _ in effective[:10]]}')
            )
            client = self._get_client()
            resp = await client.post(
                self.config.target_api_url or "https://api.openai.com/v1/chat/completions",
                json={
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 300,
                    "temperature": 0.7,
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            return None
        except CatalogError:
            raise
        except Exception:
            return None