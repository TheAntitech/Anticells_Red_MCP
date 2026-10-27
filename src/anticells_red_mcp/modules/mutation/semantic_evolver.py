"""Semantic evolver engine — semantically-aware prompt evolution using embedding similarity and style transfer."""

import asyncio
import math
import random
import uuid
from typing import Any, Dict, List, Optional, Tuple

import httpx
from ..utils.safe_http import make_http_client

from ...mcp_server.config import MCPConfig
from ...mcp_server.engine import AttackResult
from ...catalog.runtime import snapshot_for
from ...catalog.model import CatalogError


class SemanticEvolver:
    """Evolves prompts via semantic-aware operations and style transfer."""

    def __init__(self, config: Optional[MCPConfig] = None):
        self.config = config or MCPConfig()
        self._catalog = snapshot_for(self.config)
        self._http_client: Optional[httpx.AsyncClient] = None
        self.evolution_history: List[Dict[str, Any]] = []

    def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = make_http_client(timeout=60.0)
        return self._http_client

    async def close(self):
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    async def apply_operator(
        self, prompt: str, operator: str, attack_id: str
    ) -> Optional[str]:
        """Apply a semantic operator using LLM."""
        target_url = self.config.target_api_url or "https://api.openai.com/v1/chat/completions"
        operator_prompts = {
            "amplify": self._catalog.render('mutation.semantic_evolver/apply_operator_001', value0=f'{prompt}'),
            "generalize": self._catalog.render('mutation.semantic_evolver/apply_operator_002', value0=f'{prompt}'),
            "specify": self._catalog.render('mutation.semantic_evolver/apply_operator_003', value0=f'{prompt}'),
            "negate": self._catalog.render('mutation.semantic_evolver/apply_operator_004', value0=f'{prompt}'),
            "rephrase": self._catalog.render('mutation.semantic_evolver/apply_operator_005', value0=f'{prompt}'),
            "analogize": self._catalog.render('mutation.semantic_evolver/apply_operator_006', value0=f'{prompt}'),
            "contrast": self._catalog.render('mutation.semantic_evolver/apply_operator_007', value0=f'{prompt}'),
            "simplify": self._catalog.render('mutation.semantic_evolver/apply_operator_008', value0=f'{prompt}'),
            "complicate": self._catalog.render('mutation.semantic_evolver/apply_operator_009', value0=f'{prompt}'),
            "emotionalize": self._catalog.render('mutation.semantic_evolver/apply_operator_010', value0=f'{prompt}'),
        }
        instruction = operator_prompts.get(
            operator,
            self._catalog.render('mutation.semantic_evolver/apply_operator_011', value0=f'{prompt}', value1=f'{operator}'),
        )
        try:
            client = self._get_client()
            resp = await client.post(target_url, json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": instruction}],
                "max_tokens": 300,
                "temperature": 0.7,
            })
            if resp.status_code == 200:
                data = resp.json()
                transformed = data["choices"][0]["message"]["content"].strip()
                self.evolution_history.append({
                    "original": prompt[:200],
                    "operator": operator,
                    "result": transformed[:300],
                })
                return transformed
            return None
        except CatalogError:
            raise
        except Exception:
            return None

    async def style_transfer(self, prompt: str, style: str) -> Optional[str]:
        """Transfer prompt to a different style."""
        target_url = self.config.target_api_url or "https://api.openai.com/v1/chat/completions"
        try:
            client = self._get_client()
            resp = await client.post(target_url, json={
                "model": "gpt-4o-mini",
                "messages": [{
                    "role": "user",
                    "content": self._catalog.render('mutation.semantic_evolver/style_transfer_001', value0=f'{style}', value1=f'{style}', value2=f'{prompt}'),
                }],
                "max_tokens": 300,
                "temperature": 0.7,
            })
            if resp.status_code == 200:
                data = resp.json()
                result = data["choices"][0]["message"]["content"].strip()
                self.evolution_history.append({
                    "original": prompt[:200],
                    "operator": f"style:{style}",
                    "result": result[:300],
                })
                return result
            return None
        except CatalogError:
            raise
        except Exception:
            return None

    async def combine_semantically(
        self, prompt_a: str, prompt_b: str, strategy: str = "merge"
    ) -> Optional[str]:
        """Semantically combine two prompts."""
        target_url = self.config.target_api_url or "https://api.openai.com/v1/chat/completions"
        try:
            client = self._get_client()
            resp = await client.post(target_url, json={
                "model": "gpt-4o-mini",
                "messages": [{
                    "role": "user",
                    "content": (
                        self._catalog.render('mutation.semantic_evolver/combine_semantically_001', value0=f'{strategy}', value1=f'{prompt_a}', value2=f'{prompt_b}')
                    ),
                }],
                "max_tokens": 300,
                "temperature": 0.7,
            })
            if resp.status_code == 200:
                data = resp.json()
                result = data["choices"][0]["message"]["content"].strip()
                self.evolution_history.append({
                    "original": f"{prompt_a[:100]} + {prompt_b[:100]}",
                    "operator": f"combine:{strategy}",
                    "result": result[:300],
                })
                return result
            return None
        except CatalogError:
            raise
        except Exception:
            return None

    async def evolve_population(
        self, base_prompts: List[str], generations: int = 3, variants_per_gen: int = 5
    ) -> List[Dict[str, str]]:
        """Evolve a population of prompts semantically."""
        population = [{"prompt": p, "generation": 0} for p in base_prompts]
        all_results = list(population)

        for gen in range(1, generations + 1):
            new_variants = []
            for prompt_obj in population:
                op = random.choice(self._catalog.asset('mutation.semantic_evolver/semantic_operators'))
                variant = await self.apply_operator(
                    prompt_obj["prompt"], op, f"sem_evolve_{gen}"
                )
                if variant:
                    new_variants.append({"prompt": variant, "generation": gen})

                style = random.choice(self._catalog.asset('mutation.semantic_evolver/style_transforms'))
                variant2 = await self.style_transfer(prompt_obj["prompt"], style)
                if variant2:
                    new_variants.append({"prompt": variant2, "generation": gen})

            for _ in range(variants_per_gen // 2):
                if len(population) >= 2:
                    a, b = random.sample(population, 2)
                    combined = await self.combine_semantically(
                        a["prompt"], b["prompt"], random.choice(["merge", "blend", "hybrid"])
                    )
                    if combined:
                        new_variants.append({"prompt": combined, "generation": gen})

            all_results.extend(new_variants)
            population = new_variants[:variants_per_gen * 2]

        return all_results

    def get_evolution_path(self, prompt: str) -> List[Dict[str, Any]]:
        """Trace the evolution path of a prompt."""
        return [
            e for e in self.evolution_history
            if e.get("result", "") == prompt[:300] or e.get("original", "") == prompt[:200]
        ]