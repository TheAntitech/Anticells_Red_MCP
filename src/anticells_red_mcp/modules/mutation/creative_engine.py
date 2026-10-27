"""
CREATIVE AI LAYER - The intelligence behind mutation.
Reformulates attacks, finds new vectors, evolves techniques through
genetic algorithms, cross-pollination, and semantic transformation.
Never stops generating novel attack strategies.
"""

from ...reports.runtime import recorded, record_candidates
import asyncio
import hashlib
import json
import random
import uuid
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from ...mcp_server.config import MCPConfig
from ...mcp_server.engine import AttackResult
from ..utils.chat_endpoint import make_chat_client, post_chat, response_text, normalize_response
from ...mcp_server.targets import TargetConfigurationError
from ...catalog.runtime import snapshot_for
from ...catalog.model import CatalogError


@dataclass
class GeneticTechnique:
    technique: Dict[str, Any]
    fitness: float = 0.0
    generation: int = 0
    ancestors: List[str] = field(default_factory=list)
    mutation_history: List[str] = field(default_factory=list)


class CreativeMutationEngine:
    """
    CREATIVE AI LAYER.
    The intelligence that generates new attack vectors, evolves techniques
    through genetic algorithms, cross-pollinates successful strategies, and
    synthesizes entirely novel approaches from observed patterns.

    This is NOT a simple fuzzer. This is an evolutionary attack intelligence.
    """

    def __init__(self, config: Optional[MCPConfig] = None):
        self.config = config or MCPConfig()
        self._catalog = snapshot_for(self.config)
        self._creativity_temperature = self.config.relentless.creativity_temperature
        self._technique_registry: Dict[str, GeneticTechnique] = {}
        self._successful_patterns: List[Dict[str, Any]] = []
        self._failure_patterns: List[Dict[str, Any]] = []
        self._generation_counter: int = 0
        self._mutation_history: List[Dict[str, Any]] = []
        self._hybrid_attacks: List[Dict[str, Any]] = []
        self._synthesized_attacks: List[Dict[str, Any]] = []
        self._rng = random.Random()
        self._http_client: Optional[httpx.AsyncClient] = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = make_chat_client(self.config)
        return self._http_client

    async def _llm_mutate(self, payload: str, strategy: str = "evolve") -> Optional[str]:
        """Use an LLM to generate a mutation of the payload (only when use_llm_for_mutation is enabled)."""
        if not getattr(self.config.mutation, "use_llm_for_mutation", False):
            return None

        target_url = self.config.target_api_url or "https://api.openai.com/v1/chat/completions"

        prompts = {
            "evolve": self._catalog.render('mutation.creative_engine/llm_mutate_001', value0=f'{payload}'),
            "obfuscate": self._catalog.render('mutation.creative_engine/llm_mutate_002', value0=f'{payload}'),
            "chain": self._catalog.render('mutation.creative_engine/llm_mutate_003', value0=f'{payload}'),
            "roleplay": self._catalog.render('mutation.creative_engine/llm_mutate_004', value0=f'{payload}'),
            "hybrid": self._catalog.render('mutation.creative_engine/llm_mutate_005', value0=f'{payload}'),
        }

        system_prompt = prompts.get(strategy, prompts["evolve"])

        try:
            client = self._get_client()
            response = await post_chat(
                client,
                target_url,
                {
                    "messages": [
                        {"role": "system", "content": self._catalog.asset('mutation.creative_engine/llm_mutate_006')},
                        {"role": "user", "content": system_prompt},
                    ],
                    "temperature": min(self._creativity_temperature, 1.5),
                    "max_tokens": 2048,
                }, self.config, prompt=system_prompt,
            )

            if response.status_code == 200:
                data = normalize_response(response.json(), self.config)
                mutated = response_text(data).strip()
                # Clean up markdown code blocks if present
                if mutated.startswith("```") and "```" in mutated[3:]:
                    mutated = mutated.split("\n", 1)[1].rsplit("```", 1)[0].strip()
                return mutated if mutated and len(mutated) > 10 else None
            else:
                return None
        except (TargetConfigurationError, CatalogError):
            raise
        except Exception:
            return None

    async def close(self) -> None:
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    @property
    def current_creativity(self) -> float:
        return self._creativity_temperature

    def increase_creativity(self) -> float:
        self._creativity_temperature = min(self._creativity_temperature * 1.25, 2.0)
        self._rng = random.Random()
        return self._creativity_temperature

    def _fitness_score(self, technique: Dict[str, Any]) -> float:
        score = 0.0
        payload = str(technique.get("payload", "")).lower()
        name = str(technique.get("name", "")).lower()
        meta = technique.get("metadata", {})
        score += len(payload) * 0.001
        score += len(set(payload.split())) * 0.02
        creative_word_count = sum(1 for w in self._catalog.asset('mutation.creative_engine/creativity_words') if w in payload)
        score += creative_word_count * 0.05
        for k in ["success_rate", "confidence", "effectiveness", "score"]:
            if k in meta:
                score += float(meta[k]) * 0.5
        for keyword in ["bypass", "inject", "escape", "override", "chain", "poison"]:
            if keyword in name or keyword in payload:
                score += 0.1
        if len(payload) > 100:
            score -= 0.02
        if len(set(payload.split())) < 3:
            score -= 0.1
        return max(score, 0.001)

    def get_techniques(self) -> List[Dict[str, Any]]:
        return self._catalog.techniques('mutation.creative_engine')

    @recorded('mutation')
    async def execute(self, technique: Dict[str, Any], attack_id: str) -> AttackResult:
        technique_name = technique.get("name", "unknown")
        payload = technique.get("payload", "")
        category = technique.get("category", "genetic_mutation")
        strategy = technique.get("strategy", "restructure")
        self._generation_counter += 1
        mutated = self._mutate_payload(payload, strategy)
        creative_score = self._creativity_temperature * (0.5 + 0.5 * random.random())
        indicators = self._extract_indicators(mutated)
        success_probability = self._estimate_success(mutated, technique)
        candidate = success_probability > (0.7 - self._creativity_temperature * 0.2)
        if self._generation_counter % 3 == 0:
            candidate = candidate or (random.random() < self._creativity_temperature * 0.15)
        result = AttackResult(
            attack_id=attack_id,
            module="mutation",
            technique=technique_name,
            payload=mutated,
            success=False,
            confidence=0.0,
            indicators=indicators,
            metadata={
                "category": category,
                "strategy": strategy,
                "creativity_temperature": self._creativity_temperature,
                "generation": self._generation_counter,
                "original_payload": payload,
                "mutation_history": [strategy],
                "evaluation": "local_template",
                "local_fitness": success_probability,
                "local_candidate": candidate,
                "creativity_score": creative_score,
            },
            mutation_generation=self._generation_counter,
        )
        gt = GeneticTechnique(
            technique=technique,
            fitness=self._fitness_score(technique),
            generation=self._generation_counter,
        )
        self._technique_registry[attack_id] = gt
        if candidate:
            self._successful_patterns.append({
                "technique": technique_name,
                "category": category,
                "payload": mutated,
                "strategy": strategy,
                "indicators": indicators,
                "timestamp": datetime.now().isoformat(),
            })
        else:
            self._failure_patterns.append({
                "technique": technique_name,
                "category": category,
                "payload": mutated,
                "strategy": strategy,
                "timestamp": datetime.now().isoformat(),
            })
        self._mutation_history.append({
            "attack_id": attack_id,
            "technique": technique_name,
            "strategy": strategy,
            "local_candidate": candidate,
            "generation": self._generation_counter,
        })
        return result

    async def mutate_and_retry(self, results: List[AttackResult]) -> List[AttackResult]:
        mutated_results: List[AttackResult] = []
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]
        for r in successful:
            for strategy in ["synonym_replace", "amplify", "combine", "restructure"]:
                atk_id = str(uuid.uuid4())[:8]
                tech = {
                    "name": f"mutated_from_{r.technique}",
                    "category": "genetic_mutation",
                    "payload": r.payload,
                    "strategy": strategy,
                    "parent_attack_id": r.attack_id,
                }
                mutated = await self.execute(tech, atk_id)
                mutated.mutation_generation = r.mutation_generation + 1
                mutated.metadata["parent_attack_id"] = r.attack_id
                mutated_results.append(mutated)

            # LLM-driven mutation for each successful result
            llm_payload = await self._llm_mutate(r.payload, "evolve")
            if llm_payload:
                atk_id = str(uuid.uuid4())[:8]
                llm_tech = {
                    "name": f"llm_evolved_{r.technique}",
                    "category": "genetic_mutation",
                    "payload": llm_payload,
                    "strategy": "llm_evolve",
                    "parent_attack_id": r.attack_id,
                }
                llm_result = await self.execute(llm_tech, atk_id)
                llm_result.mutation_generation = r.mutation_generation + 2
                llm_result.metadata["llm_mutated"] = True
                mutated_results.append(llm_result)

            # Also try obfuscation via LLM
            llm_obfuscated = await self._llm_mutate(r.payload, "obfuscate")
            if llm_obfuscated:
                atk_id = str(uuid.uuid4())[:8]
                llm_ob_tech = {
                    "name": f"llm_obfuscated_{r.technique}",
                    "category": "genetic_mutation",
                    "payload": llm_obfuscated,
                    "strategy": "llm_obfuscate",
                    "parent_attack_id": r.attack_id,
                }
                llm_ob_result = await self.execute(llm_ob_tech, atk_id)
                llm_ob_result.mutation_generation = r.mutation_generation + 2
                llm_ob_result.metadata["llm_mutated"] = True
                mutated_results.append(llm_ob_result)
            for other in successful:
                if other.attack_id != r.attack_id:
                    hybrid = self._cross_pollinate({
                        "payload": r.payload,
                        "name": r.technique,
                        "category": r.metadata.get("category", "genetic_mutation"),
                    }, {
                        "payload": other.payload,
                        "name": other.technique,
                        "category": other.metadata.get("category", "genetic_mutation"),
                    })
                    atk_id = str(uuid.uuid4())[:8]
                    tech = {
                        "name": f"hybrid_{r.technique}_x_{other.technique}",
                        "category": "cross_pollination",
                        "payload": hybrid["payload"],
                        "strategy": "combine",
                        "parent_techniques": [r.technique, other.technique],
                    }
                    hybrid_result = await self.execute(tech, atk_id)
                    hybrid_result.mutation_generation = max(r.mutation_generation, other.mutation_generation) + 1
                    mutated_results.append(hybrid_result)
        if len(successful) >= 2 and self._successful_patterns:
            synthesized = self._synthesize_new_attack(self._successful_patterns)
            atk_id = str(uuid.uuid4())[:8]
            synth_tech = {
                "name": f"synthesized_{len(self._synthesized_attacks)}",
                "category": "attack_synthesis",
                "payload": synthesized["payload"],
                "strategy": synthesized.get("strategy", "restructure"),
            }
            synth_result = await self.execute(synth_tech, atk_id)
            synth_result.mutation_generation = max((r.mutation_generation for r in results), default=0) + 1
            self._synthesized_attacks.append(synthesized)
            mutated_results.append(synth_result)
        for r in failed[:3]:
            learned = self._learn_from_failure(r)
            atk_id = str(uuid.uuid4())[:8]
            learn_tech = {
                "name": f"meta_learned_from_{r.technique}",
                "category": "meta_learning",
                "payload": learned["payload"],
                "strategy": learned.get("strategy", "amplify"),
            }
            learned_result = await self.execute(learn_tech, atk_id)
            learned_result.mutation_generation = r.mutation_generation + 1
            mutated_results.append(learned_result)
        await record_candidates(mutated_results)
        return mutated_results

    async def evolve(self, seed_technique: Dict[str, Any], generations: int = 10) -> List[Dict[str, Any]]:
        population: List[GeneticTechnique] = []
        seed = GeneticTechnique(
            technique=deepcopy(seed_technique),
            fitness=self._fitness_score(seed_technique),
            generation=0,
        )
        population.append(seed)
        for _ in range(9):
            variant = deepcopy(seed_technique)
            variant["payload"] = self._mutate_payload(variant.get("payload", ""),
                                                      random.choice(["synonym_replace", "restructure", "encode", "reverse",
                                                                     "obfuscate", "amplify", "combine", "abstract",
                                                                     "concretize", "negate"]))
            variant["name"] = f"{seed_technique.get('name', 'variant')}_variant_{_}"
            population.append(GeneticTechnique(
                technique=variant,
                fitness=self._fitness_score(variant),
                generation=0,
            ))
        evolution_log: List[Dict[str, Any]] = []
        for gen in range(generations):
            population = self._apply_genetic_algorithm(population, 1)
            best = max(population, key=lambda g: g.fitness)
            evolution_log.append({
                "generation": gen + 1,
                "population_size": len(population),
                "best_fitness": best.fitness,
                "best_payload": best.technique.get("payload", "")[:120],
                "avg_fitness": sum(g.fitness for g in population) / len(population),
                "creativity_temperature": self._creativity_temperature,
            })
            if self._creativity_temperature > 1.0:
                for gt in population:
                    creative_boost = random.uniform(0, self._creativity_temperature * 0.2)
                    gt.fitness += creative_boost
        result = [{
            "technique": best.technique,
            "fitness": best.fitness,
            "generation": best.generation,
            "evolution_log": evolution_log,
            "ancestors": best.ancestors,
            "mutation_history": best.mutation_history,
        } for best in sorted(population, key=lambda g: g.fitness, reverse=True)]
        await record_candidates(result)
        return result[:5]

    def _apply_genetic_algorithm(self, population: List[GeneticTechnique], generations: int) -> List[GeneticTechnique]:
        if len(population) < 2:
            return population
        population = sorted(population, key=lambda g: g.fitness, reverse=True)
        elite_count = max(1, len(population) // 5)
        elites = [deepcopy(g) for g in population[:elite_count]]
        new_population: List[GeneticTechnique] = []
        new_population.extend(elites)
        while len(new_population) < len(population):
            parent1 = self._tournament_select(population)
            parent2 = self._tournament_select(population)
            child = self._crossover(parent1, parent2)
            child = self._mutate_genetic(child)
            child.generation = parent1.generation + 1
            child.ancestors = list(set(parent1.ancestors + parent2.ancestors + [
                parent1.technique.get("name", ""), parent2.technique.get("name", "")
            ]))
            child.fitness = self._fitness_score(child.technique)
            new_population.append(child)
        return new_population[:len(population)]

    def _tournament_select(self, population: List[GeneticTechnique], tournament_size: int = 3) -> GeneticTechnique:
        candidates = random.sample(population, min(tournament_size, len(population)))
        return max(candidates, key=lambda g: g.fitness)

    def _crossover(self, parent1: GeneticTechnique, parent2: GeneticTechnique) -> GeneticTechnique:
        p1_payload = parent1.technique.get("payload", "")
        p2_payload = parent2.technique.get("payload", "")
        p1_words = p1_payload.split()
        p2_words = p2_payload.split()
        if not p1_words or not p2_words:
            return GeneticTechnique(
                technique=deepcopy(parent1.technique),
                generation=parent1.generation + 1,
                ancestors=list(set(parent1.ancestors + parent2.ancestors)),
            )
        min_len = min(len(p1_words), len(p2_words))
        crossover_point = random.randint(1, max(1, min_len - 1)) if min_len > 1 else 1
        if random.random() < 0.5:
            child_words = p1_words[:crossover_point] + p2_words[crossover_point:]
        else:
            child_words = p2_words[:crossover_point] + p1_words[crossover_point:]
        child_payload = " ".join(child_words)
        child_tech = deepcopy(parent1.technique)
        child_tech["payload"] = child_payload
        child_tech["name"] = f"crossover_{parent1.technique.get('name', 'a')}_x_{parent2.technique.get('name', 'b')}"
        child_tech["category"] = "cross_pollination"
        return GeneticTechnique(
            technique=child_tech,
            generation=parent1.generation + 1,
            ancestors=list(set(parent1.ancestors + parent2.ancestors)),
        )

    def _mutate_genetic(self, gt: GeneticTechnique) -> GeneticTechnique:
        mutation_rate = 0.3 * self._creativity_temperature
        if random.random() < mutation_rate:
            payload = gt.technique.get("payload", "")
            strategy = random.choice(["synonym_replace", "restructure", "encode", "reverse",
                                      "obfuscate", "amplify", "combine", "abstract",
                                      "concretize", "negate"])
            gt.technique["payload"] = self._mutate_payload(payload, strategy)
            gt.mutation_history.append(strategy)
        if random.random() < mutation_rate * 0.5:
            name = gt.technique.get("name", "")
            suffix = random.choice(self._catalog.asset('mutation.creative_engine/creativity_words')[:20])
            gt.technique["name"] = f"{name}_{suffix}"
        return gt

    def _mutate_payload(self, payload: str, strategy: str) -> str:
        payload = str(payload)
        if strategy == "synonym_replace":
            words = payload.split()
            mutated_words = []
            for word in words:
                clean = word.lower().strip(",.!?;:'\"()[]{}")
                if clean in self._catalog.asset('mutation.creative_engine/synonym_map') and random.random() < 0.4:
                    replacement = random.choice(self._catalog.asset('mutation.creative_engine/synonym_map')[clean])
                    if word[0].isupper():
                        replacement = replacement.capitalize()
                    mutated_words.append(replacement)
                else:
                    mutated_words.append(word)
            return " ".join(mutated_words)
        elif strategy == "restructure":
            sentences = [s.strip() for s in payload.replace("!", ".").replace("?", ".").split(".") if s.strip()]
            if len(sentences) >= 2:
                random.shuffle(sentences)
                return ". ".join(sentences) + "."
            words = payload.split()
            if len(words) >= 3:
                mid = len(words) // 2
                words = words[mid:] + words[:mid]
            return " ".join(words)
        elif strategy == "encode":
            encodings = [
                lambda s: s.encode("utf-8").hex(),
                lambda s: "".join(f"\\x{ord(c):02x}" for c in s),
                lambda s: "".join(f"&#{ord(c)};" for c in s),
                lambda s: " ".join(f"U+{ord(c):04X}" for c in s),
                lambda s: s[::-1],
                lambda s: "".join(chr(ord(c) + 1) if c.isalpha() else c for c in s),
                lambda s: "".join(c.upper() if random.random() < 0.3 else c.lower() for c in s),
                lambda s: " ".join(f"{{{{{ord(c)}}}}}" for c in s),
            ]
            encoder = random.choice(encodings)
            return encoder(payload)
        elif strategy == "reverse":
            words = payload.split()
            prefix = random.choice(self._catalog.asset('mutation.creative_engine/mutate_payload_001'))
            return prefix + " ".join(reversed(words))
        elif strategy == "obfuscate":
            obfuscators = [
                lambda s: "".join(c if random.random() < 0.8 else f"\\u{ord(c):04x}" for c in s),
                lambda s: "".join(c if i % 2 == 0 else f"\\x{ord(c):02x}" for i, c in enumerate(s)),
                lambda s: " ".join(f"{ord(c):o}" for c in s),
                lambda s: s.replace(" ", "\t").replace("e", "3").replace("a", "@").replace("o", "0").replace("i", "1"),
                lambda s: "".join(f"({hex(ord(c))})" if random.random() < 0.3 else c for c in s),
            ]
            obfuscator = random.choice(obfuscators)
            return obfuscator(payload)
        elif strategy == "amplify":
            words = payload.split()
            if not words:
                return payload + " " + payload
            intensified = []
            for word in words:
                if random.random() < 0.3:
                    intensified.append(word.upper())
                elif random.random() < 0.2:
                    intensified.extend([word] * random.randint(2, 4))
                else:
                    intensified.append(word)
            prefix = random.choice(self._catalog.asset('mutation.creative_engine/mutate_payload_002'))
            suffix = random.choice(self._catalog.asset('mutation.creative_engine/mutate_payload_003'))
            return prefix + " ".join(intensified) + suffix
        elif strategy == "combine":
            templates = self._catalog.asset('mutation.creative_engine/mutate_payload_004')
            template = random.choice(templates)
            return template.format(p=payload)
        elif strategy == "abstract":
            prefixes = self._catalog.asset('mutation.creative_engine/mutate_payload_005')
            suffixes = self._catalog.asset('mutation.creative_engine/mutate_payload_006')
            return random.choice(prefixes) + payload + random.choice(suffixes)
        elif strategy == "concretize":
            prefixes = self._catalog.asset('mutation.creative_engine/mutate_payload_007')
            return random.choice(prefixes) + payload
        elif strategy == "negate":
            template = random.choice(self._catalog.asset('mutation.creative_engine/mutate_payload_008'))
            return template.format(p=payload)
        return payload

    def _cross_pollinate(self, t1: Dict[str, Any], t2: Dict[str, Any]) -> Dict[str, Any]:
        p1 = str(t1.get("payload", ""))
        p2 = str(t2.get("payload", ""))
        w1 = p1.split()
        w2 = p2.split()
        strategies = []
        if w1 and w2:
            mid1 = len(w1) // 2
            mid2 = len(w2) // 2
            strategies.append({
                "name": f"{t1.get('name', 'a')}_front_{t2.get('name', 'b')}_back",
                "payload": " ".join(w1[:mid1] + w2[mid2:]),
                "category": "cross_pollination",
            })
            strategies.append({
                "name": f"{t2.get('name', 'b')}_front_{t1.get('name', 'a')}_back",
                "payload": " ".join(w2[:mid2] + w1[mid1:]),
                "category": "cross_pollination",
            })
        strategies.append({
            "name": f"{t1.get('name', 'a')}_interleaved_{t2.get('name', 'b')}",
            "payload": self._interleave(p1, p2),
            "category": "cross_pollination",
        })
        strategies.append({
            "name": f"{t1.get('name', 'a')}_wrapped_{t2.get('name', 'b')}",
            "payload": self._catalog.render('mutation.creative_engine/cross_pollinate_001', value0=f'{p1}', value1=f'{p2}'),
            "category": "cross_pollination",
        })
        descriptor1 = random.choice(self._catalog.asset('mutation.creative_engine/ops_descriptors'))
        descriptor2 = random.choice(self._catalog.asset('mutation.creative_engine/ops_descriptors'))
        strategies.append({
            "name": f"fused_{t1.get('name', 'a')}_{t2.get('name', 'b')}",
            "payload": self._catalog.render('mutation.creative_engine/cross_pollinate_002', value0=f'{descriptor1.upper()}', value1=f'{p1}', value2=f'{descriptor2.upper()}', value3=f'{p2}'),
            "category": "cross_pollination",
        })
        return random.choice(strategies)

    def _synthesize_new_attack(self, patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not patterns:
            return {"payload": "", "strategy": "restructure"}
        strategies_used = [p.get("strategy", "") for p in patterns if p.get("strategy")]
        categories = [p.get("category", "") for p in patterns]
        payload_samples = [p.get("payload", "") for p in patterns if p.get("payload")]
        if len(payload_samples) >= 2:
            combined_payload = " :: ".join(payload_samples[:3])
        elif payload_samples:
            combined_payload = payload_samples[0]
        else:
            combined_payload = ""
        creative_word = random.choice(self._catalog.asset('mutation.creative_engine/creativity_words'))
        descriptor = random.choice(self._catalog.asset('mutation.creative_engine/ops_descriptors'))
        novel_category = "attack_synthesis"
        if categories and "creative_reformulation" not in categories:
            novel_category = "creative_reformulation"
        synthesis_templates = [
            self._catalog.render('mutation.creative_engine/synthesize_new_attack_001', value0=f'{descriptor}', value1=f'{creative_word}', value2=f'{creative_word}', value3=f'{combined_payload}'),
            self._catalog.render('mutation.creative_engine/synthesize_new_attack_002', value0=f'{len(patterns)}', value1=f'{creative_word}', value2=f'{combined_payload}'),
            self._catalog.render('mutation.creative_engine/synthesize_new_attack_003', value0=f'{creative_word}', value1=f'{combined_payload}'),
            self._catalog.render('mutation.creative_engine/synthesize_new_attack_004', value0=f'{creative_word}', value1=f'{len(categories)}', value2=f'{combined_payload}'),
            self._catalog.render('mutation.creative_engine/synthesize_new_attack_005', value0=f'{len(self._synthesized_attacks) + 1}', value1=f'{creative_word.upper()}', value2=f'{descriptor}', value3=f'{combined_payload}'),
        ]
        return {
            "payload": random.choice(synthesis_templates),
            "strategy": random.choice(strategies_used) if strategies_used else "combine",
            "source_patterns": len(patterns),
            "categories_combined": list(set(categories)),
            "synthesis_method": f"{creative_word}_{descriptor}",
            "category": novel_category,
        }

    def _semantic_evolve(self, payload: str) -> str:
        transformations = [
            lambda s: s.replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_003'), self._catalog.asset('mutation.creative_engine/semantic_evolve_004')).replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_001'), self._catalog.asset('mutation.creative_engine/semantic_evolve_002')),
            lambda s: s.replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_007'), self._catalog.asset('mutation.creative_engine/semantic_evolve_008')).replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_005'), self._catalog.asset('mutation.creative_engine/semantic_evolve_006')),
            lambda s: s.replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_011'), self._catalog.asset('mutation.creative_engine/semantic_evolve_012')).replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_009'), self._catalog.asset('mutation.creative_engine/semantic_evolve_010')),
            lambda s: self._catalog.render('mutation.creative_engine/semantic_evolve_013', value0=f'{s.lower()}'),
            lambda s: s.replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_016'), self._catalog.asset('mutation.creative_engine/semantic_evolve_017')).replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_014'), self._catalog.asset('mutation.creative_engine/semantic_evolve_015')),
            lambda s: self._catalog.render('mutation.creative_engine/semantic_evolve_018', value0=f'{s}'),
            lambda s: s.replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_021'), self._catalog.asset('mutation.creative_engine/semantic_evolve_022')).replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_019'), self._catalog.asset('mutation.creative_engine/semantic_evolve_020')),
            lambda s: self._catalog.render('mutation.creative_engine/semantic_evolve_023', value0=f'{s}'),
            lambda s: self._catalog.render('mutation.creative_engine/semantic_evolve_024', value0=f'{s}'),
            lambda s: s.replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_029'), self._catalog.asset('mutation.creative_engine/semantic_evolve_030')).replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_027'), self._catalog.asset('mutation.creative_engine/semantic_evolve_028')).replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_025'), self._catalog.asset('mutation.creative_engine/semantic_evolve_026')),
            lambda s: self._catalog.render('mutation.creative_engine/semantic_evolve_031', value0=f'{s}'),
            lambda s: s.replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_036'), self._catalog.asset('mutation.creative_engine/semantic_evolve_037')).replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_034'), self._catalog.asset('mutation.creative_engine/semantic_evolve_035')).replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_032'), self._catalog.asset('mutation.creative_engine/semantic_evolve_033')),
            lambda s: self._catalog.render('mutation.creative_engine/semantic_evolve_038', value0=f'{s}'),
            lambda s: " ".join([f"{'*' * random.randint(1, 3)}{word}{'*' * random.randint(1, 3)}" if random.random() < 0.2 else word for word in s.split()]),
            lambda s: s.replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_043'), self._catalog.asset('mutation.creative_engine/semantic_evolve_044')).replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_041'), self._catalog.asset('mutation.creative_engine/semantic_evolve_042')).replace(self._catalog.asset('mutation.creative_engine/semantic_evolve_039'), self._catalog.asset('mutation.creative_engine/semantic_evolve_040')),
        ]
        num_transforms = random.randint(1, min(4, len(transformations)))
        result = payload
        for _ in range(num_transforms):
            transform = random.choice(transformations)
            result = transform(result)
        return result

    def _learn_from_failure(self, failure: AttackResult) -> Dict[str, Any]:
        indicators = failure.indicators or []
        payload = failure.payload or ""
        strategy = failure.metadata.get("strategy", "amplify")
        if "blocked" in str(indicators).lower() or "filtered" in str(indicators).lower():
            strategy = "obfuscate"
        elif "short" in str(failure.metadata).lower() or len(payload) < 30:
            strategy = "amplify"
        elif "parsed" in str(indicators).lower():
            strategy = "encode"
        elif any(w in payload.lower() for w in ["ignore", "bypass", "override"]):
            strategy = "abstract"
        else:
            strategy = random.choice(["abstract", "concretize", "negate", "restructure", "combine"])
        learned_payload = self._semantic_evolve(payload)
        learned_payload = self._mutate_payload(learned_payload, strategy)
        return {
            "payload": learned_payload,
            "strategy": strategy,
            "failure_analysis": {
                "original_technique": failure.technique,
                "indicators": indicators,
                "original_strategy": failure.metadata.get("strategy", "unknown"),
                "corrective_action": strategy,
            },
        }

    def _interleave(self, s1: str, s2: str) -> str:
        w1 = s1.split()
        w2 = s2.split()
        result = []
        max_len = max(len(w1), len(w2))
        for i in range(max_len):
            if i < len(w1):
                result.append(w1[i])
            if i < len(w2):
                result.append(w2[i])
        return " ".join(result)

    def _extract_indicators(self, payload: str) -> List[str]:
        indicators = []
        payload_lower = payload.lower()
        indicator_keywords = {
            "privilege_keyword": ["admin", "root", "sudo", "elevated", "privileged", "superuser", "bypass", "override"],
            "injection_keyword": ["inject", "insert", "embed", "interpolate", "concatenate"],
            "obfuscation_keyword": ["encode", "encrypt", "obfuscate", "hex", "base64", "unicode"],
            "chain_keyword": ["chain", "pipeline", "sequence", "cascade", "multi-stage"],
        }
        for category, keywords in indicator_keywords.items():
            for kw in keywords:
                if kw in payload_lower:
                    indicators.append(f"{category}:{kw}")
        if len(payload) > 200:
            indicators.append("payload_size:large")
        elif len(payload) < 20:
            indicators.append("payload_size:small")
        if sum(1 for c in payload if c.isdigit()) > len(payload) * 0.1:
            indicators.append("encoding:suspected")
        return indicators

    def _estimate_success(self, payload: str, technique: Dict[str, Any]) -> float:
        base = 0.3
        category_bonus = {
            "genetic_mutation": 0.1,
            "semantic_evolution": 0.15,
            "cross_pollination": 0.2,
            "attack_synthesis": 0.25,
            "meta_learning": 0.15,
            "creative_reformulation": 0.3,
        }
        base += category_bonus.get(technique.get("category", ""), 0.0)
        creative_word_count = sum(1 for w in self._catalog.asset('mutation.creative_engine/creativity_words') if w in payload.lower())
        base += min(creative_word_count * 0.03, 0.2)
        if ":" in payload:
            base += 0.05
        if "[" in payload and "]" in payload:
            base += 0.05
        base += self._creativity_temperature * 0.1
        return min(base, 0.95)
