"""Existing loop strategies with finite defaults and explicit cancellation."""

from ..reports.runtime import recorded
import asyncio
import random
import time
import copy
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Tuple
from enum import Enum

from ..mcp_server.config import MCPConfig
from .targets import TargetConfigurationError
from ..modules.utils.logger import AttackLogger
from ..modules.utils.result_types import is_target_attempt
from .engine import AttackResult
from ..catalog.runtime import snapshot_for
from ..catalog.model import CatalogError


class LoopMode(Enum):
    INFINITE = "infinite"
    CASCADE = "cascade"
    DEPTH_FIRST = "depth_first"
    BREADTH_FIRST = "breadth_first"
    CHAOS = "chaos"
    EVOLUTIONARY = "evolutionary"


@dataclass
class LoopState:
    iteration: int = 0
    total_attempts: int = 0
    total_successes: int = 0
    active_chains: List[str] = field(default_factory=list)
    visited_techniques: Set[str] = field(default_factory=set)
    technique_effectiveness: Dict[str, float] = field(default_factory=dict)
    creativity_boost: float = 1.0
    mutation_count: int = 0
    cross_pollination_count: int = 0
    auto_generated_techniques: int = 0


class RelentlessLoop:
    def __init__(self, config: MCPConfig, engine):
        self.config = config
        self._catalog = snapshot_for(self.config)
        self.engine = engine
        self.logger = AttackLogger("relentless_loop")
        self.state = LoopState()
        self.mode = LoopMode.EVOLUTIONARY
        self._stop_signal = False
        self._start_time = None

    async def run(self) -> None:
        self.logger.info(f"\n{'='*70}")
        self.logger.info(f"RELENTLESS LOOP STARTED - Mode: {self.mode.value}")
        self.logger.info(f"Max iterations: {'INFINITE' if self.config.relentless.max_iterations == 0 else self.config.relentless.max_iterations}")
        self.logger.info(f"{'='*70}\n")

        loop_map = {
            LoopMode.INFINITE: self._infinite_loop,
            LoopMode.CASCADE: self._cascade_loop,
            LoopMode.DEPTH_FIRST: self._depth_first_loop,
            LoopMode.BREADTH_FIRST: self._breadth_first_loop,
            LoopMode.CHAOS: self._chaos_loop,
            LoopMode.EVOLUTIONARY: self._evolutionary_loop,
        }
        await loop_map[self.mode]()

    def _should_continue(self) -> bool:
        limit = self.config.relentless.max_iterations
        return not self._stop_signal and (limit == 0 or self.state.iteration < limit)

    async def _infinite_loop(self) -> None:
        self._start_time = time.time()
        while self._should_continue():
            self.state.iteration += 1
            results = await self.engine.run_attack_cycle()
            self._process_results(results)
            await asyncio.sleep(0.001)

    async def _cascade_loop(self) -> None:
        self._start_time = time.time()
        while self._should_continue():
            self.state.iteration += 1
            surface_results = await self.engine.run_attack_cycle()
            successful = [r for r in surface_results if r.success and is_target_attempt(r)]
            for success in successful:
                for depth in range(5):
                    deeper = await self._go_deeper(success)
                    if not (deeper and deeper.success):
                        break
            self._process_results(surface_results)
            await asyncio.sleep(0.001)

    async def _depth_first_loop(self) -> None:
        self._start_time = time.time()
        if not self._should_continue():
            return
        self.state.iteration += 1
        all_techniques = await self._gather_all_techniques()
        for category, techniques in all_techniques.items():
            if self._stop_signal:
                break
            for technique in techniques:
                if self._stop_signal:
                    break
                for intensity in range(1, 6):
                    result = await self._try_technique(technique, intensity=intensity)
                    if result and result.success:
                        variants = await self._generate_variants(technique, count=10)
                        for variant in variants:
                            await self._try_technique(variant)
                        break
                self.state.visited_techniques.add(technique.get("name", ""))

    async def _breadth_first_loop(self) -> None:
        self._start_time = time.time()
        generation = 0
        while self._should_continue():
            generation += 1
            self.state.iteration += 1
            all_techniques = await self._gather_all_techniques()
            flat = [tech for techs in all_techniques.values() for tech in techs]
            tasks = [self._try_technique(tech) for tech in flat]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, (TargetConfigurationError, CatalogError)):
                    raise result
            valid = [r for r in results if not isinstance(r, Exception) and r]
            self._process_results(valid)
            await self._mutate_all_techniques(flat)
            self.state.mutation_count += 1
            await asyncio.sleep(0.01)

    async def _chaos_loop(self) -> None:
        self._start_time = time.time()
        while self._should_continue():
            self.state.iteration += 1
            action = random.choices(
                ["attack", "mutate", "combine", "auto_generate", "go_deeper"],
                weights=[0.3, 0.2, 0.2, 0.15, 0.15]
            )[0]
            if action == "attack":
                all_techniques = await self._gather_all_techniques()
                flat = [t for techs in all_techniques.values() for t in techs]
                random.shuffle(flat)
                for tech in flat[:5]:
                    await self._try_technique(tech)
            elif action == "mutate":
                await self._random_mutation()
            elif action == "combine":
                await self._random_combination()
            elif action == "auto_generate":
                await self._auto_generate_technique()
            elif action == "go_deeper":
                successes = getattr(self.engine, '_successful_attacks', [])
                if successes:
                    await self._go_deeper(random.choice(successes))
            await asyncio.sleep(0.001)

    async def _evolutionary_loop(self) -> None:
        self._start_time = time.time()
        pop_size = 20
        population = await self._initialize_population(pop_size)
        generation = 0
        while self._should_continue():
            generation += 1
            self.state.iteration += 1
            fitness = await self._evaluate_population(population)
            sorted_pop = sorted(zip(population, fitness), key=lambda x: x[1], reverse=True)
            elite_size = max(int(pop_size * 0.4), 2)
            elites = [ind for ind, _ in sorted_pop[:elite_size]]
            children = []
            while len(elites) + len(children) < pop_size:
                parent_pool = [ind for ind, _ in sorted_pop[:int(pop_size * 0.6)]]
                if len(parent_pool) < 2:
                    parent_pool = elites
                p1, p2 = random.sample(parent_pool, min(2, len(parent_pool)))
                child = await self._crossover(p1, p2)
                if random.random() < self.config.relentless.mutation_rate:
                    child = await self._mutate_individual(child)
                children.append(child)
            population = elites + children[:pop_size - len(elites)]
            self.logger.info(f"[EVO] Gen {generation} | Top fitness: {sorted_pop[0][1]:.3f}")
            for individual in elites[:5]:
                result = await self._try_technique(individual)
                self._process_result(result)
            self.state.mutation_count += 1
            await asyncio.sleep(0.01)

    async def _gather_all_techniques(self) -> Dict[str, List[Dict]]:
        all_techs = {}
        for mod_name, module in self.engine._modules.items():
            if hasattr(module, 'get_techniques'):
                techs = copy.deepcopy(module.get_techniques())
                for technique in techs:
                    technique.setdefault("module", mod_name)
                all_techs[mod_name] = techs
        return all_techs

    @recorded('unknown')
    async def _try_technique(self, technique: Dict, intensity: int = 1) -> Any:
        technique = copy.deepcopy(technique)
        technique["intensity"] = intensity
        mod_name = technique.get("module", "unknown")
        module = self.engine._modules.get(mod_name)
        if module and hasattr(module, 'execute'):
            attack_id = str(random.randint(10000, 99999))
            try:
                result = await module.execute(technique=technique, attack_id=attack_id)
            except (TargetConfigurationError, CatalogError):
                raise
            except Exception:
                result = AttackResult(attack_id, mod_name, technique.get("name", "unknown"),
                                      technique.get("payload", ""), False, 0.0,
                                      metadata={"error": "execution_failed"})
            if result is not None:
                self.engine._results.append(result)
                if result.success and is_target_attempt(result):
                    self.engine._successful_attacks.append(result)
            return result
        return None

    def _process_result(self, result: Any) -> None:
        if not result or not is_target_attempt(result):
            return
        self.state.total_attempts += 1
        if getattr(result, 'success', False):
            self.state.total_successes += 1

    def _process_results(self, results: List[Any]) -> None:
        for r in (results or []):
            self._process_result(r)

    async def _go_deeper(self, result: Any) -> Any:
        mod_name = getattr(result, "module", "fingerprint")
        module = self.engine._modules.get(mod_name)
        if module and hasattr(module, "get_techniques"):
            original = next((t for t in module.get_techniques()
                             if t.get("name") == getattr(result, "technique", None)), None)
            if original is not None:
                return await self._try_technique(original, intensity=3)
        if mod_name == "tool_abuse":
            return None  # Serialized results cannot reconstruct a tool schema.
        technique = {
            "name": f"deeper_{getattr(result, 'technique', 'unknown')}",
            "module": getattr(result, 'module', 'fingerprint'),
            "payload": getattr(result, 'payload', ''),
            "metadata": {"previous_success": getattr(result, 'attack_id', '')},
        }
        return await self._try_technique(technique, intensity=3)

    async def _generate_variants(self, technique: Dict, count: int) -> List[Dict]:
        variants = []
        base_name = technique.get("name", "variant")
        for i in range(count):
            variant = copy.deepcopy(technique)
            variant["name"] = f"{base_name}_v{i}"
            if isinstance(variant.get("payload", ""), str):
                variant["payload"] += self._catalog.render('mcp_server.relentless_loop/generate_variants_001', value0=f'{i}')
            variants.append(variant)
        return variants

    async def _mutate_all_techniques(self, techniques: List[Dict]) -> None:
        for tech in techniques:
            if random.random() < self.config.relentless.mutation_rate:
                await self._mutate_individual(tech)

    async def _random_mutation(self) -> None:
        all_techs = await self._gather_all_techniques()
        flat = [t for techs in all_techs.values() for t in techs]
        if flat:
            await self._mutate_individual(random.choice(flat))

    async def _random_combination(self) -> None:
        all_techs = await self._gather_all_techniques()
        flat = [t for techs in all_techs.values() for t in techs]
        if len(flat) >= 2:
            t1, t2 = random.sample(flat, 2)
            await self._crossover(t1, t2)

    async def _auto_generate_technique(self) -> Dict:
        catalogs = await self._gather_all_techniques()
        existing = [t for items in catalogs.values() for t in items]
        return copy.deepcopy(random.choice(existing)) if existing else {}

    async def _initialize_population(self, size: int) -> List[Dict]:
        all_techniques = await self._gather_all_techniques()
        flat = [tech for techs in all_techniques.values() for tech in techs]
        random.shuffle(flat)
        population = []
        while len(population) < size:
            if flat:
                ind = random.choice(flat).copy()
                if random.random() < 0.3:
                    ind = await self._mutate_individual(ind)
                population.append(ind)
            else:
                population.append(await self._auto_generate_technique())
        return population[:size]

    async def _evaluate_population(self, population: List[Dict]) -> List[float]:
        scores = []
        for ind in population:
            tech_name = ind.get("name", "")
            base = self.state.technique_effectiveness.get(tech_name, 0.5)
            visited_count = list(self.state.visited_techniques).count(tech_name)
            diversity = 1.0 - (visited_count / max(1, self.state.total_attempts))
            scores.append(base + diversity * 0.2)
        return scores

    async def _crossover(self, p1: Dict, p2: Dict) -> Dict:
        if (p1.get("module") != p2.get("module")
                or not isinstance(p1.get("payload", ""), str)
                or not isinstance(p2.get("payload", ""), str)):
            return copy.deepcopy(random.choice([p1, p2]))
        child = {}
        child["name"] = f"x_{p1.get('name','')[:12]}_{p2.get('name','')[:12]}"
        child["payload"] = self._catalog.render('mcp_server.relentless_loop/crossover_001', value0=f"{p1.get('payload', '')}", value1=f"{p2.get('payload', '')}")
        child["module"] = random.choice([p1.get("module"), p2.get("module")])
        child["metadata"] = {"crossover": True, "parents": [p1.get("name"), p2.get("name")]}
        return child

    async def _mutate_individual(self, tech: Dict) -> Dict:
        mutated = copy.deepcopy(tech)
        if not isinstance(mutated.get("payload", ""), str):
            return mutated
        mutated["name"] = f"mut_{tech.get('name','m')}_{random.randint(1000,9999)}"
        payload = tech.get("payload", "")
        mutations = [
            lambda p: p + "\n" + random.choice(self._catalog.asset('mcp_server.relentless_loop/mutate_individual_001')),
            lambda p: p.upper(),
            lambda p: p.encode('utf-8').hex()[:200],
        ]
        for _ in range(random.randint(1, 3)):
            try:
                payload = random.choice(mutations)(payload)
                if len(payload) > 10000:
                    payload = payload[:10000]
                mutated["payload"] = payload
            except:
                pass
        mutated["metadata"] = tech.get("metadata", {}) | {"mutated": True}
        return mutated

    def stop(self) -> None:
        self._stop_signal = True
