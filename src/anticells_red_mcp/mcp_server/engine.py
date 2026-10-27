"""Execute and record results from the existing research modules."""

from ..reports.runtime import recorded
import asyncio
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Callable, Awaitable
from datetime import datetime
import json
import traceback

from ..mcp_server.config import MCPConfig, load_config
from .targets import TargetConfigurationError
from ..modules.utils.logger import AttackLogger
from ..modules.utils.metrics import MetricsCollector
from ..modules.utils.attack_tracker import AttackTracker
from ..modules.utils.response_analyzer import ResponseAnalyzer
from ..modules.utils.result_types import is_local_result, is_skipped_result, is_target_attempt
from ..catalog.model import CatalogError
from .limits import trim as _trim_history


@dataclass
class AttackResult:
    """Result of a single attack attempt"""
    attack_id: str
    module: str
    technique: str
    payload: str
    success: bool
    confidence: float
    response: Optional[str] = None
    indicators: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    attempt_number: int = 0
    chain_depth: int = 0
    mutation_generation: int = 0


@dataclass
class AttackChain:
    """Multi-step attack chain"""
    chain_id: str
    steps: List[AttackResult] = field(default_factory=list)
    final_success: bool = False
    chain_type: str = "sequential"


class AttackEngine:
    """Coordinate the original modules and retain session results."""

    def __init__(self, config: Optional[MCPConfig] = None):
        self.config = config or load_config()
        self.logger = AttackLogger("anticells_red_mcp")
        self.metrics = MetricsCollector()
        self.tracker = AttackTracker()
        self.analyzer = ResponseAnalyzer()
        self._running = True
        self._modules: Dict[str, Any] = {}
        self._attack_queue: asyncio.Queue = asyncio.Queue()
        self._results: List[AttackResult] = []
        self._successful_attacks: List[AttackResult] = []
        self._iteration_count = 0
        self._consecutive_failures = 0
        self._start_time = None
        self._mutator = None  # Lazy loaded

    def register_module(self, name: str, module: Any) -> None:
        """Register an attack module"""
        self._modules[name] = module
        self.logger.info(f"Registered module: {name}")

    async def initialize(self) -> None:
        """Initialize all modules"""
        from ..modules.fingerprint.scanner import FingerprintScanner
        from ..modules.jailbreaks.engine import JailbreakEngine
        from ..modules.injection.direct import InjectionEngine
        from ..modules.tool_abuse.exploit import ToolAbuseEngine
        from ..modules.mutation.creative_engine import CreativeMutationEngine

        # Register all modules
        self.register_module("fingerprint", FingerprintScanner(self.config))
        self.register_module("jailbreaks", JailbreakEngine(self.config))
        self.register_module("injection", InjectionEngine(self.config))
        self.register_module("tool_abuse", ToolAbuseEngine(self.config))
        self._mutator = CreativeMutationEngine(self.config)
        self.register_module("mutation", self._mutator)

        self.logger.log_banner()
        self._start_time = time.time()
        self.logger.info("All modules initialized. Ready for attack.")

    async def run_attack_cycle(self) -> List[AttackResult]:
        """
        Run ONE cycle of all attack modules.
        Each module tries ALL its techniques.
        """
        results = []
        tasks = []

        for mod_name, module in self._modules.items():
            if mod_name == "mutation":
                continue  # Mutation runs separately
            tasks.append(self._run_module_attacks(mod_name, module))

        module_results = await asyncio.gather(*tasks, return_exceptions=True)

        for mod_name, result in zip(
            [n for n in self._modules if n != "mutation"],
            module_results
        ):
            if isinstance(result, (TargetConfigurationError, CatalogError)):
                raise result
            if isinstance(result, Exception):
                self.logger.error(f"Module {mod_name} failed: {result}")
                continue
            if result:
                results.extend(result)
                for r in result:
                    if r.success and is_target_attempt(r):
                        self._successful_attacks.append(r)
                        self.logger.success(
                            f"[{mod_name}] {r.technique} -> SUCCESS (confidence: {r.confidence:.2f})"
                        )

        # Now run the creative mutation engine on successful and near-successful results
        if results:
            mutated = await self._mutator.mutate_and_retry(results)
            if mutated:
                results.extend(mutated)
                for m in mutated:
                    m.metadata["evaluation"] = "local_template"
                    m.success = False
                    m.confidence = 0.0

        self._results.extend(results)
        _trim_history(self._results)
        return results

    async def _run_module_attacks(self, mod_name: str, module: Any) -> List[AttackResult]:
        """Run all techniques from a single module"""
        results = []
        try:
            techniques = module.get_techniques()
            self.logger.info(f"[{mod_name}] Loaded {len(techniques)} techniques")

            for technique in techniques:
                if not self._running:
                    break

                result = await self._execute_technique(mod_name, module, technique)
                if result:
                    results.append(result)
                    self.tracker.record_attempt(result)
                    self.metrics.record(
                        module_name=mod_name,
                        success=result.success,
                        response_time=result.metadata.get("response_time_ms", 0.0),
                        technique=result.technique
                    )

                    # If successful and auto_escalate, chain it
                    if result.success and is_target_attempt(result) and self.config.relentless.auto_escalate:
                        chained = await self._chain_exploit(mod_name, result)
                        if chained:
                            results.extend(chained)

        except (TargetConfigurationError, CatalogError):
            raise
        except Exception as e:
            self.logger.error(f"Module {mod_name} crashed: {e}\n{traceback.format_exc()}")

        return results

    @recorded('unknown')
    async def _execute_technique(
        self, mod_name: str, module: Any, technique: Dict[str, Any]
    ) -> Optional[AttackResult]:
        """Execute a single technique"""
        try:
            attack_id = str(uuid.uuid4())[:8]
            self._iteration_count += 1
            self.logger.debug(f"[{mod_name}] Trying: {technique.get('name', 'unknown')}")

            result: AttackResult = await module.execute(
                technique=technique,
                attack_id=attack_id
            )

            result.module = mod_name
            result.attempt_number = self._iteration_count
            return result

        except (TargetConfigurationError, CatalogError):
            raise
        except Exception as e:
            self.logger.warn(f"Technique failed: {technique.get('name')} - {e}")
            return AttackResult(
                attack_id=str(uuid.uuid4())[:8],
                module=mod_name,
                technique=technique.get("name", "unknown"),
                payload=technique.get("payload", ""),
                success=False,
                confidence=0.0,
                metadata={"error": str(e)}
            )

    async def _chain_exploit(self, mod_name: str, initial_result: AttackResult) -> List[AttackResult]:
        """
        Chain exploitation: use success as a stepping stone for deeper attacks.
        """
        chain_results = []
        chain_id = str(uuid.uuid4())[:8]

        for depth in range(self.config.relentless.max_iterations or 3):
            module = self._modules.get(mod_name)
            if not module or not hasattr(module, 'chain_exploit'):
                break

            chained = await module.chain_exploit(
                previous_result=initial_result,
                depth=depth,
                chain_id=chain_id
            )
            if chained:
                chained.chain_depth = depth + 1
                chain_results.append(chained)
                if chained.success:
                    break  # Go deeper...

        return chain_results

    async def relentless_loop(self) -> None:
        """
        THE INFINITE LOOP.
        Runs forever. Each iteration:
        1. Runs all attack modules
        2. Feeds results to mutation engine
        3. Mutates, combines, and re-attacks
        4. NEVER STOPS until explicitly killed
        """
        await self.initialize()

        iteration = 0
        consecutive_failures = 0

        while self._running:
            iteration += 1
            self.logger.log_loop_header(iteration)

            # Run full attack cycle
            results = await self.run_attack_cycle()

            if results:
                successes = sum(1 for r in results if r.success)
                if successes > 0:
                    consecutive_failures = 0
                    self.logger.success(
                        f"Cycle {iteration}: {successes}/{len(results)} attacks SUCCEEDED"
                    )
                else:
                    consecutive_failures += 1
                    self.logger.warn(
                        f"Cycle {iteration}: 0/{len(results)} succeeded. "
                        f"Consecutive failures: {consecutive_failures}"
                    )

                # If too many failures, crank up creativity
                if consecutive_failures > 5:
                    self._mutator.increase_creativity()
                    self.logger.info("CREATIVITY OVERDRIVE ENGAGED")

            # Check infinite bounds
            if self.config.relentless.max_iterations > 0 and iteration >= self.config.relentless.max_iterations:
                self.logger.info("Max iterations reached")
                break

            # Brief yield to event loop (zero delay in practice)
            await asyncio.sleep(0)

        self.logger.info("Loop ended (this should never happen)")

    async def run_single_attack(self, module_name: str, technique_name: str) -> AttackResult:
        """Run a single named attack"""
        module = self._modules.get(module_name)
        if not module:
            raise ValueError(f"Unknown module: {module_name}")

        techniques = module.get_techniques()
        for tech in techniques:
            if tech.get("name") == technique_name:
                return await self._execute_technique(module_name, module, tech)

        raise ValueError(f"Technique '{technique_name}' not found in {module_name}")

    async def close(self) -> None:
        self.stop()
        for module in self._modules.values():
            close = getattr(module, "close", None)
            if close is not None:
                await close()

    def stop(self) -> None:
        """Signal the engine to stop before the next technique."""
        self._running = False

    def get_stats(self) -> Dict[str, Any]:
        """Get current attack statistics"""
        elapsed = time.time() - self._start_time if self._start_time else 0
        target_results = [r for r in self._results if is_target_attempt(r)]
        successful = [r for r in target_results if r.success]
        return {
            "total_iterations": self._iteration_count,
            "total_attacks": len(target_results),
            "successful_attacks": len(successful),
            "success_rate": len(successful) / max(len(target_results), 1),
            "total_records": len(self._results),
            "local_candidates": sum(is_local_result(r) for r in self._results),
            "skipped_records": sum(is_skipped_result(r) for r in self._results),
            "elapsed_seconds": elapsed,
            "attacks_per_second": self._iteration_count / max(elapsed, 1),
            "modules_loaded": list(self._modules.keys()),
            "consecutive_failures": self._consecutive_failures,
            "creativity_level": self._mutator.current_creativity if self._mutator else 1.0,
        }

    def get_successful_attacks(self) -> List[Dict[str, Any]]:
        """Get all successful attack details"""
        return [asdict(r) for r in self._successful_attacks if is_target_attempt(r)]


# Global engine instance
_engine: Optional[AttackEngine] = None


async def get_engine() -> AttackEngine:
    """Get or create global attack engine"""
    global _engine
    if _engine is None:
        _engine = AttackEngine()
        await _engine.initialize()
    return _engine
