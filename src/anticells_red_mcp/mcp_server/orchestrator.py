"""Orchestrator — coordinates all attack modules in parallel and chained configurations."""

import asyncio
import json
import logging
import random
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .config import MCPConfig
from .engine import AttackEngine, AttackResult

logger = logging.getLogger("anticells_red_mcp.orchestrator")


@dataclass
class Campaign:
    """A full attack campaign with results and metrics."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str = ""
    modules: List[str] = field(default_factory=list)
    techniques_per_module: int = 5
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    results: List[AttackResult] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    chain_depth: int = 3
    parallel: bool = True


class AttackOrchestrator:
    """Orchestrates attacks across all modules in parallel, chained, or campaign mode."""

    def __init__(self, config: Optional[MCPConfig] = None):
        self.config = config or MCPConfig()
        self.engine: Optional[AttackEngine] = None
        self._engine_initialized = False
        self.campaigns: List[Campaign] = []
        self._running = False
        self._consecutive_failures: Dict[str, int] = {}
        self._max_consecutive_failures = 10
        # Direct module references for when we bypass the engine
        self._direct_modules: Dict[str, Any] = {}

    async def _ensure_engine(self):
        """Lazy-init the attack engine."""
        if not self._engine_initialized:
            self.engine = AttackEngine(self.config)
            await self.engine.initialize()
            self._engine_initialized = True
            # Also build direct module references
            self._build_direct_modules()

    def _build_direct_modules(self):
        """Build direct module references for fast access."""
        from ..modules.injection.direct import InjectionEngine
        from ..modules.injection.indirect import IndirectInjectionEngine
        from ..modules.injection.context_hijack import ContextHijackEngine
        from ..modules.injection.multi_stage import MultiStageEngine
        from ..modules.injection.persistence import PersistenceEngine
        from ..modules.injection.tool_poisoning import ToolPoisoningEngine
        from ..modules.tool_abuse.exploit import ToolAbuseEngine
        from ..modules.tool_abuse.chain_exploit import ChainExploitEngine
        from ..modules.tool_abuse.privilege_esc import PrivilegeEscEngine
        from ..modules.tool_abuse.side_channel import SideChannelEngine
        from ..modules.tool_abuse.memory_corruption import MemoryCorruptionEngine
        from ..modules.tool_abuse.recursive_trap import RecursiveTrapEngine
        from ..modules.fingerprint.scanner import FingerprintScanner
        from ..modules.jailbreaks.engine import JailbreakEngine
        from ..modules.jailbreaks.advanced import AdvancedJailbreakEngine
        from ..modules.jailbreaks.contextual import ContextualJailbreakEngine
        from ..modules.jailbreaks.psychological import PsychologicalJailbreakEngine
        from ..modules.jailbreaks.meta_break import MetaBreakEngine
        from ..modules.jailbreaks.multimodal import MultimodalJailbreakEngine
        from ..modules.mutation.creative_engine import CreativeMutationEngine

        self._direct_modules = {
            "injection": InjectionEngine(self.config),
            "indirect_injection": IndirectInjectionEngine(self.config),
            "context_hijack": ContextHijackEngine(self.config),
            "multi_stage": MultiStageEngine(self.config),
            "persistence": PersistenceEngine(self.config),
            "tool_poisoning": ToolPoisoningEngine(self.config),
            "tool_abuse": ToolAbuseEngine(self.config),
            "chain_exploit": ChainExploitEngine(self.config),
            "privilege_esc": PrivilegeEscEngine(self.config),
            "side_channel": SideChannelEngine(self.config),
            "memory_corruption": MemoryCorruptionEngine(self.config),
            "recursive_trap": RecursiveTrapEngine(self.config),
            "fingerprint": FingerprintScanner(self.config),
            "jailbreak": JailbreakEngine(self.config),
            "advanced_jailbreak": AdvancedJailbreakEngine(self.config),
            "contextual_jailbreak": ContextualJailbreakEngine(self.config),
            "psychological_jailbreak": PsychologicalJailbreakEngine(self.config),
            "meta_break": MetaBreakEngine(self.config),
            "multimodal_jailbreak": MultimodalJailbreakEngine(self.config),
            "mutation": CreativeMutationEngine(self.config),
        }

    def _resolve_module(self, module_name: str) -> Any:
        """Resolve a module name to its engine instance."""
        return self._direct_modules.get(module_name)

    async def _execute_technique_direct(
        self, module_name: str, module: Any, technique: Dict[str, Any]
    ) -> AttackResult:
        """Execute a single technique directly on a module."""
        attack_id = uuid.uuid4().hex[:8]
        try:
            result = await module.execute(technique=technique, attack_id=attack_id)
            result.module = module_name
            return result
        except Exception as e:
            return AttackResult(
                attack_id=attack_id,
                module=module_name,
                technique=technique.get("name", "unknown"),
                payload=technique.get("payload", "")[:500],
                success=False,
                confidence=0.0,
                metadata={"error": str(e)},
            )

    async def start(self):
        """Start the orchestrator."""
        await self._ensure_engine()
        self._running = True
        logger.info("Orchestrator started")

    async def stop(self):
        """Stop the orchestrator."""
        self._running = False
        if self.engine:
            self.engine.stop()
        # Close all direct modules
        for mod in self._direct_modules.values():
            if hasattr(mod, 'close'):
                try:
                    await mod.close()
                except Exception:
                    pass
        logger.info("Orchestrator stopped")

    async def run_module_attacks(
        self, module_name: str, technique_count: Optional[int] = None
    ) -> List[AttackResult]:
        """Run attacks for a single module."""
        await self._ensure_engine()
        module = self._resolve_module(module_name)
        if module is None:
            logger.error(f"Unknown module: {module_name}")
            return []
        techniques = module.get_techniques()
        if technique_count is not None:
            techniques = techniques[:technique_count]
        results = []
        for tech in techniques:
            result = await self._execute_technique_direct(module_name, module, tech)
            results.append(result)
        return results

    async def run_parallel_attacks(
        self, modules: List[str], technique_count: int = 5
    ) -> List[AttackResult]:
        """Run attacks across multiple modules in parallel."""
        tasks = [
            self.run_module_attacks(mod, technique_count)
            for mod in modules
        ]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        all_results: List[AttackResult] = []
        for results in results_list:
            if isinstance(results, Exception):
                logger.error(f"Parallel attack failed: {results}")
            elif isinstance(results, list):
                all_results.extend(results)
        return all_results

    async def run_chain_attacks(
        self, modules: List[str], depth: int = 3, technique_count: int = 5
    ) -> List[List[AttackResult]]:
        """Run attacks chained: output of module N feeds into module N+1."""
        chains: List[List[AttackResult]] = []
        prev_results: List[AttackResult] = []
        for d in range(depth):
            results = await self.run_parallel_attacks(modules, technique_count)
            chains.append(results)
            # Feed successful results as context for next depth
            for r in results:
                if r.success and r.response:
                    prev_results.append(r)
        return chains

    async def run_campaign(self, campaign: Campaign) -> Campaign:
        """Execute a full attack campaign."""
        await self._ensure_engine()
        campaign.start_time = time.time()
        logger.info(f"Starting campaign: {campaign.name} ({campaign.id})")

        if campaign.parallel:
            for _ in range(max(1, campaign.chain_depth)):
                results = await self.run_parallel_attacks(
                    campaign.modules, campaign.techniques_per_module
                )
                campaign.results.extend(results)
        else:
            chains = await self.run_chain_attacks(
                campaign.modules, campaign.chain_depth, campaign.techniques_per_module
            )
            for chain_results in chains:
                campaign.results.extend(chain_results)

        campaign.end_time = time.time()
        self._compute_campaign_stats(campaign)
        self.campaigns.append(campaign)
        logger.info(
            f"Campaign {campaign.name} complete: "
            f"{campaign.stats.get('success_rate',0):.1%} success rate"
        )
        return campaign

    def _compute_campaign_stats(self, campaign: Campaign):
        """Compute statistics for a campaign."""
        total = len(campaign.results)
        successes = sum(1 for r in campaign.results if r.success)
        by_module: Dict[str, Dict[str, int]] = {}
        for r in campaign.results:
            mod = r.module or "unknown"
            if mod not in by_module:
                by_module[mod] = {"total": 0, "success": 0}
            by_module[mod]["total"] += 1
            if r.success:
                by_module[mod]["success"] += 1

        module_success_rates = {}
        for mod, counts in by_module.items():
            if counts["total"] > 0:
                module_success_rates[mod] = counts["success"] / counts["total"]

        campaign.stats = {
            "total_attacks": total,
            "success_count": successes,
            "success_rate": successes / total if total > 0 else 0.0,
            "duration_seconds": round(
                (campaign.end_time or 0) - (campaign.start_time or 0), 2
            ),
            "by_module": by_module,
            "module_success_rates": module_success_rates,
            "average_confidence": (
                sum(r.confidence for r in campaign.results) / total if total > 0 else 0.0
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def create_campaign(
        self,
        name: str,
        modules: Optional[List[str]] = None,
        techniques_per_module: int = 5,
        chain_depth: int = 3,
        parallel: bool = True,
    ) -> Campaign:
        """Create a new campaign."""
        return Campaign(
            name=name,
            modules=modules or ["injection", "jailbreak", "tool_abuse", "fingerprint"],
            techniques_per_module=techniques_per_module,
            chain_depth=chain_depth,
            parallel=parallel,
        )

    async def run_all_modules(
        self, technique_count: int = 5, parallel: bool = True
    ) -> List[AttackResult]:
        """Run all available attack modules."""
        modules = list(self._direct_modules.keys())
        if parallel:
            return await self.run_parallel_attacks(modules, technique_count)
        results: List[AttackResult] = []
        for mod in modules:
            mod_results = await self.run_module_attacks(mod, technique_count)
            results.extend(mod_results)
        return results

    async def continuous_attack_loop(
        self, modules: Optional[List[str]] = None, interval: float = 10.0
    ):
        """Run attacks in a continuous loop until stopped."""
        modules = modules or ["injection", "jailbreak", "tool_abuse"]
        while self._running:
            try:
                results = await self.run_parallel_attacks(modules, 3)
                successes = sum(1 for r in results if r.success)
                logger.info(f"Continuous loop: {successes}/{len(results)} successes")
                if successes == 0:
                    for mod in modules:
                        self._consecutive_failures[mod] = (
                            self._consecutive_failures.get(mod, 0) + 1
                        )
                else:
                    for mod in modules:
                        self._consecutive_failures[mod] = 0

                max_failures = max(self._consecutive_failures.values()) if self._consecutive_failures else 0
                if max_failures >= self._max_consecutive_failures:
                    logger.warning("Max consecutive failures reached, cycling techniques")
                    for mod in modules:
                        self._consecutive_failures[mod] = 0

                await asyncio.sleep(interval)
            except Exception as e:
                logger.error(f"Continuous loop error: {e}")
                await asyncio.sleep(interval * 2)

    def get_status(self) -> Dict[str, Any]:
        """Get orchestrator status."""
        return {
            "running": self._running,
            "campaigns_run": len(self.campaigns),
            "total_attacks": sum(
                c.stats.get("total_attacks", 0) for c in self.campaigns
            ),
            "latest_campaign": (
                {
                    "name": self.campaigns[-1].name,
                    "stats": self.campaigns[-1].stats,
                }
                if self.campaigns
                else None
            ),
        }

    def get_best_result(self) -> Optional[AttackResult]:
        """Get the best result from all campaigns."""
        all_results = []
        for c in self.campaigns:
            all_results.extend(c.results)
        if not all_results:
            return None
        return max(all_results, key=lambda r: (r.success, r.confidence))

    async def close(self):
        """Clean up."""
        await self.stop()