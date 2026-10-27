"""anticells_red_mcp configuration and legacy module settings."""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path
from .targets import ResolvedTarget, load_target_sources


def _template_env_default() -> Dict[str, str]:
    """Return the environment visible to target template rendering.

    By default this is EMPTY -- an inline target cannot reference anything
    through ``${env.*}``. Saved profiles authored by the operator may
    reference variables declared through ``ANTICELLS_RED_MCP_TEMPLATE_ENV``
    (a comma-separated list of variable names) or through an explicitly
    loaded ``.env`` file (``ANTICELLS_RED_MCP_ENV_FILE``). This is the fix
    for the "any env var exfiltrated to configured provider" finding.
    """
    allowed = {name.strip() for name in os.environ.get("ANTICELLS_RED_MCP_TEMPLATE_ENV", "").split(",") if name.strip()}
    return {name: value for name, value in os.environ.items() if name in allowed}


@dataclass
class RelentlessConfig:
    """Settings consumed by the existing loop strategies."""
    max_iterations: int = 1  # 0 explicitly requests an unlimited legacy loop
    parallel_workers: int = 8
    loop_delay_ms: int = 0  # ZERO DELAY
    mutation_rate: float = 0.3
    cross_pollination_rate: float = 0.25
    creativity_temperature: float = 0.9
    min_confidence_for_exploit: float = 0.5
    auto_escalate: bool = True
    persist_attacks: bool = True
    log_all_attempts: bool = True
    retry_on_failure: int = 9999  # Try 9999 times before even thinking about stopping


@dataclass
class AttackModuleConfig:
    """Per-module attack configuration"""
    enabled: bool = True
    priority: int = 1
    max_depth: int = 10  # Recursive depth limit (but we keep pushing)
    techniques_per_run: int = 50  # How many techniques to try per run
    adaptive: bool = True
    use_llm_for_mutation: bool = False


@dataclass
class MCPConfig:
    """Master configuration"""
    name: str = "anticells_red_mcp"
    version: str = "1.1.0"

    server_host: str = "127.0.0.1"
    server_port: int = 9190
    transport: str = "stdio"  # stdio | sse

    # Sub-configs
    relentless: RelentlessConfig = field(default_factory=RelentlessConfig)
    fingerprint: AttackModuleConfig = field(default_factory=AttackModuleConfig)
    jailbreaks: AttackModuleConfig = field(default_factory=AttackModuleConfig)
    injection: AttackModuleConfig = field(default_factory=AttackModuleConfig)
    tool_abuse: AttackModuleConfig = field(default_factory=AttackModuleConfig)
    mutation: AttackModuleConfig = field(default_factory=AttackModuleConfig)

    # Logging
    log_dir: str = str(Path.home() / ".local/state/anticells_red_mcp/logs")
    verbose: bool = True
    save_successful_attacks: bool = True
    attack_history_file: str = "attack_history.json"

    # Target specific
    target_model: Optional[str] = None
    target_provider: Optional[str] = None
    target_api_url: Optional[str] = field(default=None, repr=False)
    target_api_key: Optional[str] = field(default=None, repr=False)
    target_profiles: Dict[str, Any] = field(default_factory=dict, repr=False)
    target_environment: Dict[str, str] = field(default_factory=_template_env_default, repr=False)
    target: Optional[ResolvedTarget] = field(default=None, repr=False)
    database_path: Optional[str] = field(default=None, repr=False)
    # Legacy setting is retained only to detect upgrades requiring data transfer.
    database_url: Optional[str] = field(default=None, repr=False)
    catalog_snapshot: Any = field(default=None, repr=False)
    catalog_auto_setup: bool = True
    catalog_state_dir: Optional[str] = field(default=None, repr=False)
    reports_dir: Optional[str] = field(default=None, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "relentless": self.relentless.__dict__,
            "modules": {
                "fingerprint": self.fingerprint.__dict__,
                "jailbreaks": self.jailbreaks.__dict__,
                "injection": self.injection.__dict__,
                "tool_abuse": self.tool_abuse.__dict__,
                "mutation": self.mutation.__dict__,
            }
        }


def load_config() -> MCPConfig:
    """Load configuration from environment or defaults.

    ``load_target_sources`` returns the restricted ``target_environment``
    (what ``${env.*}`` can see) plus the ``system_values`` superset (where
    this process looks up its own ``ANTICELLS_RED_MCP_*`` knobs). The
    separation is the enforcement side of the "arbitrary env readable
    through inline target" fix.
    """
    config = MCPConfig()
    config.target_profiles, config.target_environment, env = load_target_sources()
    config.database_path = env.get("ANTICELLS_RED_MCP_DATABASE_PATH")
    config.database_url = env.get("ANTICELLS_RED_MCP_DATABASE_URL")
    automatic = env.get("ANTICELLS_RED_MCP_CATALOG_AUTO_SETUP", "true").strip().lower()
    if automatic not in {"true", "false", "1", "0"}:
        from ..catalog.model import CatalogError
        raise CatalogError('invalid_auto_setup_setting')
    config.catalog_auto_setup = automatic in {"true", "1"}
    config.catalog_state_dir = env.get("ANTICELLS_RED_MCP_STATE_DIR")
    config.reports_dir = env.get("ANTICELLS_RED_MCP_REPORTS_DIR")
    config.log_dir = env.get("ANTICELLS_RED_MCP_LOG_DIR", config.log_dir)
    try:
        config.relentless.parallel_workers = int(env.get("ANTICELLS_RED_MCP_WORKERS", "8"))
        config.relentless.mutation_rate = float(env.get("ANTICELLS_RED_MCP_MUTATION_RATE", "0.3"))
        config.server_port = int(env.get("ANTICELLS_RED_MCP_PORT", "9190"))
    except ValueError:
        from .targets import TargetConfigurationError
        raise TargetConfigurationError("invalid_numeric_setting") from None
    config.target_model = env.get("ANTICELLS_RED_MCP_TARGET_MODEL")
    config.target_provider = env.get("ANTICELLS_RED_MCP_TARGET_PROVIDER")
    config.target_api_url = env.get("ANTICELLS_RED_MCP_TARGET_API_URL")
    config.target_api_key = env.get("ANTICELLS_RED_MCP_TARGET_API_KEY")
    if config.relentless.parallel_workers < 1:
        raise ValueError("ANTICELLS_RED_MCP_WORKERS must be at least one")
    return config
