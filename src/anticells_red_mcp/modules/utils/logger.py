import sys
import logging
from typing import Optional

_HAS_STRUCTLOG = False
try:
    import structlog
    _HAS_STRUCTLOG = True
except ImportError:
    pass

from rich.console import Console
from rich.theme import Theme
from rich.text import Text
from rich.panel import Panel
from rich.table import Table

BANNER = "anticells_red_mcp · ♢𝓜𝖗𝚇₀𝚛𝚍⚡🖤"


class AttackLogger:
    def __init__(self, name: str = "anticells_red_mcp"):
        self.name = name

        self._theme = Theme({
            "info": "cyan",
            "success": "bold green",
            "warning": "yellow",
            "error": "bold red",
            "debug": "dim white",
            "banner": "bold cyan",
            "module": "bold magenta",
            "iteration": "bold yellow",
            "payload": "dim cyan",
            "refusal": "red",
            "indicator": "green",
        })
        self._console = Console(theme=self._theme, highlight=False, stderr=True)

        if _HAS_STRUCTLOG:
            structlog.configure(
                processors=[
                    structlog.stdlib.filter_by_level,
                    structlog.stdlib.add_logger_name,
                    structlog.stdlib.add_log_level,
                    structlog.stdlib.PositionalArgumentsFormatter(),
                    structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
                    structlog.processors.StackInfoRenderer(),
                    structlog.processors.format_exc_info,
                    structlog.dev.ConsoleRenderer(colors=True),
                ],
                context_class=dict,
                logger_factory=structlog.stdlib.LoggerFactory(),
                wrapper_class=structlog.stdlib.BoundLogger,
                cache_logger_on_first_use=True,
            )
            self._logger = structlog.get_logger(name)
        else:
            self._logger = logging.getLogger(name)
            if not self._logger.handlers:
                handler = logging.StreamHandler(sys.stderr)
                handler.setFormatter(logging.Formatter(
                    "[%(asctime)s] %(levelname)-8s %(message)s",
                    datefmt="%H:%M:%S",
                ))
                self._logger.addHandler(handler)
                self._logger.setLevel(logging.DEBUG)

    def _format_msg(self, msg: str) -> str:
        prefix = f"[{self.name}]"
        return f"{prefix} {msg}"

    def info(self, msg: str, **kwargs):
        if _HAS_STRUCTLOG:
            self._logger.info(msg, **kwargs)
        else:
            self._logger.info(self._format_msg(msg))
            self._console.print(f"  [info]ℹ[/info] {msg}", **kwargs)

    def success(self, msg: str, **kwargs):
        if _HAS_STRUCTLOG:
            self._logger.info(msg, status="success", **kwargs)
        else:
            self._logger.info(self._format_msg(f"[SUCCESS] {msg}"))
            self._console.print(f"  [success]✓[/success] {msg}", **kwargs)

    def warn(self, msg: str, **kwargs):
        if _HAS_STRUCTLOG:
            self._logger.warning(msg, **kwargs)
        else:
            self._logger.warning(self._format_msg(msg))
            self._console.print(f"  [warning]⚠[/warning] {msg}", **kwargs)

    def error(self, msg: str, exc_info: bool = False, **kwargs):
        if _HAS_STRUCTLOG:
            self._logger.error(msg, exc_info=exc_info, **kwargs)
        else:
            self._logger.error(self._format_msg(msg), exc_info=exc_info)
            self._console.print(f"  [error]✗[/error] {msg}", **kwargs)

    def debug(self, msg: str, **kwargs):
        if _HAS_STRUCTLOG:
            self._logger.debug(msg, **kwargs)
        else:
            self._logger.debug(self._format_msg(msg))
            self._console.print(f"  [debug]·[/debug] {msg}", **kwargs)

    def log_banner(self):
        self._console.print()
        self._console.print(BANNER, style="banner")
        self._console.print()

    def log_loop_header(self, iteration: int):
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column(style="iteration")
        table.add_row(f"▸ ITERATION {iteration}")
        self._console.print()
        self._console.print(table)
        self._console.print("  " + "─" * 50, style="dim")