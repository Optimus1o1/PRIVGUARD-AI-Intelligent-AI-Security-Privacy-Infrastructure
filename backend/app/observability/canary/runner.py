"""PRIVGUARD AI - Synthetic Security Canary Execution Runner.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from app.observability.canary.scenarios import (
    ALL_CANARY_CLASSES,
    BaseCanaryScenario,
    CanaryResult,
)

logger = logging.getLogger("privguard.observability.canary")


class CanaryRunner:
    """Manages periodic and on-demand execution of synthetic security canaries."""

    def __init__(self) -> None:
        self.canaries: Dict[str, BaseCanaryScenario] = {
            cls.name: cls() for cls in ALL_CANARY_CLASSES
        }
        self.latest_results: Dict[str, CanaryResult] = {}
        self.last_run_timestamp: Optional[str] = None

    async def run_all(self) -> List[CanaryResult]:
        """Runs all 8 synthetic security canaries in parallel."""
        logger.info("Executing all %d synthetic security canaries...", len(self.canaries))
        tasks = [canary.execute() for canary in self.canaries.values()]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        for res in results:
            self.latest_results[res.canary_name] = res
            status_text = "PASS" if res.passed else "FAIL"
            logger.info("Canary '%s': %s (%0.2fms)", res.canary_name, status_text, res.latency_ms)

        self.last_run_timestamp = datetime.now(timezone.utc).isoformat()
        return results

    async def run_one(self, name: str) -> Optional[CanaryResult]:
        """Runs a single canary scenario by name."""
        canary = self.canaries.get(name)
        if not canary:
            return None

        result = await canary.execute()
        self.latest_results[name] = result
        return result

    def get_latest_results(self) -> List[CanaryResult]:
        """Returns the most recent results for all canaries."""
        return list(self.latest_results.values())

    def get_summary(self) -> Dict[str, Any]:
        """Returns an aggregated health summary of canary results."""
        results = self.get_latest_results()
        total = len(self.canaries)
        passed = sum(1 for r in results if r.passed)
        failed = sum(1 for r in results if not r.passed)

        return {
            "total_canaries": total,
            "executed": len(results),
            "passed": passed,
            "failed": failed,
            "healthy": failed == 0 and len(results) > 0,
            "last_run_timestamp": self.last_run_timestamp,
        }


# Singleton Runner Instance
_canary_runner: Optional[CanaryRunner] = None


def get_canary_runner() -> CanaryRunner:
    """Returns the singleton CanaryRunner."""
    global _canary_runner
    if _canary_runner is None:
        _canary_runner = CanaryRunner()
    return _canary_runner
