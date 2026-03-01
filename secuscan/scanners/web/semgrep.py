import os
import shutil
import subprocess
import json
import logging
from typing import List

from secuscan.scanners.base import BaseScanner
from secuscan.scanners.models import Vulnerability

logger = logging.getLogger(__name__)

# Semgrep severity → SecuScan severity mapping
SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}

# Rule IDs containing these keywords are promoted to CRITICAL
# (Semgrep has no native CRITICAL level)
CRITICAL_RULE_KEYWORDS = {"hardcoded", "credential", "secret", "password", "passwd", "api_key", "token"}


class SemgrepScanner(BaseScanner):
    """
    Multi-language SAST scanner using Semgrep.
    Runs for Web projects only. Python is excluded (handled by Bandit).
    """

    def scan(self) -> List[Vulnerability]:
        if not self._check_dependency():
            logger.warning(
                "Semgrep not found. Skipping multi-language scan. "
                "Install with: pip install semgrep"
            )
            return []

        logger.info(f"Running Semgrep on {self.target} (excluding Python)...")
        return self._run_semgrep()

    def _get_rules_dir(self) -> str:
        """Returns path to the bundled local Semgrep rules directory."""
        return os.path.join(os.path.dirname(__file__), "..", "..", "config", "rules")

    def _run_semgrep(self) -> List[Vulnerability]:
        rules_dir = os.path.abspath(self._get_rules_dir())
        cmd = [
            "semgrep", "scan",
            "--config", rules_dir,   # Local rules — no login needed
            "--json",
            "--quiet",
            "--exclude", "*.py",   # Bandit already covers Python
            "--exclude", "venv",
            "--exclude", "node_modules",
            "--exclude", ".git",
            self.target
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            # 0 = clean, 1 = findings found, 2 = partial error but still has output
            if result.returncode > 2:
                logger.error(f"Semgrep failed (exit {result.returncode}): {result.stderr[:300]}")
                return []

            return self._parse_output(result.stdout)

        except subprocess.TimeoutExpired:
            logger.error("Semgrep scan timed out after 120 seconds.")
            return []
        except Exception as e:
            logger.error(f"Failed to execute Semgrep: {e}")
            return []

    def _parse_output(self, json_output: str) -> List[Vulnerability]:
        if not json_output.strip():
            return []

        try:
            data = json.loads(json_output)
        except json.JSONDecodeError:
            logger.error("Failed to parse Semgrep JSON output.")
            return []

        results = []
        seen = set()  # Deduplicate by (file, line, rule)
        for finding in data.get("results", []):
            path = finding.get("path", self.target)
            line = finding.get("start", {}).get("line")
            check_id = finding.get("check_id", "")

            severity = SEVERITY_MAP.get(
                finding.get("extra", {}).get("severity", "").upper(),
                "MEDIUM"
            )
            # Promote credential/secret findings to CRITICAL
            if any(kw in check_id.lower() for kw in CRITICAL_RULE_KEYWORDS):
                severity = "CRITICAL"

            dedup_key = (path, line, check_id)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            results.append(Vulnerability(
                type=f"Semgrep: {check_id.split('.')[-1]}",
                file=path,
                severity=severity,
                description=finding.get("extra", {}).get("message", "No description."),
                line=line,
                id=check_id
            ))

        return results

    def _check_dependency(self) -> bool:
        return shutil.which("semgrep") is not None
