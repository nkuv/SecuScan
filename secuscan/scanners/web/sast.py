import shutil
import logging
import subprocess
import json
from typing import List
from secuscan.scanners.base import BaseScanner
from secuscan.scanners.models import Vulnerability

logger = logging.getLogger(__name__)

class WebScanner(BaseScanner):
    """Static Application Security Testing (SAST) for Web projects using Bandit."""

    def scan(self) -> List[Vulnerability]:
        """
        Runs Bandit against the target directory.
        """
        if not self._check_dependency():
            logger.error("Bandit dependency not found.")
            return []

        cmd = ["bandit", "-r", self.target, "-f", "json", "-x", "venv,.git,__pycache__,test,build,dist"]
            
        try:
            logger.info(f"Running Bandit on {self.target}...")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            if result.returncode <= 1: # 0 = No issues, 1 = Issues found
                self._parse_output(result.stdout)
            else:
                 logger.error(f"Bandit failed: {result.stderr}")

        except Exception as e:
            logger.error(f"Failed to execute Bandit: {e}")

        return self.results

    def _parse_output(self, json_output: str):
        """Parses Bandit JSON output and populates results."""
        try:
            data = json.loads(json_output)
            results = data.get('results', [])
            
            for item in results:
                self.add_vulnerability(
                    type=f"Bandit: {item.get('test_name')}",
                    file=item.get('filename'),
                    severity=item.get('issue_severity'),
                    description=f"{item.get('issue_text')} (Confidence: {item.get('issue_confidence')})",
                    line=item.get('line_number'),
                    id=item.get('test_id')
                )
        except json.JSONDecodeError:
            logger.error("Failed to parse Bandit JSON output.")

    def _check_dependency(self) -> bool:
        """Checks if bandit is installed and available in PATH."""
        return shutil.which("bandit") is not None
