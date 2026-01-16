import re
import os
import logging
from typing import List
from secuscan.scanners.models import Vulnerability

logger = logging.getLogger(__name__)

class SecretScanner:
    """Scans files for hardcoded secrets using regex patterns."""

    PATTERNS = {
        "AWS Access Key": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "Slack Token": r"xox[baprs]-[a-zA-Z0-9-]+",
        "Private Key": r"-----BEGIN.*PRIVATE KEY-----",
        "Generic API Key": r"api_key\s*=\s*['\"][A-Za-z0-9\-_]{20,}['\"]"
    }

    # Directories to exclude from scanning
    EXCLUDE_DIRS = {'.git', 'venv', 'node_modules', '__pycache__', '.idea', '.vscode', 'build', 'dist', 'eggs', '.tox'}
    # Extensions to check (text files)
    INCLUDE_EXTS = {'.py', '.js', '.ts', '.java', '.kt', '.xml', '.json', '.yml', '.yaml', '.txt', '.md', '.env', '.sh', '.properties'}

    def __init__(self, target_dir: str):
        self.target_dir = target_dir
        self.results: List[Vulnerability] = []

    def scan(self) -> List[Vulnerability]:
        logger.info(f"Starting Secret Scan on {self.target_dir}")
        
        for root, dirs, files in os.walk(self.target_dir):
            # Modify dirs in-place to skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.EXCLUDE_DIRS]

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext not in self.INCLUDE_EXTS and file != 'Dockerfile':
                    continue

                file_path = os.path.join(root, file)
                self._scan_file(file_path)

        return self.results

    def _scan_file(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f, 1):
                    for name, pattern in self.PATTERNS.items():
                        if re.search(pattern, line):
                            # Obfuscate the secret in the description
                            match = re.search(pattern, line).group(0)
                            masked = match[:4] + "*" * (len(match) - 4) if len(match) > 4 else "****"
                            
                            self.results.append(Vulnerability(
                                type="Hardcoded Secret",
                                file=file_path,
                                severity="CRITICAL",
                                description=f"Found {name}: {masked}",
                                line=i,
                                id=f"SECRET-{name.upper().replace(' ', '_')}"
                            ))
        except Exception as e:
            logger.warning(f"Could not scan file {file_path}: {e}")
