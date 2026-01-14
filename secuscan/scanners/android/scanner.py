from secuscan.scanners.base import BaseScanner
from secuscan.scanners.models import Vulnerability
from secuscan.scanners.android.mobsf_adapter import MobSFAdapter
import os
import logging
from typing import List

logger = logging.getLogger(__name__)

class AndroidScanner(BaseScanner):
    """Static scanner for Android projects (APK & Source)."""
    
    def scan(self) -> List[Vulnerability]:
        mobsf = MobSFAdapter()
        
        # 1. Try MobSF Scan if it's an APK
        if self.target.endswith('.apk') and os.path.exists(self.target):
            try:
                # Upload
                logger.info("Uploading APK to MobSF...")
                file_hash = mobsf.upload_file(self.target)
                
                # Scan
                logger.info("Scanning with MobSF...")
                mobsf.scan_file(file_hash)
                
                # Report
                logger.info("Retrieving report...")
                report = mobsf.get_report(file_hash)
                
                self._parse_mobsf_report(report)
                mobsf.delete_scan(file_hash)
                
                return self.results
                
            except Exception as e:
                logger.error(f"MobSF scan failed: {e}. Falling back to local checks.")
        
        # 2. Fallback: Local Manifest Check (if folder or MobSF failed)
        # (Preserving existing logic for robustness)
        manifest_path = os.path.join(self.target, "AndroidManifest.xml")
        
        if os.path.exists(manifest_path):
             self._scan_manifest(manifest_path)
        
        return self.results

    def _parse_mobsf_report(self, report: dict):
        """Extracts vulnerabilities from MobSF JSON report."""
        
        
        # Manifest Analysis
        manifest_analysis = report.get('manifest_analysis', {})
        manifest_issues = manifest_analysis.get('manifest_findings', [])
        
        for issue in manifest_issues:
            # MobSF manifest entries: {'title':..., 'stat': 'high', 'desc':...}
             if isinstance(issue, dict) and issue.get('stat') in ['high', 'critical', 'medium']:
                 self.add_vulnerability(
                     type=f"MobSF: {issue.get('title')}",
                     file="AndroidManifest.xml",
                     severity=issue.get('stat').upper(),
                     description=issue.get('desc')
                 )

        # Code Analysis
        code_analysis = report.get('code_analysis', {})
        code_issues = code_analysis.get('findings', {})
        
        for rule_id, finding in code_issues.items():
            metadata = finding.get('metadata', {})
            severity = metadata.get('severity', 'low').lower()
            
            # Map severity
            if severity == 'high':
                mapped_severity = "HIGH"
            elif severity == 'warning':
                mapped_severity = "MEDIUM"
            elif severity == 'info':
                mapped_severity = "LOW"
            else:
                mapped_severity = "LOW"
                
            description = metadata.get('description', f"Issue found: {rule_id}")
            
            # Iterate files affected by this rule
            file_map = finding.get('files', {})
            for file_path, lines in file_map.items():
                line_num = None
                try:
                    if isinstance(lines, str):
                        # Lines can be "26" or "26,29"
                        line_num = int(lines.split(',')[0])
                    elif isinstance(lines, int):
                        line_num = lines
                except:
                    pass
                
                self.add_vulnerability(
                    type=f"MobSF: {rule_id}",
                    file=file_path,
                    severity=mapped_severity,
                    description=description,
                    line=line_num
                )

    def _scan_manifest(self, manifest_path):
        """Local simple manifest check (Fallback)."""
        try:
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                if 'android:debuggable="true"' in content.lower():
                    self.add_vulnerability(
                        type="Security Misconfiguration",
                        file="AndroidManifest.xml",
                        severity="HIGH",
                        description="Application is marked as debuggable."
                    )
                
                if 'android:allowbackup="true"' in content.lower():
                     self.add_vulnerability(
                        type="Security Misconfiguration",
                        file="AndroidManifest.xml",
                        severity="MEDIUM",
                        description="Backup is enabled."
                    )
        except Exception:
            pass
