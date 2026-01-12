from secuscan.scanners.base import BaseScanner
import os

class AndroidScanner(BaseScanner):
    """Static scanner for Android projects."""
    
    def scan(self):
        # 1. Check for AndroidManifest.xml
        manifest_path = os.path.join(self.target, "AndroidManifest.xml")
        
        if os.path.exists(manifest_path):
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # Check for debuggable flag
                if 'android:debuggable="true"' in content.lower():
                    self.add_vulnerability(
                        type="Security Misconfiguration",
                        file="AndroidManifest.xml",
                        severity="HIGH",
                        description="Application is marked as debuggable. This allows attackers to attach a debugger and access sensitive data."
                    )
                
                # Check for allowBackup flag
                if 'android:allowbackup="true"' in content.lower():
                    self.add_vulnerability(
                        type="Security Misconfiguration",
                        file="AndroidManifest.xml",
                        severity="MEDIUM",
                        description="Application data backup is enabled. Sensitive data might be extracted via adb backup."
                    )
        
        return self.results
