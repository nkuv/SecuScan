from typing import Optional
from secuscan.core.detection import ProjectType
from secuscan.scanners.base import BaseScanner
from secuscan.scanners.web.sast import WebScanner
from secuscan.scanners.android.scanner import AndroidScanner

class ScannerFactory:
    """Factory to create the appropriate scanner based on project type."""
    
    @staticmethod
    def get_scanner(project_type: ProjectType, target: str) -> Optional[BaseScanner]:
        if project_type == ProjectType.WEB:
            return WebScanner(target)
        elif project_type == ProjectType.ANDROID:
            return AndroidScanner(target)
        return None
