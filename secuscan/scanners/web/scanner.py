from secuscan.scanners.base import BaseScanner
import os

class WebScanner(BaseScanner):
    """Static scanner for Web projects."""
    
    def scan(self):
        # Heuristics for sensitive files/content
        sensitive_keywords = ['password', 'secret', 'api_key', 'access_token']
        unsafe_patterns = ['eval(', 'document.write(']
        
        exclude_dirs = {'.git', 'node_modules', 'venv', '__pycache__'}

        for root, dirs, files in os.walk(self.target):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                if file.endswith(('.js', '.py', '.config', '.env')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # Check for keywords
                            for keyword in sensitive_keywords:
                                if f"{keyword} =" in content.lower() or f"{keyword}=" in content.lower():
                                    self.add_vulnerability(
                                        type="Hardcoded Secret",
                                        file=file,
                                        severity="HIGH",
                                        description=f"Potential hardcoded secret found: '{keyword}'"
                                    )
                                    
                            # Check for unsafe patterns (JS)
                            if file.endswith('.js'):
                                for pattern in unsafe_patterns:
                                    if pattern in content:
                                         self.add_vulnerability(
                                            type="Insecure Code",
                                            file=file,
                                            severity="MEDIUM",
                                            description=f"Unsafe pattern found: '{pattern}'"
                                        )
                            
                    except Exception:
                        pass # Skip files we can't read
        
        return self.results
