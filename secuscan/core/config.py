from typing import Dict, Any
import os

class Config:
    """Holds configuration settings for SecuScan."""
    def __init__(self):
        self.debug = False
        self.output_dir = "reports"
    
    def load_from_env(self):
        """Load configuration from environment variables."""
        self.debug = os.getenv("SECUSCAN_DEBUG", "false").lower() == "true"

config = Config()
