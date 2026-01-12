import os
import yaml
from typing import Dict, Any, Optional
from secuscan.core.exceptions import ConfigError

class Config:
    """Holds configuration settings for SecuScan."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
            
        self.debug = False
        self.mobsf_url = "http://localhost:8000"
        self.mobsf_api_key = None
        self.output_dir = "reports"
        
        self.load_config()
        self.load_from_env()
        self._initialized = True
    
    def load_config(self):
        """Load configuration from YAML file."""
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'secuscan.yaml')
        config_path = os.path.abspath(config_path)
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    yaml_config = yaml.safe_load(f)
                    if yaml_config:
                        mobsf = yaml_config.get('mobsf', {})
                        self.mobsf_url = mobsf.get('url', self.mobsf_url)
                        self.mobsf_api_key = mobsf.get('api_key', self.mobsf_api_key)
                        
                        reports = yaml_config.get('reports', {})
                        self.output_dir = reports.get('output_dir', self.output_dir)
            except Exception as e:
                print(f"Warning: Failed to load config file: {e}") 
                # raise ConfigError(f"Failed to load config file: {e}") from e

    def load_from_env(self):
        """Load configuration from environment variables."""
        self.debug = os.getenv("SECUSCAN_DEBUG", "false").lower() == "true"
        self.mobsf_url = os.getenv("MOBSF_URL", self.mobsf_url)
        self.mobsf_api_key = os.getenv("MOBSF_API_KEY", self.mobsf_api_key)

config = Config()
