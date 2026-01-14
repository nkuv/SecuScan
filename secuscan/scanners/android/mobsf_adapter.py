import requests
import logging
import os
from secuscan.core.config import config

logger = logging.getLogger(__name__)

class MobSFAdapter:
    """
    Adapter to interact with the Mobile Security Framework (MobSF) API.
    Handles uploading, scanning, and retrieving reports.
    """

    def __init__(self):
        self.server_url = config.mobsf_url.rstrip('/')
        self.api_key = config.mobsf_api_key
        
        if not self.api_key:
            logger.warning("MobSF API Key is missing. Operations requiring auth will fail.")

    def _get_headers(self):
        """Constructs standard headers for MobSF requests."""
        return {
            'Authorization': self.api_key
        }

    # Future methods: upload(), scan(), report_json(), delete()
