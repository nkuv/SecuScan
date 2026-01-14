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
            logger.info("MobSF API Key not found in config. Attempting strict auto-discovery from Docker...")
            from secuscan.core.docker_manager import DockerManager
            dm = DockerManager()
            self.api_key = dm.get_mobsf_api_key()
            
            if self.api_key:
                logger.info(f"Successfully retrieved API Key from MobSF container.")
            else:
                logger.warning("MobSF API Key is missing and could not be retrieved. Operations requiring auth will fail.")

    def _get_headers(self):
        """Constructs standard headers for MobSF requests."""
        return {
            'Authorization': self.api_key
        }

    def upload_file(self, file_path: str) -> str:
        """
        Uploads an APK or Source zip to MobSF.
        Returns the hash of the uploaded file.
        """
        if not self.api_key:
            raise ValueError("MobSF API Key is not configured.")

        upload_url = f"{self.server_url}/api/v1/upload"
        
        try:
            logger.info(f"Uploading {os.path.basename(file_path)} to MobSF...")
            with open(file_path, 'rb') as f:
                # Explicitly define filename and content type
                files = {'file': (os.path.basename(file_path), f, 'application/octet-stream')}
                response = requests.post(upload_url, headers=self._get_headers(), files=files)
            
            if response.status_code != 200:
                logger.error(f"MobSF Upload Failed: {response.text}")
                
            response.raise_for_status()
            data = response.json()
            
            # Helper: MobSF returns file info including hash
            file_hash = data.get('hash')
            if not file_hash:
                raise ValueError("MobSF did not return a file hash.")
                
            return file_hash

        except Exception as e:
            logger.error(f"Error during upload: {e}")
            raise

    def scan_file(self, file_hash: str) -> dict:
        """
        Triggers the scan for the uploaded file (Step 64).
        Note: MobSF static scan is usually synchronous (Step 65 handled by blocking request).
        """
        if not self.api_key:
             raise ValueError("MobSF API Key is not configured.")
             
        scan_url = f"{self.server_url}/api/v1/scan"
        data = {'hash': file_hash}
        
        try:
            logger.info(f"Initiating scan for hash {file_hash}...")
            response = requests.post(scan_url, headers=self._get_headers(), data=data)
            response.raise_for_status()
            logger.info("Scan completed successfully.")
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to scan file: {e}")
            raise

    def get_report(self, file_hash: str) -> dict:
        """
        Retrieves the JSON report for the file (Step 66).
        """
        if not self.api_key:
             raise ValueError("MobSF API Key is not configured.")

        report_url = f"{self.server_url}/api/v1/report_json"
        data = {'hash': file_hash}
        
        try:
            logger.info(f"Fetching report for hash {file_hash}...")
            response = requests.post(report_url, headers=self._get_headers(), data=data)
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get report: {e}")
            raise

    def delete_scan(self, file_hash: str):
        """
        Deletes the scan result from MobSF (Step 69).
        """
        if not self.api_key:
             return

        delete_url = f"{self.server_url}/api/v1/delete"
        data = {'hash': file_hash}
        
        try:
            requests.post(delete_url, headers=self._get_headers(), data=data)
            logger.info(f"Deleted scan data for {file_hash}.")
        except Exception as e:
            logger.warning(f"Failed to delete scan data: {e}")
