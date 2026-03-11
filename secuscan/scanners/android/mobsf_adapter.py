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
        temp_zip_path = None
        target_file = file_path
        
        try:
            if os.path.isdir(file_path):
                import tempfile
                import zipfile
                logger.info("Target is a directory. Creating a sanitized temporary zip archive for MobSF upload...")
                temp_dir = tempfile.mkdtemp()
                temp_zip_path = os.path.join(temp_dir, "mobsf_upload.zip")
                
                with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for root, dirs, files in os.walk(file_path):
                        # Filter out hidden folders and common build outputs
                        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('build', 'dist', 'node_modules', '__pycache__')]
                        for file in files:
                            # Also skip hidden files like .gitignore, .DS_Store which cause MobSF errors
                            if not file.startswith('.'):
                                f_path = os.path.join(root, file)
                                arcname = os.path.relpath(f_path, file_path)
                                zipf.write(f_path, arcname)
                
                target_file = temp_zip_path

            logger.info(f"Uploading {os.path.basename(target_file)} to MobSF...")
            with open(target_file, 'rb') as f:
                # Explicitly define filename and content type
                files = {'file': (os.path.basename(target_file), f, 'application/octet-stream')}
                # Increased timeout for potentially large source zips
                response = requests.post(upload_url, headers=self._get_headers(), files=files, timeout=600)
            
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
        finally:
            if temp_zip_path and os.path.exists(temp_zip_path):
                try:
                    import shutil
                    os.remove(temp_zip_path)
                    shutil.rmtree(os.path.dirname(temp_zip_path))
                except Exception as e:
                    logger.debug(f"Failed to clean up temp zip: {e}")

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
            response = requests.post(scan_url, headers=self._get_headers(), data=data, timeout=120)
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
            response = requests.post(report_url, headers=self._get_headers(), data=data, timeout=30)
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
            requests.post(delete_url, headers=self._get_headers(), data=data, timeout=30)
            logger.info(f"Deleted scan data for {file_hash}.")
        except Exception as e:
            logger.warning(f"Failed to delete scan data: {e}")
