"""SonarQube Manager - Handles SonarQube container and scanning operations."""

import docker
import time
import requests
import os
from typing import Optional
from rich.console import Console
from secuscan.core.config import config

console = Console()


class SonarQubeManager:
    """Manages SonarQube container interactions and scanning."""
    
    SONARQUBE_IMAGE = "sonarqube:community"
    SCANNER_IMAGE = "sonarsource/sonar-scanner-cli:latest"
    CONTAINER_NAME = "secuscan-sonarqube"
    
    def __init__(self):
        try:
            self.client = docker.from_env()
            self._available = True
        except docker.errors.DockerException:
            self.client = None
            self._available = False

    def is_available(self) -> bool:
        """Checks if Docker daemon is running and accessible."""
        if not self._available:
            return False
            
        try:
            self.client.ping()
            return True
        except docker.errors.DockerException:
            return False

    def pull_image(self, image_name: str):
        """Pulls a Docker image if not present."""
        if not self.is_available():
            return

        try:
            self.client.images.get(image_name)
            console.print(f"[green]Image {image_name} found locally.[/green]")
        except docker.errors.ImageNotFound:
            console.print(f"[yellow]Pulling {image_name}...[/yellow]")
            with console.status(f"[bold green]Downloading {image_name}... This may take a while..."):
                self.client.images.pull(image_name)
            console.print("[green]Image pulled successfully.[/green]")

    def is_container_running(self) -> bool:
        """Checks if the SonarQube container is currently running."""
        if not self.is_available():
            return False
            
        try:
            container = self.client.containers.get(self.CONTAINER_NAME)
            return container.status == "running"
        except docker.errors.NotFound:
            return False

    def start_sonarqube(self):
        """Starts the SonarQube container."""
        if not self.is_available():
            raise RuntimeError("Docker is not available.")

        # Ensure image is pulled
        self.pull_image(self.SONARQUBE_IMAGE)

        if self.is_container_running():
            console.print("[green]SonarQube container is already running.[/green]")
            return

        console.print("[yellow]Starting SonarQube container...[/yellow]")
        try:
            # Check if stopped container exists and remove it
            try:
                old_container = self.client.containers.get(self.CONTAINER_NAME)
                old_container.remove(force=True)
            except docker.errors.NotFound:
                pass

            self.client.containers.run(
                self.SONARQUBE_IMAGE,
                name=self.CONTAINER_NAME,
                ports={'9000/tcp': 9000},
                environment={"SONAR_ES_BOOTSTRAP_CHECKS_DISABLE": "true"},
                volumes={
                    'sonarqube_data': {'bind': '/opt/sonarqube/data', 'mode': 'rw'},
                    'sonarqube_extensions': {'bind': '/opt/sonarqube/extensions', 'mode': 'rw'},
                    'sonarqube_logs': {'bind': '/opt/sonarqube/logs', 'mode': 'rw'}
                },
                detach=True
            )
            console.print("[green]SonarQube container started on port 9000.[/green]")
            self.wait_for_sonarqube()
            
        except Exception as e:
            console.print(f"[bold red]Failed to start SonarQube container: {e}[/bold red]")
            raise

    def wait_for_sonarqube(self, timeout: int = 180):
        """Waits for SonarQube API to become available."""
        start_time = time.time()
        
        with console.status("[bold green]Waiting for SonarQube to initialize (this may take 1-2 minutes)...") as status:
            while time.time() - start_time < timeout:
                try:
                    response = requests.get(
                        f"{config.sonar_url}/api/system/status",
                        timeout=5
                    )
                    if response.status_code == 200:
                        data = response.json()
                        if data.get("status") == "UP":
                            console.print("[green]SonarQube is ready![/green]")
                            return
                except requests.exceptions.RequestException:
                    pass
                time.sleep(3)
        
        raise TimeoutError("SonarQube failed to start within the timeout period.")

    def ensure_sonarqube(self):
        """Ensures SonarQube is running and ready."""
        if not self.is_available():
            raise RuntimeError("Docker is not available.")
             
        self.start_sonarqube()

    def run_scan(self, target_dir: str):
        """Runs the SonarQube scanner on the target directory."""
        if not self.is_available():
            raise RuntimeError("Docker is not available.")

        target_dir = os.path.abspath(target_dir)
        self.pull_image(self.SCANNER_IMAGE)
        
        console.print(f"[yellow]Running SonarQube Scan on {target_dir}...[/yellow]")
        
        try:
            # Run sonar-scanner container linked to SonarQube
            self.client.containers.run(
                self.SCANNER_IMAGE,
                remove=True,
                volumes={target_dir: {'bind': '/usr/src', 'mode': 'rw'}},
                environment={
                    'SONAR_HOST_URL': f'http://{self.CONTAINER_NAME}:9000',
                    'SONAR_TOKEN': config.sonar_token,
                } if config.sonar_token else {
                    'SONAR_HOST_URL': f'http://{self.CONTAINER_NAME}:9000',
                    'SONAR_LOGIN': config.sonar_login,
                    'SONAR_PASSWORD': config.sonar_password
                },
                links={self.CONTAINER_NAME: self.CONTAINER_NAME},
                command=['-Dsonar.projectKey=secuscan_project', '-Dsonar.sources=.', '-Dsonar.java.binaries=.']
            )
            console.print("[green]SonarQube Scan completed successfully.[/green]")
            console.print(f"Results available at: {config.sonar_url}/dashboard?id=secuscan_project")
            
        except docker.errors.ContainerError as e:
            console.print(f"[bold red]SonarQube Scanner failed: {e}[/bold red]")
        except Exception as e:
            console.print(f"[bold red]Error running SonarQube scan: {e}[/bold red]")
