import docker
from typing import Optional
import requests
import time
import re
from rich.console import Console

console = Console()

class DockerManager:
    """Manages Docker container interactions."""
    
    MOBSF_IMAGE = "opensecurity/mobile-security-framework-mobsf:latest"
    
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

    def pull_image(self):
        """Pulls the MobSF Docker image if not present."""
        if not self.is_available():
            return

        try:
            self.client.images.get(self.MOBSF_IMAGE)
            console.print(f"[green]Image {self.MOBSF_IMAGE} found locally.[/green]")
        except docker.errors.ImageNotFound:
            console.print(f"[yellow]Pulling {self.MOBSF_IMAGE}...[/yellow]")
            with console.status("[bold green]Downloading MobSF image... This may take a while..."):
                self.client.images.pull(self.MOBSF_IMAGE)
            console.print("[green]Image pulled successfully.[/green]")

    def is_container_running(self) -> bool:
        """Checks if the MobSF container is currently running."""
        if not self.is_available():
            return False
            
        try:
            container = self.client.containers.get("secuscan-mobsf")
            return container.status == "running"
        except docker.errors.NotFound:
            return False

    def start_mobsf(self):
        """Starts the MobSF container."""
        if not self.is_available():
            raise RuntimeError("Docker is not available.")

        if self.is_container_running():
            console.print("[green]MobSF container is already running.[/green]")
            return

        console.print("[yellow]Starting MobSF container...[/yellow]")
        try:
            # Check if stopped container exists and remove it
            try:
                old_container = self.client.containers.get("secuscan-mobsf")
                old_container.remove()
            except docker.errors.NotFound:
                pass

            self.client.containers.run(
                self.MOBSF_IMAGE,
                name="secuscan-mobsf",
                ports={'8000/tcp': 8000},
                volumes={'mobsf_data': {'bind': '/root/.MobSF', 'mode': 'rw'}},
                detach=True
            )
            console.print("[green]MobSF container started on port 8000.[/green]")
            self.wait_for_mobsf()
            
        except Exception as e:
            console.print(f"[bold red]Failed to start MobSF container: {e}[/bold red]")
            raise

    def wait_for_mobsf(self, timeout: int = 60):
        """Waits for MobSF API to become available."""
        start_time = time.time()
        
        with console.status("[bold green]Waiting for MobSF to initialize (this usually takes 10-20s)...") as status:
            while time.time() - start_time < timeout:
                try:
                    # MobSF requires authorization generally, but for health check 
                    # we just want to see if the server responds, even 401/403 is fine.
                    requests.get("http://localhost:8000/", timeout=1)
                    console.print("[green]MobSF is ready![/green]")
                    return
                except requests.exceptions.RequestException:
                    time.sleep(2)
        
        raise TimeoutError("MobSF failed to start within the timeout period.")

    def stop_mobsf(self):
        """Stops the MobSF container."""
        if not self.is_available():
            return

        try:
            container = self.client.containers.get("secuscan-mobsf")
            console.print("[yellow]Stopping MobSF container...[/yellow]")
            container.stop()
            console.print("[green]MobSF container stopped.[/green]")
        except docker.errors.NotFound:
            pass
        except Exception as e:
            console.print(f"[bold red]Failed to stop MobSF: {e}[/bold red]")

    def ensure_mobsf(self):
        """Ensures MobSF is running and ready."""
        if not self.is_available():
             raise RuntimeError("Docker is not available.")
             
        self.pull_image()
        self.start_mobsf()

    def get_mobsf_api_key(self) -> Optional[str]:
        """Attempts to retrieve the API Key from MobSF container logs."""
        if not self.is_available():
            return None
            
        try:
            container = self.client.containers.get("secuscan-mobsf")
            logs = container.logs().decode('utf-8')
            
            # Find all occurrences of the key pattern
            # Matches: "REST API Key: <Optional ANSI Codes><Key>"
            # Handle potential ANSI color codes like \x1b[1m
            matches = re.findall(r'REST API Key:\s+(?:\x1b\[.*?m)?([a-zA-Z0-9]+)', logs)
            
            if matches:
                # remote potential duplicate outputs, take the most recent one (last one)
                return matches[-1]
                
        except Exception as e:
            # console.print(f"Debug: Failed to grep API Key: {e}")
            return None
        return None
