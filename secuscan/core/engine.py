from typing import Optional
from rich.console import Console
from secuscan.core.config import config

from secuscan.core.detection import detect_project_type, ProjectType
from secuscan.core.docker_manager import DockerManager

console = Console()

class ScanEngine:
    """Orchestrates the scanning process."""
    
    def __init__(self, target: str):
        self.target = target
        self.docker_manager = DockerManager()
    
    def start(self):
        """Starts the vulnerability scan."""
        console.print(f"[bold green]Starting SecuScan analysis on:[/bold green] {self.target}")
        
        # 1. Detect Project Type
        project_type, stats = detect_project_type(self.target)
        console.print(f"Detected Project Type: [bold cyan]{project_type.name}[/bold cyan]")
        
        if config.debug:
            console.print(f"[dim]File Stats: {stats}[/dim]")

        # 2. Check Docker Availability
        if self.docker_manager.is_available():
            console.print("[green]Docker is available.[/green]")
        else:
            console.print("[yellow]Warning: Docker is not available. Deep scans (MobSF) will be skipped.[/yellow]")
            
        console.print("[bold blue]Analysis complete.[/bold blue]")
