
from typing import Optional
from rich.console import Console
from secuscan.core.config import config

from secuscan.core.detection import detect_project_type, ProjectType
from secuscan.core.docker_manager import DockerManager
from secuscan.scanners.factory import ScannerFactory

console = Console()

class ScanEngine:
    """Orchestrates the scanning process."""
    
    def __init__(self, target: str):
        self.target = target
        self.docker_manager = DockerManager()
    
    def start(self):
        """Starts the vulnerability scan."""
        console.print(f"[bold green]Starting SecuScan analysis on:[/bold green] {self.target}", style="bold")
        
        # 1. Detect Project Type
        with console.status("[bold green]Detecting project type...[/bold green]"):
            project_type, stats = detect_project_type(self.target)
        
        console.print(f"Detected Project Type: [bold cyan]{project_type.name}[/bold cyan]")
        
        if config.debug:
            console.print(f"[dim]File Stats: {stats}[/dim]")

        # 2. Check Docker Availability (if Android)
        if project_type == ProjectType.ANDROID:
            with console.status("[bold green]Checking Docker and MobSF status...[/bold green]"):
                if self.docker_manager.is_available():
                    console.print("[green]Docker is available.[/green]")
                    try:
                        self.docker_manager.ensure_mobsf()
                    except Exception as e:
                        console.print(f"[yellow]Warning: Failed to start MobSF: {e}. Skipping deep scan.[/yellow]")
                else:
                    console.print("[yellow]Warning: Docker is not available. Deep scans (MobSF) will be skipped.[/yellow]")
            
        # 3. Running Scanners
        scanner = ScannerFactory.get_scanner(project_type, self.target)
        
        if not scanner:
             console.print("[bold red]Error: Unrecognized project type.[/bold red]")
             console.print("Could not detect whether this is an Android or Web project.")
             return

        results = []
        with console.status(f"[bold green]Running {project_type.name} Scanner...[/bold green]"):
             # Add specific messaging depending on type
             if project_type == ProjectType.ANDROID and self.docker_manager.is_available():
                  console.print("[dim]Uploading and analyzing APK with MobSF (this may take a minute)...[/dim]")
             
             results = scanner.scan()
        
        # 4. Report Results
        if results:
            console.print(f"\n[bold red]Found {len(results)} issues:[/bold red]")
            for issue in results:
                severity_color = "red" if issue.severity == "HIGH" else "yellow" if issue.severity == "MEDIUM" else "green" 
                console.print(f" - [{severity_color}]{issue.severity}[/{severity_color}] in [bold]{issue.file}[/bold]: {issue.description}")
        else:
            console.print("\n[bold green]No obvious static issues found.[/bold green]")

        console.print("\n[bold blue]Analysis complete.[/bold blue]")
