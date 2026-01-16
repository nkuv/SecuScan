
from typing import Optional
from rich.console import Console
from secuscan.core.config import config

from secuscan.core.detection import detect_project_type, ProjectType
from secuscan.core.docker_manager import DockerManager
from secuscan.scanners.factory import ScannerFactory
from secuscan.scanners.secrets import SecretScanner

console = Console()

class ScanEngine:
    """Orchestrates the scanning process."""
    
    def __init__(self, target: str):
        self.target = target
        self.docker_manager = DockerManager()
    
    def start(self):
        """Starts the vulnerability scan and returns findings."""
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

        # Run Secret Scanner (Global)
        with console.status("[bold green]Scanning for Hardcoded Secrets...[/bold green]"):
            secret_scanner = SecretScanner(self.target)
            secret_results = secret_scanner.scan()
            if secret_results:
                console.print(f"[bold red]Found {len(secret_results)} potential secrets![/bold red]")
                results.extend(secret_results)
        
        # 4. Report Results (Handled by Caller/CLI via Reporter, or return results for CLI to handle)
        # Actually, refactoring plan said Engine should delegate. 
        # But CLI needs to pass format options. 
        # Better design: Engine returns results. CLI handles reporting.
        # However, to keep 'start()' API simple for now, let's accept format/output in start() or __init__.
        
        # Let's return results here so CLI can decide what to do.
        # Wait, start() current logic does printing.
        # Let's change start() to return List[Vulnerability] and print nothing (or minimal).
        
        return results
