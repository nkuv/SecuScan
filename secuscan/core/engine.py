from typing import Optional
from rich.console import Console
from secuscan.core.config import config

from secuscan.core.detection import detect_project_type, ProjectType
from secuscan.core.docker_manager import DockerManager
from secuscan.scanners.android.scanner import AndroidScanner
from secuscan.scanners.web.scanner import WebScanner

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
            
        # 3. Running Static Scanners
        results = []
        if project_type == ProjectType.ANDROID:
            console.print("Running [bold]Android Static Scanner[/bold]...")
            scanner = AndroidScanner(self.target)
            results = scanner.scan()
        elif project_type == ProjectType.WEB:
             console.print("Running [bold]Web Static Scanner[/bold]...")
             scanner = WebScanner(self.target)
             results = scanner.scan()
        
        # 4. Report Results
        if results:
            console.print(f"\n[bold red]Found {len(results)} issues:[/bold red]")
            for issue in results:
                severity_color = "red" if issue['severity'] == "HIGH" else "yellow"
                console.print(f" - [{severity_color}]{issue['severity']}[/{severity_color}] in [bold]{issue['file']}[/bold]: {issue['description']}")
        else:
            console.print("\n[bold green]No obvious static issues found.[/bold green]")

        console.print("\n[bold blue]Analysis complete.[/bold blue]")
