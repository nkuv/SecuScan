import json
import os
from typing import List, Dict
from datetime import datetime
from rich.console import Console
from rich.table import Table
from jinja2 import Environment, FileSystemLoader
from secuscan.scanners.models import Vulnerability

console = Console()

class Reporter:
    """Handles reporting of scan results in various formats."""
    
    @staticmethod
    def _sort_results(results: List[Vulnerability]) -> List[Vulnerability]:
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return sorted(results, key=lambda x: severity_order.get(x.severity.upper(), 4))

    @staticmethod
    def show_console(results: List[Vulnerability], use_table: bool = False):
        results = Reporter._sort_results(results)
        if not results:
            console.print("\n[bold green]No obvious static issues found.[/bold green]")
            return

        if use_table:
            table = Table(title=f"Scan Results ({len(results)} issues found)")
            table.add_column("Severity", justify="center", style="bold")
            table.add_column("File", style="cyan")
            table.add_column("Line", justify="right")
            table.add_column("Description")

            for issue in results:
                if issue.severity == "CRITICAL":
                    severity_style = "bold red"
                elif issue.severity == "HIGH":
                    severity_style = "red"
                elif issue.severity == "MEDIUM":
                    severity_style = "yellow"
                else:
                    severity_style = "green"
                table.add_row(
                    f"[{severity_style}]{issue.severity}[/{severity_style}]",
                    issue.file,
                    str(issue.line) if issue.line else "-",
                    issue.description
                )
            console.print(table)
        else:
            # Restore original text format
            console.print(f"\n[bold red]Found {len(results)} issues:[/bold red]")
            for issue in results:
                if issue.severity == "CRITICAL":
                    severity_color = "bold red"
                elif issue.severity == "HIGH":
                    severity_color = "red"
                elif issue.severity == "MEDIUM":
                    severity_color = "yellow"
                else:
                    severity_color = "green"
                console.print(f" - [{severity_color}]{issue.severity}[/{severity_color}] in [bold]{issue.file}[/bold]: {issue.description}")
                if issue.line:
                    console.print(f"   [dim]Line: {issue.line}[/dim]")

    @staticmethod
    def save_json(results: List[Vulnerability], output_path: str):
        results = Reporter._sort_results(results)
        data = [issue.__dict__ for issue in results]
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        console.print(f"[green]Report saved to {output_path}[/green]")

    @staticmethod
    def save_html(results: List[Vulnerability], output_path: str):
        results = Reporter._sort_results(results)
        try:
            template_dir = os.path.join(os.path.dirname(__file__), 'templates')
            env = Environment(loader=FileSystemLoader(template_dir))
            template = env.get_template('report_template.html')
            
            html_output = template.render(
                results=results,
                generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_output)
                
            console.print(f"[bold green]HTML Report saved to {output_path}[/bold green]")
            
        except Exception as e:
            console.print(f"[bold red]Failed to generate HTML report: {e}[/bold red]")

    def report(self, results: List[Vulnerability], output_format: str = "console", output_path: str = None):
        """Main entry point for reporting."""
        
        if output_format == "console":
            self.show_console(results, use_table=False)
        elif output_format == "table":
            self.show_console(results, use_table=True)
        elif output_format == "json":
             if output_path:
                 self.save_json(results, output_path)
             else:
                 # Print JSON to stdout
                 print(json.dumps([i.__dict__ for i in results], indent=4))
        elif output_format == "html":
             if output_path:
                 self.save_html(results, output_path)
             else:
                 console.print("[red]Error: HTML format requires --output path.[/red]")
