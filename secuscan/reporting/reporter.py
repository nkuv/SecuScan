import json
import os
from typing import List, Dict
from rich.console import Console
from rich.table import Table
from secuscan.scanners.models import Vulnerability

console = Console()

class Reporter:
    """Handles reporting of scan results in various formats."""
    
    @staticmethod
    def show_console(results: List[Vulnerability]):
        if not results:
            console.print("\n[bold green]No obvious static issues found.[/bold green]")
            return

        console.print(f"\n[bold red]Found {len(results)} issues:[/bold red]")
        
        # Optional: Use a Rich Table for cleaner output?
        # For now, stick to the existing list format as it's compact.
        for issue in results:
            severity_color = "red" if issue.severity == "HIGH" else "yellow" if issue.severity == "MEDIUM" else "green"
            console.print(f" - [{severity_color}]{issue.severity}[/{severity_color}] in [bold]{issue.file}[/bold]: {issue.description}")
            if issue.line:
                console.print(f"   [dim]Line: {issue.line}[/dim]")

    @staticmethod
    def save_json(results: List[Vulnerability], output_path: str):
        data = [issue.__dict__ for issue in results]
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        console.print(f"[green]Report saved to {output_path}[/green]")

    @staticmethod
    def save_html(results: List[Vulnerability], output_path: str):
        # Simple HTML template
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SecuScan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .HIGH {{ color: red; font-weight: bold; }}
                .MEDIUM {{ color: orange; font-weight: bold; }}
                .LOW {{ color: green; }}
            </style>
        </head>
        <body>
            <h1>SecuScan Vulnerability Report</h1>
            <p>Found {len(results)} issues.</p>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>File</th>
                    <th>Line</th>
                    <th>Description</th>
                </tr>
        """
        
        for issue in results:
            html_content += f"""
                <tr>
                    <td class="{issue.severity}">{issue.severity}</td>
                    <td>{issue.file}</td>
                    <td>{issue.line if issue.line else 'N/A'}</td>
                    <td>{issue.description}</td>
                </tr>
            """
        
        html_content += """
            </table>
        </body>
        </html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        console.print(f"[green]Report saved to {output_path}[/green]")

    def report(self, results: List[Vulnerability], output_format: str = "console", output_path: str = None):
        """Main entry point for reporting."""
        
        # Always output to console logic? 
        # If format is JSON/HTML, user probably still wants to see summary in console.
        # But 'console' format specifically means DETAILED console output.
        
        if output_format == "console":
            self.show_console(results)
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
