import click
import logging
import sys
from secuscan.core.engine import ScanEngine
from secuscan.core.config import config

@click.group()
@click.version_option()
def main():
    """SecuScan - Vulnerability Scanner for Android and Web"""
    pass

@main.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--debug", is_flag=True, help="Enable debug mode")
@click.option("--format", type=click.Choice(['console', 'table', 'json', 'html'], case_sensitive=False), default="console", help="Output format.")
@click.option("--output", help="Path to save the report file.")
def scan(target, debug, format, output):
    """Run a vulnerability scan on a TARGET directory or file."""
    if debug:
        config.debug = True
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    else:
        logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
    engine = ScanEngine(target)
    results = engine.start()
    
    if results is None:
        # Error during detection
        sys.exit(1)
        
    # Reporting
    from secuscan.reporting.reporter import Reporter
    reporter = Reporter()
    reporter.report(results, output_format=format, output_path=output)
    
    # CI/CD Exit Code
    if results:
        # Exit with 1 if any issues found (security gate)
        sys.exit(1)
    
    sys.exit(0)

if __name__ == "__main__":
    main()
