import click
import logging
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
def scan(target, debug):
    """Run a vulnerability scan on a TARGET directory or file."""
    if debug:
        config.debug = True
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    else:
        logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        # Defaults to ERROR to keep CLI clean, unless specific components need INFO.
        
    engine = ScanEngine(target)
    engine.start()

if __name__ == "__main__":
    main()
