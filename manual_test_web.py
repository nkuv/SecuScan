import sys
import logging
from secuscan.scanners.web.sast import WebScanner
from rich.console import Console

# Configure logging to see dependency check errors
logging.basicConfig(level=logging.INFO)

def main():
    target = "examples"
    print(f"Scanning target: {target}")
    
    try:
        scanner = WebScanner(target)
        results = scanner.scan()
        
        console = Console()
        console.print(results)
        
        if len(results) == 0:
            print("Scan completed (Empty results expected as logic is TODO).")
        else:
            print("Scan completed with results.")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
