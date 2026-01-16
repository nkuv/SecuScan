# SecuScan

A dual-platform static vulnerability scanner for **Android** and **Web** applications.

## Features
- **Auto-Detection**: Automatically detects if the project is Android or Web.
- **Web Scanning**: Uses `Bandit` to find security issues in Python code.
- **Android Scanning**: Uses `MobSF` (via Docker) for deep APK analysis.
- **Reporting**: Output to Console (Rich Table), HTML, or JSON.
- **CI/CD Ready**: Exit codes for passing/failing builds based on severity.

## Getting Started

### Option 1: Docker (Easiest)
You can use the pre-built image directly from Docker Hub without installing Python dependencies.

```bash
# Pull the latest image
docker pull secuscan/secuscan:latest

# Run a scan on the current directory
docker run --rm -v $(pwd):/scan secuscan/secuscan:latest scan /scan
```
*Note: The official image is available at `secuscan/secuscan`.*

### Option 2: PyPI (Python Package)
Install directly via pip:

```bash
pip install secuscan
```

### Option 3: Local Installation
If you prefer to run it from source:

```bash
git clone https://github.com/nkuv/SecuScan.git
cd SecuScan
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
```

### Option 4: Build from Source
To build the Docker image locally:

```bash
docker build -f docker/Dockerfile -t secuscan .
docker run --rm -v $(pwd):/scan secuscan scan /scan
```

## Usage

### Basic Scan
```bash
secuscan scan .
```

### Output Formats
```bash
secuscan scan . --format table          # Pretty table (default via console)
secuscan scan . --format console        # Text list
secuscan scan . --format json --output report.json
secuscan scan . --format html --output report.html
```

### CI/CD Integration
SecuScan will exit with **code 1** if any **HIGH** or **CRITICAL** vulnerabilities are found.

```yaml
steps:
  - name: Security Scan
    uses: docker://secuscan/secuscan:latest
    with:
      args: scan .
```
