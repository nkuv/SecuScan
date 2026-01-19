# SecuScan

A dual-platform static vulnerability scanner for **Android** and **Web** applications.

## Features
- **Auto-Detection**: Automatically detects if the project is Android or Web.
- **Web Scanning**: Uses `Bandit` to find security issues in Python code.
- **Android Scanning**: Uses `MobSF` (via Docker) for deep APK analysis.
- **Reporting**: Output to Console (Rich Table), HTML, or JSON.
- **CI/CD Ready**: Exit codes for passing/failing builds based on severity.

## Getting Started

### Option 1: PyPI (Recommended)
Install directly via pip:

```bash
pip install secuscan
secuscan scan .
```

### Option 2: Docker

```bash
curl -sL https://raw.githubusercontent.com/nkuv/SecuScan/main/docker/docker-compose.yml | docker-compose -f - run --rm secuscan scan /scan
```


<details>
<summary>Alternative: Direct Docker Run (Web only)</summary>

```bash
docker pull secuscan/secuscan:latest
docker run --rm -v ${PWD}:/scan secuscan/secuscan:latest scan /scan
```

</details>

### Option 3: Local Installation

```bash
git clone https://github.com/nkuv/SecuScan.git
cd SecuScan
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
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
