# CVE Finder

Fetch CVEs per application from NVD (National Vulnerability Database) API 2.0.

## Installation

```bash
pip install -e .
```

Or from the directory:
```bash
python -m pip install .
```

## Usage

After installation, use the `cve-finder` command:

```bash
# Using CPE (exact match)
cve-finder --cpe "cpe:2.3:a:gitlab:gitlab:16.7:*:*:*:*:*:*:*" --json output.json

# Using keyword search
cve-finder --app "nginx" --version "1.24.0" --csv nginx.csv

# Filter by severity and date
cve-finder --app "openssl" --severity CRITICAL --since 2024-01-01 --max 50

# Print to console (no file output)
cve-finder --app "tomcat" --version "9.0.0"
```

## Options

- `--cpe` - Exact CPE name for precise matching
- `--app` - Application name for keyword search
- `--version` - Optional version (with --app)
- `--since` - Filter CVEs published since date (YYYY-MM-DD)
- `--until` - End date for published window
- `--severity` - Filter by severity: LOW, MEDIUM, HIGH, CRITICAL
- `--max` - Maximum CVEs to fetch (default: 1000)
- `--json` - Save results to JSON file
- `--csv` - Save results to CSV file

## API Key

Set `NVD_API_KEY` environment variable to reduce rate limiting:
```bash
export NVD_API_KEY="your_key_here"
```

Get your API key at: https://nvd.nist.gov/developers/request-an-api-key
