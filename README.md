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

# Filter by severity and date (case-insensitive)
cve-finder --app "openssl" --severity critical --since 2024-01-01 --max 50

# Multiple severities (repeat flag or comma-separated)
cve-finder --app "jira" --severity CRITICAL --severity MEDIUM
cve-finder --app "jira" --severity CRITICAL,MEDIUM

# Print to console (no file output)
cve-finder --app "tomcat" --version "9.0.0"
```

### Direct script usage

You can also run the entry script directly:

```bash
# Best (exact): use a CPE name
python main.py --cpe "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*" --csv nginx_1.24.0.csv

# Keyword search (fuzzier)
python main.py --app "nginx" --version "1.24.0" --json out.json

# Keyword search, no version
python main.py --app "openssl" --since 2024-01-01 --max 200 --csv openssl.csv
```

## Options

- `--cpe` - Exact CPE name for precise matching
- `--app` - Application name for keyword search
- `--version` - Optional version (with --app)
- `--since` - Filter CVEs published since date (YYYY-MM-DD)
- `--until` - End date for published window
- `--severity` - Filter by severity (case-insensitive). Repeat flag or use comma-separated list (LOW, MEDIUM, HIGH, CRITICAL)
- `--max` - Maximum CVEs to fetch (default: 1000)
- `--page-size` - Results per page (max 200)
- `--timeout` - HTTP timeout seconds
- `--json` - Save results to JSON file
- `--csv` - Save results to CSV file
- `--format` - Output format to stdout: json or csv

## API Key

Set `NVD_API_KEY` environment variable to reduce rate limiting:
```bash
export NVD_API_KEY="your_key_here"
```

Get your API key at: https://nvd.nist.gov/developers/request-an-api-key
