# CVE Finder - AI Coding Agent Instructions

## Project Overview
CLI tool to fetch CVEs per application from NVD (CVE API 2.0). Supports CPE or keyword search, optional time window and severity filtering, and outputs grouped results or JSON/CSV.

## Architecture
- `cve_finder/cli.py` - CLI parsing, parameter building, pagination, and output routing
- `cve_finder/api.py` - NVD API requests and response parsing
- `cve_finder/models.py` - Data model (`CVEItem`)
- `cve_finder/utils.py` - Date/format helpers and CVSS parsing
- `cve_finder/output.py` - JSON/CSV/grouped formatting and file writes

## Tech Stack
- **Language**: Python 3.7+
- **Dependencies**: `requests`
- **Tests**: `pytest`, `pytest-cov`

## Development Workflow
- Run tests: `pytest`
- Coverage: `pytest --cov=cve_finder --cov-report=term-missing`

## Conventions
- Keep CLI behavior backward compatible.
- Severity filters are case-insensitive and can be repeated or comma-separated.
- Prefer small, focused functions and deterministic outputs for tests.
