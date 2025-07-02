# SeeVee - CVE and CWE Vulnerability Information Tool

SeeVee is a Python tool for querying CVE (Common Vulnerabilities and Exposures) and CWE (Common Weakness Enumeration) information. It can retrieve data from the National Vulnerability Database (NVD) API and store it locally for offline access.

## Features

- **CVE Lookup**: Get detailed information about CVEs including CVSS scores, descriptions, affected vendors/products, and references
- **CWE Lookup**: Query CWE information to understand vulnerability types
- **Local Database**: SQLite database for caching CVE data for offline access
- **API Integration**: Direct integration with NVD API 2.0
- **CLI Interface**: Command-line tool for quick lookups
- **Module Import**: Use as a Python module in your own scripts
- **Rate Limiting**: Built-in retry logic and rate limiting handling
- **Multiple Output Formats**: Human-readable, JSON, or specific data extraction

## Installation

1. Clone or download the repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Command Line Interface

#### Basic CVE lookup:
```bash
python seevee.py --cve CVE-2021-44228
```

#### CWE lookup:
```bash
python seevee.py --cwe CWE-79
# or
python seevee.py --cwe 79
```

#### Get only CVSS score:
```bash
python seevee.py --cve CVE-2021-44228 --cvss-only
```

#### Output as JSON:
```bash
python seevee.py --cve CVE-2021-44228 --json
```

#### Force API call (skip local database):
```bash
python seevee.py --cve CVE-2021-44228 --force-api
```

#### Disable local database entirely:
```bash
python seevee.py --cve CVE-2021-44228 --no-local-db
```

#### Use NVD API key for higher rate limits:
```bash
python seevee.py --cve CVE-2021-44228 --api-key YOUR_API_KEY
```

#### Look up both CVE and CWE:
```bash
python seevee.py --cve CVE-2021-44228 --cwe CWE-502
```

### Module Import

Use SeeVee in your own Python scripts:

```python
from seevee import get_cve_info, get_cwe_info, get_cvss_score

# Get CVE information
cve_data = get_cve_info("CVE-2021-44228")
if cve_data:
    print(f"CVSS Score: {cve_data.get('cvss_v3_score')}")
    print(f"Description: {cve_data.get('description')}")

# Get CWE information
cwe_data = get_cwe_info("CWE-502")
if cwe_data:
    print(f"CWE Name: {cwe_data['name']}")

# Get just the CVSS score
cvss_score = get_cvss_score("CVE-2021-44228")
print(f"CVSS v3 Score: {cvss_score}")

# Get CVSS v2 score
cvss_v2_score = get_cvss_score("CVE-2021-44228", version="v2")
```

### Advanced Module Usage

```python
from seevee import NVDClient, CWEClient

# Create client with API key and custom settings
nvd_client = NVDClient(api_key="your_api_key", use_local_db=True)

# Force API call even if data exists locally
cve_data = nvd_client.get_cve_info("CVE-2021-44228", force_api=True)

# Use CWE client directly
cwe_client = CWEClient()
cwe_info = cwe_client.get_cwe_info("CWE-79")
```

## API Rate Limiting

The NVD API has rate limits:
- **Without API key**: 5 requests per 30 seconds
- **With API key**: 50 requests per 30 seconds

Get a free API key from: https://nvd.nist.gov/developers/request-an-api-key

## Local Database

SeeVee automatically creates a local SQLite database (`cve_database.db`) to cache CVE data. This provides:
- Faster subsequent lookups
- Offline access to previously queried CVEs
- Reduced API calls

The database stores:
- Complete CVE metadata
- CVSS scores (v2 and v3)
- CWE mappings
- References and vendor information

## Supported Data

### CVE Information
- CVE ID and basic metadata
- CVSS v2 and v3 scores and severity ratings
- Vulnerability descriptions
- Associated CWE IDs
- Vendor and product information
- Reference links
- Publication and modification dates

### CWE Information
The tool includes built-in mappings for common CWE types including:
- CWE-20: Improper Input Validation
- CWE-22: Path Traversal
- CWE-79: Cross-site Scripting (XSS)
- CWE-89: SQL Injection
- CWE-119: Buffer Overflow
- CWE-200: Information Exposure
- CWE-287: Improper Authentication
- And many more...

## Examples

### Real-world CVE Examples

**Log4j Vulnerability (Log4Shell):**
```bash
python seevee.py --cve CVE-2021-44228
```

**Spring4Shell:**
```bash
python seevee.py --cve CVE-2022-22965
```

**Heartbleed:**
```bash
python seevee.py --cve CVE-2014-0160
```

### Integration Example

```python
#!/usr/bin/env python3
"""
Example: Security assessment script
"""
from seevee import get_cve_info, get_cvss_score

def assess_vulnerability(cve_id):
    """Assess the severity of a vulnerability"""
    cvss_score = get_cvss_score(cve_id)
    
    if not cvss_score:
        return f"{cve_id}: Unable to retrieve CVSS score"
    
    if cvss_score >= 9.0:
        severity = "CRITICAL"
    elif cvss_score >= 7.0:
        severity = "HIGH"
    elif cvss_score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
    return f"{cve_id}: {cvss_score} ({severity})"

# Assess multiple vulnerabilities
vulnerabilities = ["CVE-2021-44228", "CVE-2022-22965", "CVE-2014-0160"]
for cve in vulnerabilities:
    print(assess_vulnerability(cve))
```

## Error Handling

The tool handles various error conditions gracefully:
- Network connectivity issues
- API rate limiting
- Invalid CVE/CWE identifiers
- Database errors

## Contributing

To extend the CWE database, modify the `cwe_mappings` dictionary in the `CWEClient` class or load mappings from an external file.

## License

This tool is for educational and security research purposes. Please respect the NVD API terms of service and rate limits. 