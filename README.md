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

#### Show detailed CVSS vector components:
```bash
python seevee.py --cve CVE-2021-44228 --cvss-details
```

#### Show CVSS risk analysis:
```bash
python seevee.py --cve CVE-2021-44228 --cvss-risk
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

#### Update local database from NVD feeds:
```bash
# Update with current and previous year + recent/modified feeds
python seevee.py --update-db

# Update specific years only
python seevee.py --update-db --years 2023 2024 2025

# Update without recent/modified feeds (only yearly feeds)
python seevee.py --update-db --no-modified --years 2024
```

#### Update CWE database:
```bash
# Update CWE database with latest data from MITRE
python seevee.py --update-cwe
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

# Get CVSS vector string
vector = get_cvss_vector("CVE-2021-44228")
print(f"CVSS Vector: {vector}")

# Get detailed CVSS components
cvss_details = get_cvss_details("CVE-2021-44228")
print(f"Attack Vector: {cvss_details['attackVector']}")
print(f"Attack Complexity: {cvss_details['attackComplexity']}")
print(f"Privileges Required: {cvss_details['privilegesRequired']}")

# Analyze CVSS risk factors
risk_analysis = analyze_cvss_risk("CVE-2021-44228")
print(f"Risk Factors: {risk_analysis['risk_factors']}")

# Parse a CVSS vector string
parsed = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
print(f"Attack Vector: {parsed['attackVector']}")  # NETWORK
```

### Advanced Module Usage

```python
from seevee import NVDClient, CWEClient, NVDFeedManager, update_database

# Create client with API key and custom settings
nvd_client = NVDClient(api_key="your_api_key", use_local_db=True)

# Force API call even if data exists locally
cve_data = nvd_client.get_cve_info("CVE-2021-44228", force_api=True)

# Use CWE client directly
cwe_client = CWEClient()
cwe_info = cwe_client.get_cwe_info("CWE-79")

# Bulk database update
update_database(years=[2023, 2024], include_modified=True)

# Advanced feed management
feed_manager = NVDFeedManager(use_local_db=True)
vulnerabilities = feed_manager.download_feed("nvdcve-2.0-2024")
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

## NVD Data Feeds

SeeVee supports bulk downloading from NVD's traditional JSON feeds, which is much more efficient than individual API calls for large datasets:

### Available Feeds
- **Yearly feeds**: Complete vulnerability data for specific years (e.g., 2002-2025)
- **Modified feed**: Recently modified vulnerabilities (updated ~every 2 hours)
- **Recent feed**: Recently published vulnerabilities (updated ~every 2 hours)

### Feed Management Features
- **Automatic updates**: Only downloads feeds when they have changed (using META files)
- **SHA256 verification**: Validates download integrity
- **Efficient storage**: Avoids duplicate downloads and processing
- **Historical data**: Access to vulnerability data back to 2002

### Bulk Import Example
```bash
# Download current and previous year + recent changes
python seevee.py --update-db

# Download complete historical data (this will take a while!)
python seevee.py --update-db --years 2002 2003 2004 2005 2006 2007 2008 2009 2010 2011 2012 2013 2014 2015 2016 2017 2018 2019 2020 2021 2022 2023 2024 2025
```

This approach respects NVD's guidelines by checking META files before downloading and can efficiently maintain an up-to-date local copy of the entire NVD database.

## Supported Data

### CVE Information with Enhanced CVSS Analysis
- CVE ID and basic metadata
- CVSS v2 and v3 scores and severity ratings
- **CVSS vector strings** (e.g., `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`)
- **Detailed CVSS components**:
  - Attack Vector (Network, Adjacent, Local, Physical)
  - Attack Complexity (Low, High)
  - Privileges Required (None, Low, High)
  - User Interaction (None, Required)
  - Scope (Unchanged, Changed)
  - Impact levels for Confidentiality, Integrity, Availability
  - Exploitability and Impact scores
- **Automated risk factor analysis**
- Vulnerability descriptions
- Associated CWE IDs
- Vendor and product information
- Reference links
- Publication and modification dates

### CWE Information
SeeVee provides comprehensive CWE (Common Weakness Enumeration) support using the official MITRE CWE database:

**CWE Database Features:**
- **Complete Coverage**: Downloads and stores the entire MITRE CWE database (399+ entries)
- **Detailed Information**: Provides full descriptions, weakness abstractions, status, and extended descriptions
- **Local Storage**: Stores CWE data in SQLite database for fast offline access
- **Easy Updates**: Update the CWE database with `python seevee.py --update-cwe`
- **Fallback Support**: Includes built-in mappings for common CWEs when database is unavailable

**CWE Update Command:**
```bash
# Update the CWE database with latest data from MITRE
python seevee.py --update-cwe
```

**Available CWE data includes:**
- CWE-20: Improper Input Validation
- CWE-22: Path Traversal
- CWE-79: Cross-site Scripting (XSS)
- CWE-89: SQL Injection
- CWE-119: Buffer Overflow
- CWE-200: Information Exposure
- CWE-287: Improper Authentication
- CWE-434: Unrestricted Upload of File with Dangerous Type
- CWE-502: Deserialization of Untrusted Data
- And hundreds more from the complete MITRE database...

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