# SeeVee - CVE and CWE Vulnerability Information Tool

SeeVee is a comprehensive Python tool for querying CVE (Common Vulnerabilities and Exposures) and CWE (Common Weakness Enumeration) information. It can retrieve data from the National Vulnerability Database (NVD) API, build complete historical vulnerability databases, and provide detailed CVSS analysis with comprehensive timing and progress tracking.

## Features

- **🔍 CVE Lookup**: Get detailed information about CVEs including CVSS scores, descriptions, affected vendors/products, and references
- **🛡️ CWE Database**: Complete MITRE CWE database (399+ entries) with detailed descriptions and classifications  
- **📊 Advanced CVSS Analysis**: Detailed vector parsing, risk assessment, and component analysis for both v2 and v3
- **🗄️ Comprehensive Database**: Build complete historical vulnerability database from 2002 to present
- **⚡ Local SQLite Storage**: High-performance caching for offline access and faster lookups
- **🌐 NVD API Integration**: Direct integration with NVD API 2.0 with intelligent rate limiting
- **📈 Progress Tracking**: Real-time progress bars for downloads and imports with speed indicators
- **⏱️ Performance Timing**: Detailed timing analysis for database operations and feed processing
- **🔄 Bulk Feed Management**: Efficient downloading of yearly NVD feeds with SHA256 verification
- **🖥️ Dual Interface**: Full CLI and Python module interfaces
- **📤 Multiple Output Formats**: Human-readable, JSON, or specific data extraction

## Installation

1. Clone or download the repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

**Dependencies:**
- `requests>=2.28.0` - HTTP requests and API communication
- `urllib3>=1.26.0` - HTTP client library
- `tqdm>=4.64.0` - Progress bars and timing displays

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

#### Enhanced CVSS Analysis:
```bash
# Get only CVSS score
python seevee.py --cve CVE-2021-44228 --cvss-only

# Show detailed CVSS vector components
python seevee.py --cve CVE-2021-44228 --cvss-details

# Show CVSS risk analysis
python seevee.py --cve CVE-2021-44228 --cvss-risk
```

#### Database Operations:

**🚀 Build Complete Historical Database (NEW DEFAULT):**
```bash
# Downloads ALL historical data from 2002 to current year + recent updates
# Processes ~26 feeds chronologically with progress bars and timing
python seevee.py --update-db
```

**⚡ Quick Recent Updates:**
```bash
# Update specific years only  
python seevee.py --update-db --years 2023 2024 2025

# Update without recent/modified feeds (only yearly feeds)
python seevee.py --update-db --no-modified --years 2024
```

**🔧 CWE Database Management:**
```bash
# Update CWE database with latest data from MITRE (399+ entries)
python seevee.py --update-cwe
```

#### Output and API Options:
```bash
# Output as JSON
python seevee.py --cve CVE-2021-44228 --json

# Force API call (skip local database)
python seevee.py --cve CVE-2021-44228 --force-api

# Disable local database entirely
python seevee.py --cve CVE-2021-44228 --no-local-db

# Use NVD API key for higher rate limits
python seevee.py --cve CVE-2021-44228 --api-key YOUR_API_KEY
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

# Bulk database update with progress tracking
update_database(years=[2023, 2024], include_modified=True)

# Advanced feed management
feed_manager = NVDFeedManager(use_local_db=True)
vulnerabilities = feed_manager.download_feed("nvdcve-2.0-2024")
```

## Performance & Progress Tracking

SeeVee provides comprehensive progress tracking and timing analysis:

### Progress Indicators
- **📥 Download Progress**: Real-time download speeds (MB/s) with progress bars
- **🔄 Import Progress**: CVE processing speeds (CVE/s) with estimated completion times  
- **📊 CWE Updates**: Progress tracking for MITRE database imports
- **📦 Multi-Feed Processing**: Overall progress when processing multiple feeds

### Example Output:
```
Building comprehensive vulnerability database:
  • Historical feeds: 24 years (2002-2025)
  • Recent updates: modified and recent feeds
  • Total feeds to process: 26
  • Processing order: chronological (oldest to newest)

Downloading nvdcve-2.0-2024: 100%|████████| 18.4M/18.4M [00:04<00:00, 4.41MB/s]
Importing vulnerabilities: 100%|█████████| 38365/38365 [01:58<00:00, 324.04CVE/s]

=== Database Update Summary ===
Total vulnerabilities imported: 723,453
Total time: 45m 32.1s
Per-feed timing:
  nvdcve-2.0-2002: 12.3s
  nvdcve-2.0-2024: 2m 15.7s
Average time per feed: 1m 45.2s
```

### Performance Benchmarks
- **Import Speed**: ~320 CVE/s average processing rate
- **Download Speed**: 4-8 MB/s (network dependent)
- **Database Size**: ~500MB for complete historical database (2002-2025)
- **Quick Updates**: Recent feeds typically complete in <5 seconds
- **Full Build**: Complete historical database in ~45-60 minutes

## API Rate Limiting

The NVD API has rate limits:
- **Without API key**: 5 requests per 30 seconds
- **With API key**: 50 requests per 30 seconds

Get a free API key from: https://nvd.nist.gov/developers/request-an-api-key

## Local Database

SeeVee automatically creates a local SQLite database (`cve_database.db`) to cache CVE data. This provides:
- **⚡ Faster lookups**: Sub-second response times for cached data
- **🔌 Offline access**: Complete functionality without internet connection  
- **📉 Reduced API calls**: Minimize rate limiting and improve performance
- **📊 Rich storage**: Complete metadata with CVSS vectors and timing data

### Database Schema
The database stores:
- Complete CVE metadata and descriptions
- Full CVSS v2 and v3 vectors and component breakdowns
- CWE mappings and detailed weakness information
- Vendor/product information and reference links
- Feed metadata and update timestamps
- Publication and modification dates

## NVD Data Feeds

SeeVee supports efficient bulk downloading from NVD's JSON feeds:

### Available Feeds
- **📅 Yearly feeds**: Complete vulnerability data for specific years (2002-2025)
- **🔄 Modified feed**: Recently modified vulnerabilities (updated ~every 2 hours)
- **⚡ Recent feed**: Recently published vulnerabilities (updated ~every 2 hours)

### Feed Management Features
- **🔍 Smart Updates**: Only downloads feeds when they have changed (using META files)
- **✅ SHA256 verification**: Validates download integrity  
- **💾 Efficient storage**: Avoids duplicate downloads and processing
- **📈 Progress tracking**: Real-time download and import progress
- **⏱️ Performance timing**: Detailed timing analysis for optimization
- **📊 Historical data**: Complete access to vulnerability data back to 2002

### Database Update Strategies

**🏗️ Complete Database Build (NEW DEFAULT):**
```bash
# Downloads everything from 2002 to current year (26 feeds)
# Perfect for building comprehensive vulnerability database
python seevee.py --update-db
```

**⚡ Daily Updates:**
```bash  
# Quick updates for recent changes only
python seevee.py --update-db --years 2024 2025
```

**🎯 Targeted Analysis:**
```bash
# Specific years for security research
python seevee.py --update-db --years 2020 2021 2022 --no-modified
```

## Comprehensive CVSS Analysis

### Detailed Vector Support
SeeVee provides the most comprehensive CVSS analysis available:

```python
# Get complete CVSS vector string
vector = get_cvss_vector("CVE-2021-44228")
# Returns: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

# Parse vector into components
components = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
print(components['attackVector'])  # "NETWORK"
print(components['scope'])         # "CHANGED"

# Get detailed CVSS analysis
details = get_cvss_details("CVE-2021-44228")
print(f"Exploitability Score: {details['exploitabilityScore']}")
print(f"Impact Score: {details['impactScore']}")

# Automated risk assessment
risk = analyze_cvss_risk("CVE-2021-44228")
print("Risk Factors:")
for factor in risk['risk_factors']:
    print(f"  • {factor}")
```

### CVSS Component Analysis
- **🌐 Attack Vector**: Network, Adjacent, Local, Physical
- **🔧 Attack Complexity**: Low, High  
- **🔑 Privileges Required**: None, Low, High
- **👤 User Interaction**: None, Required
- **🎯 Scope**: Unchanged, Changed
- **💥 Impact Levels**: None, Low, High for C/I/A
- **📊 Composite Scores**: Exploitability and Impact scores
- **⚠️ Risk Analysis**: Automated risk factor identification

## CWE Database

SeeVee provides comprehensive CWE (Common Weakness Enumeration) support using the official MITRE CWE database:

### Features
- **📚 Complete Coverage**: Downloads entire MITRE CWE database (399+ entries)
- **📄 Rich Metadata**: Full descriptions, weakness abstractions, status information  
- **⚡ Local Storage**: SQLite database for fast offline access
- **🔄 Easy Updates**: Simple command to refresh CWE data
- **🛡️ Fallback Support**: Built-in mappings for common CWEs
- **📈 Progress Tracking**: Real-time import progress with timing

### CWE Update with Progress:
```bash
python seevee.py --update-cwe
```

**Example Output:**
```
Downloading CWE data from MITRE...
Extracting and parsing CWE data... (download took 0.9s)
Processing 399 CWE entries...
Importing CWE entries: 100%|████████| 399/399 [00:01<00:00, 349.29CWE/s]

=== CWE Update Summary ===
Download time: 0.9s
Processing time: 1.2s  
Total time: 2.1s
CWE database update completed. Total CWE entries: 399
```

### Available CWE Categories
Complete coverage including:
- **CWE-20**: Improper Input Validation
- **CWE-22**: Path Traversal  
- **CWE-79**: Cross-site Scripting (XSS)
- **CWE-89**: SQL Injection
- **CWE-119**: Buffer Overflow
- **CWE-200**: Information Exposure  
- **CWE-287**: Improper Authentication
- **CWE-434**: Unrestricted Upload of File with Dangerous Type
- **CWE-502**: Deserialization of Untrusted Data
- Plus 390+ additional weakness types from MITRE

## Examples

### Real-world CVE Examples

**Log4j Vulnerability (Log4Shell):**
```bash
python seevee.py --cve CVE-2021-44228 --cvss-risk
```

**Spring4Shell:**
```bash
python seevee.py --cve CVE-2022-22965 --cvss-details
```

**Heartbleed:**
```bash
python seevee.py --cve CVE-2014-0160 --json
```

### Security Assessment Script

```python
#!/usr/bin/env python3
"""
Example: Comprehensive security assessment script
"""
from seevee import get_cve_info, get_cvss_score, analyze_cvss_risk
import time

def assess_vulnerability_list(cve_list):
    """Assess multiple vulnerabilities with comprehensive analysis"""
    results = []
    
    print(f"Assessing {len(cve_list)} vulnerabilities...")
    start_time = time.time()
    
    for cve_id in cve_list:
        cve_data = get_cve_info(cve_id)
        if not cve_data:
            results.append(f"{cve_id}: Unable to retrieve data")
            continue
            
        cvss_score = cve_data.get('cvss_v3_score') or cve_data.get('cvss_v2_score')
        
        if cvss_score:
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"  
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
                
            # Get risk factors
            risk_analysis = analyze_cvss_risk(cve_id)
            risk_count = len(risk_analysis.get('risk_factors', [])) if risk_analysis else 0
            
            results.append({
                'cve': cve_id,
                'score': cvss_score,
                'severity': severity,
                'risk_factors': risk_count,
                'description': cve_data.get('description', '')[:100] + '...'
            })
        else:
            results.append(f"{cve_id}: No CVSS score available")
    
    duration = time.time() - start_time
    print(f"Assessment completed in {duration:.1f}s")
    return results

# Example usage
high_profile_cves = [
    "CVE-2021-44228",  # Log4Shell
    "CVE-2022-22965",  # Spring4Shell  
    "CVE-2014-0160",   # Heartbleed
    "CVE-2017-5638",   # Apache Struts
    "CVE-2021-34527"   # PrintNightmare
]

results = assess_vulnerability_list(high_profile_cves)
for result in results:
    if isinstance(result, dict):
        print(f"{result['cve']}: {result['score']} ({result['severity']}) - {result['risk_factors']} risk factors")
    else:
        print(result)
```

## Error Handling

The tool handles various error conditions gracefully:
- **🌐 Network issues**: Automatic retry with exponential backoff
- **⏱️ API rate limiting**: Intelligent waiting and retry logic  
- **❌ Invalid identifiers**: Clear error messages for malformed CVE/CWE IDs
- **💾 Database errors**: Automatic database initialization and repair
- **📁 File system issues**: Graceful handling of permissions and disk space
- **🔍 Download failures**: SHA256 verification and retry mechanisms

## Use Cases

### 🔍 Security Research
- Build comprehensive historical vulnerability database
- Analyze CVSS trends over time
- Research vulnerability patterns and classifications

### 🛡️ Vulnerability Management  
- Automate vulnerability assessment workflows
- Integrate with security scanning tools
- Generate detailed risk reports

### 📊 Compliance & Reporting
- Generate vulnerability summaries for compliance
- Track CVSS score distributions  
- Historical vulnerability impact analysis

### 🎓 Education & Training
- Offline CVE database for training environments
- CVSS methodology demonstration
- Security awareness and education

## Contributing

Contributions are welcome! Areas for enhancement:
- Additional output formats (CSV, XML)
- Advanced filtering and search capabilities  
- Integration with other vulnerability databases
- Performance optimizations for large datasets

## License

This tool is for educational and security research purposes. Please respect the NVD API terms of service and rate limits when using the API functionality. The bulk feed approach is preferred for large-scale data collection. 