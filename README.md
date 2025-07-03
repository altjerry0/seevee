# SeeVee - CVE and CWE Vulnerability Information Tool

A comprehensive Python tool for querying CVE (Common Vulnerabilities and Exposures) and CWE (Common Weakness Enumeration) information. Provides **command-line interface**, **Python module**, and **high-performance REST API service**.

## 🚀 Quick Start

### 📦 Installation
```bash
git clone <repository-url>
cd seevee
pip install -r requirements.txt
```

### 🌐 REST API Service (Recommended)
```bash
# Start containerized API service
docker-compose up -d

# Test the API
python api_client_example.py

# Interactive docs: http://localhost:8000/docs
```

### 🖥️ Command Line Usage
```bash
# CVE lookup with CWE details
python seevee.py CVE-2021-44228 --cvss-details

# Build complete vulnerability database
python seevee.py --update-db --update-cwe

# Batch analysis with JSON output
python seevee.py CVE-2021-44228 CVE-2022-22965 --json
```

### 📦 Python Module
```python
from seevee import get_cve_info, get_cwe_info

# CVE with enhanced CWE details
cve_data = get_cve_info("CVE-2021-44228", include_cwe_details=True)
print(f"CVSS: {cve_data['cvss_v3_score']} - {cve_data['cvss_v3_severity']}")

# CWE information  
cwe_data = get_cwe_info("CWE-79")
print(f"CWE: {cwe_data['name']}")
```

## 📊 Data Models & Example Outputs

### CVE Response Structure
```python
{
    "id": "CVE-2021-44228",
    "published": "2021-12-10T10:15:09.143",
    "description": "Apache Log4j2 2.0-beta9 through 2.15.0...",
    "cvss_v3_score": 10.0,
    "cvss_v3_severity": "CRITICAL", 
    "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cvss_v3_details": {
        "attackVector": "NETWORK",
        "attackComplexity": "LOW",
        "privilegesRequired": "NONE",
        "scope": "CHANGED"
    },
    "vendor_name": "apache",
    "product_name": "log4j",
    "cwe_ids": ["CWE-20", "CWE-502"],
    "cwe_details": [
        {
            "cwe_id": "CWE-20",
            "name": "Improper Input Validation",
            "weakness_abstraction": "Class",
            "status": "Draft"
        },
        {
            "cwe_id": "CWE-502", 
            "name": "Deserialization of Untrusted Data",
            "weakness_abstraction": "Variant",
            "status": "Draft"
        }
    ],
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
}
```

### CWE Response Structure
```python
{
    "cwe_id": "CWE-79",
    "name": "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)",
    "weakness_abstraction": "Variant",
    "status": "Draft",
    "description": "The software does not neutralize or incorrectly neutralizes user-controllable input...",
    "extended_description": "Cross-site scripting (XSS) vulnerabilities occur when...",
    "source": "database"  # or "fallback mapping"
}
```

### Command Line Example Output
```bash
$ python seevee.py CVE-2021-44228 --cvss-details

CVE-2021-44228 - Apache Log4j2 JNDI features do not protect against attacker controlled LDAP
═══════════════════════════════════════════════════════════════════════════════════════════

Published: 2021-12-10T10:15:09.143

CVSS v3.1 Score: 10.0 (CRITICAL)
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

Attack Characteristics:
├─ Attack Vector: NETWORK
├─ Attack Complexity: LOW  
├─ Privileges Required: NONE
├─ User Interaction: NONE
└─ Scope: CHANGED

Impact Assessment:
├─ Confidentiality Impact: HIGH
├─ Integrity Impact: HIGH
└─ Availability Impact: HIGH

CWE Weaknesses:
├─ CWE-20: Improper Input Validation (Class)
├─ CWE-502: Deserialization of Untrusted Data (Variant)
└─ CWE-917: Improper Neutralization of Special Elements

Risk Factors:
• Network accessible
• Low attack complexity  
• No privileges required
• High impact on all security aspects
```

### API Response Example
```json
{
  "cve_id": "CVE-2021-44228",
  "found": true,
  "data": {
    "id": "CVE-2021-44228",
    "cvss_v3_score": 10.0,
    "cvss_v3_severity": "CRITICAL",
    "cwe_details": [
      {
        "cwe_id": "CWE-20",
        "name": "Improper Input Validation",
        "weakness_abstraction": "Class"
      }
    ]
  },
  "risk_analysis": {
    "v3": {
      "risk_factors": [
        "Network accessible",
        "Low attack complexity", 
        "No privileges required"
      ],
      "risk_score": 10.0
    }
  }
}
```

## 🔗 Documentation

| Topic | Documentation File | Description |
|-------|-------------------|-------------|
| **🌐 API Service** | [API_SERVICE.md](API_SERVICE.md) | REST API endpoints, Docker deployment, performance metrics |
| **📦 Module Integration** | [INTEGRATION.md](INTEGRATION.md) | Python module usage, advanced features, integration patterns |

## 📈 Performance & Scale

- **300,103+ CVEs**: Complete NVD database (2002-present)
- **399+ CWEs**: Full MITRE CWE database
- **235+ CVE/s**: High-performance batch processing
- **1.4GB Database**: Efficient SQLite storage for offline access
- **<100ms**: Single API response time

## 🛠️ Core Features

- **🔍 CVE Analysis**: Complete vulnerability data with CVSS v2/v3 scoring
- **🛡️ CWE Integration**: Enhanced weakness classification from MITRE database  
- **📊 CVSS Parsing**: Detailed vector analysis and risk assessment
- **🌐 Multi-Interface**: CLI, Python module, and REST API
- **⚡ High Performance**: Optimized for both single lookups and batch processing
- **🗄️ Offline Capable**: Local SQLite database for air-gapped environments

## 📋 Quick Reference

### Common Commands
```bash
# Single CVE lookup
python seevee.py CVE-2021-44228

# Multiple CVEs with JSON output  
python seevee.py CVE-2021-44228 CVE-2022-22965 --json

# CWE lookup
python seevee.py --cwe CWE-79

# Database operations
python seevee.py --update-db --years 2023 2024
python seevee.py --update-cwe

# CVSS analysis
python seevee.py CVE-2021-44228 --cvss-details --cvss-risk
```

### Python Module Functions
```python
# Core functions
get_cve_info(cve_id, include_cwe_details=True)
get_cwe_info(cwe_id)
get_cvss_score(cve_id, version='v3')
get_cvss_details(cve_id, version='v3')
analyze_cvss_risk(cve_id, version='v3')

# Database management
update_database(years=[2023, 2024])
update_cwe_database()
```

### API Endpoints
```bash
# Single lookups
GET /cve/CVE-2021-44228?include_risk_analysis=true
GET /cwe/CWE-79

# Batch processing
POST /cve/batch
POST /cwe/batch

# Service info
GET /health
GET /stats
```

## 📄 License

This project is licensed under the MIT License. 