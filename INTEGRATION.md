# SeeVee Integration Guide 📦

Complete guide for integrating SeeVee as a module into your Python applications and codebases.

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [CVE Operations](#cve-operations)
- [CWE Operations](#cwe-operations)
- [CVSS Analysis](#cvss-analysis)
- [Advanced Features](#advanced-features)
- [Database Management](#database-management)
- [Error Handling](#error-handling)
- [Performance Considerations](#performance-considerations)
- [Integration Patterns](#integration-patterns)
- [Configuration Options](#configuration-options)
- [Best Practices](#best-practices)

## Quick Start

```python
# Install SeeVee in your project
pip install -r requirements.txt  # From SeeVee directory

# Basic usage in your code
from seevee import get_cve_info, get_cwe_info

# Get CVE information with CWE details
cve_data = get_cve_info("CVE-2021-44228", include_cwe_details=True)
print(f"CVE: {cve_data['id']}")
print(f"CVSS: {cve_data.get('cvss_v3_score', 'N/A')}")

# Access CWE details if available
if cve_data.get('cwe_details'):
    for cwe in cve_data['cwe_details']:
        print(f"CWE: {cwe['cwe_id']} - {cwe['name']}")

# Get standalone CWE information
cwe_data = get_cwe_info("CWE-79")
print(f"CWE: {cwe_data['cwe_id']} - {cwe_data['name']}")
```

## Installation

### Option 1: Copy Module Files
```bash
# Copy the SeeVee files to your project
cp seevee.py your_project/
cp requirements.txt your_project/seevee_requirements.txt

# Install dependencies
pip install -r seevee_requirements.txt
```

### Option 2: Git Submodule
```bash
# Add SeeVee as a git submodule
git submodule add https://github.com/your-org/seevee.git libs/seevee
git submodule update --init

# In your Python code
import sys
sys.path.append('libs/seevee')
from seevee import get_cve_info, get_cwe_info
```

### Option 3: Package Installation (if packaged)
```bash
pip install seevee
```

## Basic Usage

### Import Core Functions

```python
from seevee import (
    get_cve_info,           # Get CVE details
    get_cwe_info,           # Get CWE details  
    get_cvss_score,         # Get CVSS score only
    get_cvss_vector,        # Get CVSS vector string
    get_cvss_details,       # Get detailed CVSS components
    analyze_cvss_risk,      # Get risk analysis
    parse_cvss_vector       # Parse CVSS vector string
)
```

### Database Setup

```python
from seevee import update_database, update_cwe_database

# One-time setup: Build local database (optional but recommended)
update_database()        # Download all CVE data (takes time)
update_cwe_database()    # Download CWE data (quick)
```

## CVE Operations

### Basic CVE Lookup

```python
from seevee import get_cve_info

# Simple lookup
cve_data = get_cve_info("CVE-2021-44228")

if cve_data:
    print(f"CVE ID: {cve_data['id']}")
    print(f"Published: {cve_data['published']}")
    print(f"CVSS v3 Score: {cve_data.get('cvss_v3_score', 'N/A')}")
    print(f"Severity: {cve_data.get('cvss_v3_severity', 'N/A')}")
    print(f"Description: {cve_data['description']}")
    print(f"Vendor: {cve_data.get('vendor_name', 'N/A')}")
    print(f"Product: {cve_data.get('product_name', 'N/A')}")
else:
    print("CVE not found")
```

### CVE Lookup with CWE Details

```python
# Get CVE with enriched CWE information
cve_data = get_cve_info("CVE-2021-44228", include_cwe_details=True)

if cve_data:
    print(f"CVE: {cve_data['id']} - {cve_data.get('cvss_v3_score', 'N/A')}")
    
    # Display CWE information
    if cve_data.get('cwe_details'):
        print("Associated Weaknesses:")
        for cwe in cve_data['cwe_details']:
            print(f"  {cwe['cwe_id']}: {cwe['name']}")
            if cwe.get('weakness_abstraction'):
                print(f"    Abstraction: {cwe['weakness_abstraction']}")
    elif cve_data.get('cwe_ids'):
        print(f"CWE IDs: {', '.join(cve_data['cwe_ids'])}")
```

### Advanced CVE Configuration

```python
from seevee import get_cve_info

# Force API call (bypass local cache)
cve_data = get_cve_info("CVE-2021-44228", force_api=True)

# Use specific API key
cve_data = get_cve_info("CVE-2021-44228", api_key="your_nvd_api_key")

# Disable local database entirely
cve_data = get_cve_info("CVE-2021-44228", use_local_db=False)

# Combine options
cve_data = get_cve_info(
    "CVE-2021-44228",
    api_key="your_api_key",
    use_local_db=True,
    force_api=False,
    include_cwe_details=True
)
```

## CWE Operations

### Basic CWE Lookup

```python
from seevee import get_cwe_info

# Lookup by CWE ID (various formats supported)
cwe_data = get_cwe_info("CWE-79")      # String format
cwe_data = get_cwe_info(79)            # Integer format  
cwe_data = get_cwe_info("79")          # String without prefix

if cwe_data:
    print(f"CWE ID: {cwe_data['cwe_id']}")
    print(f"Name: {cwe_data['name']}")
    print(f"Abstraction: {cwe_data.get('weakness_abstraction', 'N/A')}")
    print(f"Status: {cwe_data.get('status', 'N/A')}")
    print(f"Description: {cwe_data.get('description', 'N/A')}")
    print(f"Source: {cwe_data['source']}")
```

## CVSS Analysis

### Basic CVSS Operations

```python
from seevee import get_cvss_score, get_cvss_vector, get_cvss_details

cve_id = "CVE-2021-44228"

# Get just the score
cvss_score = get_cvss_score(cve_id)
print(f"CVSS Score: {cvss_score}")

# Get the vector string
cvss_vector = get_cvss_vector(cve_id)
print(f"CVSS Vector: {cvss_vector}")

# Get detailed components
cvss_details = get_cvss_details(cve_id)
if cvss_details:
    print(f"Attack Vector: {cvss_details.get('attackVector', 'N/A')}")
    print(f"Attack Complexity: {cvss_details.get('attackComplexity', 'N/A')}")
    print(f"Privileges Required: {cvss_details.get('privilegesRequired', 'N/A')}")
    print(f"User Interaction: {cvss_details.get('userInteraction', 'N/A')}")
    print(f"Scope: {cvss_details.get('scope', 'N/A')}")
    print(f"Impact (C/I/A): {cvss_details.get('confidentialityImpact', 'N/A')}/{cvss_details.get('integrityImpact', 'N/A')}/{cvss_details.get('availabilityImpact', 'N/A')}")
```

### CVSS Risk Analysis

```python
from seevee import analyze_cvss_risk

def assess_vulnerability_risk(cve_id):
    """Comprehensive risk assessment"""
    risk_analysis = analyze_cvss_risk(cve_id)
    
    if not risk_analysis:
        return {"error": "No CVSS data available"}
    
    assessment = {
        'cve_id': cve_id,
        'score': risk_analysis.get('base_score'),
        'severity': risk_analysis.get('severity'),
        'risk_factors': risk_analysis.get('risk_factors', []),
        'risk_level': 'unknown'
    }
    
    # Determine overall risk level
    score = assessment['score']
    risk_count = len(assessment['risk_factors'])
    
    if score >= 9.0:
        assessment['risk_level'] = 'critical'
    elif score >= 7.0 and risk_count >= 3:
        assessment['risk_level'] = 'high'
    elif score >= 4.0:
        assessment['risk_level'] = 'medium'
    else:
        assessment['risk_level'] = 'low'
    
    return assessment

# Example usage
risk = assess_vulnerability_risk("CVE-2021-44228")
print(f"Risk Level: {risk['risk_level'].upper()}")
print(f"CVSS Score: {risk['score']}")
print(f"Risk Factors ({len(risk['risk_factors'])}):")
for factor in risk['risk_factors']:
    print(f"  • {factor}")
```

## Advanced Features

### Custom CVE Analysis

```python
from seevee import get_cve_info, get_cvss_details, analyze_cvss_risk

class VulnerabilityAnalyzer:
    """Custom vulnerability analysis class"""
    
    def __init__(self):
        self.severity_weights = {
            'CRITICAL': 4,
            'HIGH': 3, 
            'MEDIUM': 2,
            'LOW': 1
        }
    
    def analyze_cve(self, cve_id):
        """Comprehensive CVE analysis"""
        # Get CVE data with CWE details
        cve_data = get_cve_info(cve_id, include_cwe_details=True)
        if not cve_data:
            return None
        
        # Get CVSS details
        cvss_details = get_cvss_details(cve_id)
        risk_analysis = analyze_cvss_risk(cve_id)
        
        # Build comprehensive analysis
        analysis = {
            'basic_info': {
                'cve_id': cve_data['id'],
                'published': cve_data['published'],
                'description': cve_data['description'],
                'vendor': cve_data.get('vendor_name', 'N/A'),
                'product': cve_data.get('product_name', 'N/A')
            },
            'scoring': {
                'cvss_v3_score': cve_data.get('cvss_v3_score'),
                'cvss_v3_severity': cve_data.get('cvss_v3_severity'),
                'cvss_v2_score': cve_data.get('cvss_v2_score'),
                'cvss_v2_severity': cve_data.get('cvss_v2_severity')
            },
            'weakness_analysis': self._analyze_weaknesses(cve_data.get('cwe_details', [])),
            'risk_factors': risk_analysis.get('risk_factors', []) if risk_analysis else [],
            'attack_vector': cvss_details.get('attackVector') if cvss_details else None,
            'exploitability': self._assess_exploitability(cvss_details, risk_analysis)
        }
        
        return analysis
    
    def _analyze_weaknesses(self, cwe_details):
        """Analyze CWE weakness patterns"""
        if not cwe_details:
            return {'count': 0, 'categories': [], 'severity': 'unknown'}
        
        categories = []
        for cwe in cwe_details:
            name = cwe['name'].lower()
            if 'injection' in name or 'sql' in name or 'xss' in name:
                categories.append('injection')
            elif 'authentication' in name:
                categories.append('authentication')
            elif 'authorization' in name or 'privilege' in name:
                categories.append('authorization')
            elif 'buffer' in name or 'memory' in name:
                categories.append('memory_corruption')
            else:
                categories.append('other')
        
        return {
            'count': len(cwe_details),
            'categories': list(set(categories)),
            'details': [{'id': cwe['cwe_id'], 'name': cwe['name']} for cwe in cwe_details]
        }
    
    def _assess_exploitability(self, cvss_details, risk_analysis):
        """Assess how easily the vulnerability can be exploited"""
        if not cvss_details:
            return 'unknown'
        
        # Simple exploitability assessment
        factors = []
        
        if cvss_details.get('attackVector') == 'NETWORK':
            factors.append('network_accessible')
        
        if cvss_details.get('attackComplexity') == 'LOW':
            factors.append('low_complexity')
        
        if cvss_details.get('privilegesRequired') == 'NONE':
            factors.append('no_privileges')
        
        if cvss_details.get('userInteraction') == 'NONE':
            factors.append('no_user_interaction')
        
        # Determine overall exploitability
        if len(factors) >= 3:
            return 'very_high'
        elif len(factors) >= 2:
            return 'high'
        elif len(factors) >= 1:
            return 'medium'
        else:
            return 'low'

# Example usage
analyzer = VulnerabilityAnalyzer()
analysis = analyzer.analyze_cve("CVE-2021-44228")

if analysis:
    print(f"CVE Analysis: {analysis['basic_info']['cve_id']}")
    print(f"CVSS Score: {analysis['scoring']['cvss_v3_score']}")
    print(f"Exploitability: {analysis['exploitability']}")
    print(f"Weakness Categories: {', '.join(analysis['weakness_analysis']['categories'])}")
    print(f"Risk Factors: {len(analysis['risk_factors'])}")
```

## Best Practices

### 1. Database Management
```python
# Initialize database early in your application
from seevee import update_cwe_database, update_database

def initialize_vulnerability_database():
    """One-time database setup"""
    # Quick CWE update (always do this)
    update_cwe_database()
    
    # CVE database update (can be slow)
    # For production: do this during maintenance windows
    # For development: use recent years only
    import os
    if os.getenv('ENVIRONMENT') == 'development':
        from datetime import datetime
        current_year = datetime.now().year
        update_database(years=[current_year - 1, current_year])
    else:
        update_database()  # Full database in production
```

### 2. Error Handling and Logging
```python
import logging
from seevee import get_cve_info

# Set up proper logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def robust_cve_lookup(cve_id):
    """Production-ready CVE lookup with logging"""
    try:
        logger.info(f"Looking up CVE: {cve_id}")
        cve_data = get_cve_info(cve_id, include_cwe_details=True)
        
        if cve_data:
            logger.info(f"Successfully retrieved {cve_id}")
            return cve_data
        else:
            logger.warning(f"CVE not found: {cve_id}")
            return None
            
    except Exception as e:
        logger.error(f"Error looking up {cve_id}: {str(e)}", exc_info=True)
        return None
```

### 3. Performance Optimization
```python
# Use local database for better performance
from seevee import get_cve_info

# Cache frequently accessed data
import functools

@functools.lru_cache(maxsize=1000)
def cached_cve_lookup(cve_id):
    """Cached CVE lookup for frequently accessed CVEs"""
    return get_cve_info(cve_id, include_cwe_details=True, use_local_db=True)
```

---

## Summary

SeeVee provides a powerful and flexible module interface for vulnerability data access. Key benefits for integration:

✅ **Rich Data**: CVE details with enhanced CWE information  
✅ **High Performance**: Local SQLite database for fast lookups  
✅ **Comprehensive CVSS**: Full vector parsing and risk analysis  
✅ **Flexible Configuration**: API keys, database options, caching  
✅ **Error Handling**: Robust error handling and logging support  
✅ **Production Ready**: Suitable for production applications and services  

For questions or advanced integration scenarios, refer to the main README.md or create an issue in the project repository. 