#!/usr/bin/env python3
"""
SeeVee - CVE and CWE Vulnerability Information Tool

This script provides functionality to query CVE (Common Vulnerabilities and Exposures)
and CWE (Common Weakness Enumeration) information from various sources.

Usage:
    Command line: python seevee.py --cve CVE-2021-44228
    Module import: from seevee import get_cve_info, get_cwe_info
"""

import argparse
import gzip
import hashlib
import io
import json
import os
import sqlite3
import sys
import time
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Union
from urllib.parse import quote, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class SeeVeeError(Exception):
    """Custom exception for SeeVee operations"""
    pass


class CVEDatabase:
    """Handles local SQLite database operations for CVE data"""
    
    def __init__(self, db_path: str = "cve_database.db"):
        self.db_path = Path(db_path)
        self.init_database()
    
    def init_database(self):
        """Initialize the SQLite database with required tables"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_data (
                    cve_id TEXT PRIMARY KEY,
                    published_date TEXT,
                    last_modified TEXT,
                    cvss_v3_score REAL,
                    cvss_v3_severity TEXT,
                    cvss_v2_score REAL,
                    cvss_v2_severity TEXT,
                    description TEXT,
                    references TEXT,
                    cwe_ids TEXT,
                    vendor_name TEXT,
                    product_name TEXT,
                    raw_data TEXT
                )
            """)
            
            # Table to track feed metadata
            conn.execute("""
                CREATE TABLE IF NOT EXISTS feed_metadata (
                    feed_name TEXT PRIMARY KEY,
                    last_modified TEXT,
                    sha256 TEXT,
                    last_updated TEXT
                )
            """)
            conn.commit()
    
    def store_cve(self, cve_data: Dict) -> bool:
        """Store CVE data in the local database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO cve_data 
                    (cve_id, published_date, last_modified, cvss_v3_score, cvss_v3_severity,
                     cvss_v2_score, cvss_v2_severity, description, references, cwe_ids,
                     vendor_name, product_name, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cve_data.get('id'),
                    cve_data.get('published'),
                    cve_data.get('lastModified'),
                    cve_data.get('cvss_v3_score'),
                    cve_data.get('cvss_v3_severity'),
                    cve_data.get('cvss_v2_score'),
                    cve_data.get('cvss_v2_severity'),
                    cve_data.get('description'),
                    json.dumps(cve_data.get('references', [])),
                    json.dumps(cve_data.get('cwe_ids', [])),
                    cve_data.get('vendor_name'),
                    cve_data.get('product_name'),
                    json.dumps(cve_data)
                ))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error storing CVE data: {e}")
            return False
    
    def get_cve(self, cve_id: str) -> Optional[Dict]:
        """Retrieve CVE data from the local database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT raw_data FROM cve_data WHERE cve_id = ?", (cve_id,)
                )
                result = cursor.fetchone()
                if result:
                    return json.loads(result[0])
                return None
        except Exception as e:
            print(f"Error retrieving CVE data: {e}")
            return None
    
    def store_feed_metadata(self, feed_name: str, last_modified: str, sha256: str):
        """Store feed metadata to track updates"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO feed_metadata 
                    (feed_name, last_modified, sha256, last_updated)
                    VALUES (?, ?, ?, ?)
                """, (feed_name, last_modified, sha256, datetime.now().isoformat()))
                conn.commit()
        except Exception as e:
            print(f"Error storing feed metadata: {e}")
    
    def get_feed_metadata(self, feed_name: str) -> Optional[Dict]:
        """Get stored feed metadata"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT last_modified, sha256, last_updated FROM feed_metadata WHERE feed_name = ?", 
                    (feed_name,)
                )
                result = cursor.fetchone()
                if result:
                    return {
                        'last_modified': result[0],
                        'sha256': result[1],
                        'last_updated': result[2]
                    }
                return None
        except Exception as e:
            print(f"Error retrieving feed metadata: {e}")
            return None


class NVDFeedManager:
    """Manages NVD data feeds for bulk operations"""
    
    FEED_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"
    
    def __init__(self, use_local_db: bool = True):
        self.use_local_db = use_local_db
        self.db = CVEDatabase() if use_local_db else None
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry strategy"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        session.headers.update({
            'User-Agent': 'SeeVee/1.0',
            'Accept': 'application/json'
        })
        
        return session
    
    def get_feed_metadata(self, feed_name: str) -> Optional[Dict]:
        """Get metadata for a specific feed"""
        try:
            url = f"{self.FEED_BASE_URL}/{feed_name}.meta"
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            metadata = {}
            for line in response.text.strip().split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    metadata[key] = value
            
            return metadata
        except Exception as e:
            print(f"Error fetching feed metadata for {feed_name}: {e}")
            return None
    
    def download_feed(self, feed_name: str, format_type: str = 'gz') -> Optional[List[Dict]]:
        """Download and parse a CVE feed"""
        try:
            # Check if we need to update
            if self.use_local_db:
                remote_meta = self.get_feed_metadata(feed_name)
                if remote_meta:
                    local_meta = self.db.get_feed_metadata(feed_name)
                    if local_meta and local_meta['last_modified'] == remote_meta.get('lastModifiedDate'):
                        print(f"Feed {feed_name} is already up to date")
                        return None
            
            # Download the feed
            url = f"{self.FEED_BASE_URL}/{feed_name}.json.{format_type}"
            print(f"Downloading {feed_name} feed...")
            
            response = self.session.get(url, timeout=300)  # 5 minute timeout for large files
            response.raise_for_status()
            
            # Extract and parse the data
            if format_type == 'gz':
                data = gzip.decompress(response.content).decode('utf-8')
            elif format_type == 'zip':
                with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
                    data = zf.read(f"{feed_name}.json").decode('utf-8')
            else:
                data = response.text
            
            # Verify SHA256 if available
            if self.use_local_db and remote_meta and 'sha256' in remote_meta:
                actual_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
                if actual_hash != remote_meta['sha256']:
                    print(f"Warning: SHA256 mismatch for {feed_name}")
            
            feed_data = json.loads(data)
            vulnerabilities = feed_data.get('vulnerabilities', [])
            
            print(f"Downloaded {len(vulnerabilities)} vulnerabilities from {feed_name}")
            
            # Store metadata
            if self.use_local_db and remote_meta:
                self.db.store_feed_metadata(
                    feed_name, 
                    remote_meta.get('lastModifiedDate', ''), 
                    remote_meta.get('sha256', '')
                )
            
            return vulnerabilities
            
        except Exception as e:
            print(f"Error downloading feed {feed_name}: {e}")
            return None
    
    def update_database_from_feeds(self, years: Optional[List[int]] = None, include_modified: bool = True):
        """Update local database from NVD feeds"""
        if not self.use_local_db:
            print("Database not enabled")
            return
        
        # Determine which feeds to download
        feeds_to_download = []
        
        if include_modified:
            feeds_to_download.extend(['nvdcve-2.0-modified', 'nvdcve-2.0-recent'])
        
        if years:
            for year in years:
                feeds_to_download.append(f'nvdcve-2.0-{year}')
        else:
            # Default to current and previous year
            current_year = datetime.now().year
            feeds_to_download.extend([
                f'nvdcve-2.0-{current_year}',
                f'nvdcve-2.0-{current_year - 1}'
            ])
        
        print(f"Updating database from feeds: {feeds_to_download}")
        
        total_imported = 0
        for feed_name in feeds_to_download:
            vulnerabilities = self.download_feed(feed_name)
            if vulnerabilities:
                imported = self._import_vulnerabilities(vulnerabilities)
                total_imported += imported
                print(f"Imported {imported} vulnerabilities from {feed_name}")
        
        print(f"Total vulnerabilities imported: {total_imported}")
    
    def _import_vulnerabilities(self, vulnerabilities: List[Dict]) -> int:
        """Import vulnerabilities into the database"""
        imported_count = 0
        client = NVDClient(use_local_db=True)
        
        for vuln in vulnerabilities:
            try:
                cve_data = client._parse_cve_data(vuln)
                if self.db.store_cve(cve_data):
                    imported_count += 1
            except Exception as e:
                print(f"Error importing vulnerability {vuln.get('cve', {}).get('id', 'unknown')}: {e}")
        
        return imported_count


class NVDClient:
    """Client for interacting with the National Vulnerability Database (NVD) API"""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json"
    
    def __init__(self, api_key: Optional[str] = None, use_local_db: bool = True):
        self.api_key = api_key
        self.use_local_db = use_local_db
        self.db = CVEDatabase() if use_local_db else None
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry strategy"""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        headers = {
            'User-Agent': 'SeeVee/1.0',
            'Accept': 'application/json'
        }
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        session.headers.update(headers)
        return session
    
    def get_cve_info(self, cve_id: str, force_api: bool = False) -> Optional[Dict]:
        """
        Get CVE information from NVD API or local database
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")
            force_api: Force API call even if local data exists
            
        Returns:
            Dictionary containing CVE information or None if not found
        """
        cve_id = cve_id.upper()
        
        # Check local database first (unless forced to use API)
        if self.use_local_db and not force_api:
            local_data = self.db.get_cve(cve_id)
            if local_data:
                print(f"Found {cve_id} in local database")
                return local_data
        
        # Query NVD API
        try:
            url = f"{self.BASE_URL}/cves/2.0"
            params = {'cveId': cve_id}
            
            print(f"Querying NVD API for {cve_id}...")
            response = self.session.get(url, params=params, timeout=30)
            
            if response.status_code == 429:
                print("Rate limited by NVD API. Please wait and try again.")
                return None
            
            response.raise_for_status()
            data = response.json()
            
            if not data.get('vulnerabilities'):
                print(f"No data found for {cve_id}")
                return None
            
            # Parse the CVE data
            vulnerability = data['vulnerabilities'][0]
            cve_data = self._parse_cve_data(vulnerability)
            
            # Store in local database
            if self.use_local_db:
                self.db.store_cve(cve_data)
            
            return cve_data
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching CVE data: {e}")
            return None
        except Exception as e:
            print(f"Error parsing CVE data: {e}")
            return None
    
    def _parse_cve_data(self, vulnerability: Dict) -> Dict:
        """Parse raw NVD vulnerability data into a structured format"""
        cve = vulnerability.get('cve', {})
        
        # Basic information
        cve_data = {
            'id': cve.get('id'),
            'sourceIdentifier': cve.get('sourceIdentifier'),
            'published': cve.get('published'),
            'lastModified': cve.get('lastModified'),
            'vulnStatus': cve.get('vulnStatus')
        }
        
        # Description
        descriptions = cve.get('descriptions', [])
        description = next((d['value'] for d in descriptions if d['lang'] == 'en'), 'N/A')
        cve_data['description'] = description
        
        # CVSS scores
        metrics = cve.get('metrics', {})
        
        # CVSS v3.x
        cvss_v3 = metrics.get('cvssMetricV31') or metrics.get('cvssMetricV30')
        if cvss_v3:
            cvss_data = cvss_v3[0]['cvssData']
            cve_data['cvss_v3_score'] = cvss_data.get('baseScore')
            cve_data['cvss_v3_severity'] = cvss_data.get('baseSeverity')
            cve_data['cvss_v3_vector'] = cvss_data.get('vectorString')
        
        # CVSS v2
        cvss_v2 = metrics.get('cvssMetricV2')
        if cvss_v2:
            cvss_data = cvss_v2[0]['cvssData']
            cve_data['cvss_v2_score'] = cvss_data.get('baseScore')
            cve_data['cvss_v2_severity'] = cvss_data.get('baseSeverity')
            cve_data['cvss_v2_vector'] = cvss_data.get('vectorString')
        
        # CWE information
        weaknesses = cve.get('weaknesses', [])
        cwe_ids = []
        for weakness in weaknesses:
            for desc in weakness.get('description', []):
                if desc.get('lang') == 'en':
                    cwe_ids.append(desc.get('value'))
        cve_data['cwe_ids'] = cwe_ids
        
        # References
        references = []
        for ref in cve.get('references', []):
            references.append({
                'url': ref.get('url'),
                'source': ref.get('source'),
                'tags': ref.get('tags', [])
            })
        cve_data['references'] = references
        
        # Vendor and product information
        configurations = cve.get('configurations', [])
        vendors = set()
        products = set()
        
        for config in configurations:
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    cpe = cpe_match.get('criteria', '')
                    if cpe.startswith('cpe:2.3:'):
                        parts = cpe.split(':')
                        if len(parts) >= 5:
                            vendors.add(parts[3])
                            products.add(parts[4])
        
        cve_data['vendor_name'] = ', '.join(sorted(vendors)) if vendors else 'N/A'
        cve_data['product_name'] = ', '.join(sorted(products)) if products else 'N/A'
        
        return cve_data


class CWEClient:
    """Client for Common Weakness Enumeration (CWE) information"""
    
    def __init__(self):
        # Common CWE mappings - this could be expanded or loaded from a file
        self.cwe_mappings = {
            'CWE-1': 'Location',
            'CWE-2': '7PK - Environment',
            'CWE-3': '7PK - Time and State',
            'CWE-20': 'Improper Input Validation',
            'CWE-22': 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)',
            'CWE-79': 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)',
            'CWE-89': 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)',
            'CWE-94': 'Improper Control of Generation of Code (Code Injection)',
            'CWE-119': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
            'CWE-125': 'Out-of-bounds Read',
            'CWE-190': 'Integer Overflow or Wraparound',
            'CWE-200': 'Exposure of Sensitive Information to an Unauthorized Actor',
            'CWE-269': 'Improper Privilege Management',
            'CWE-287': 'Improper Authentication',
            'CWE-352': 'Cross-Site Request Forgery (CSRF)',
            'CWE-416': 'Use After Free',
            'CWE-476': 'NULL Pointer Dereference',
            'CWE-502': 'Deserialization of Untrusted Data',
            'CWE-787': 'Out-of-bounds Write',
            'CWE-798': 'Use of Hard-coded Credentials',
            'CWE-862': 'Missing Authorization',
            'CWE-863': 'Incorrect Authorization',
            'CWE-918': 'Server-Side Request Forgery (SSRF)',
        }
    
    def get_cwe_info(self, cwe_id: Union[str, int]) -> Optional[Dict]:
        """
        Get CWE information
        
        Args:
            cwe_id: CWE identifier (e.g., "CWE-79" or 79)
            
        Returns:
            Dictionary containing CWE information or None if not found
        """
        # Normalize CWE ID
        if isinstance(cwe_id, int):
            cwe_key = f"CWE-{cwe_id}"
        else:
            cwe_id = str(cwe_id).upper()
            if not cwe_id.startswith('CWE-'):
                cwe_key = f"CWE-{cwe_id}"
            else:
                cwe_key = cwe_id
        
        # Look up in our mappings
        description = self.cwe_mappings.get(cwe_key)
        
        if description:
            return {
                'cwe_id': cwe_key,
                'name': description,
                'source': 'built-in mapping'
            }
        else:
            # For unmapped CWEs, we could potentially query MITRE's CWE database
            # For now, return basic info
            return {
                'cwe_id': cwe_key,
                'name': f'Unknown CWE (not in built-in mapping)',
                'source': 'unknown'
            }


def get_cve_info(cve_id: str, api_key: Optional[str] = None, use_local_db: bool = True, force_api: bool = False) -> Optional[Dict]:
    """
    Get CVE information (module function)
    
    Args:
        cve_id: CVE identifier
        api_key: NVD API key (optional)
        use_local_db: Whether to use local database
        force_api: Force API call even if local data exists
        
    Returns:
        Dictionary containing CVE information or None if not found
    """
    client = NVDClient(api_key=api_key, use_local_db=use_local_db)
    return client.get_cve_info(cve_id, force_api=force_api)


def get_cwe_info(cwe_id: Union[str, int]) -> Optional[Dict]:
    """
    Get CWE information (module function)
    
    Args:
        cwe_id: CWE identifier
        
    Returns:
        Dictionary containing CWE information or None if not found
    """
    client = CWEClient()
    return client.get_cwe_info(cwe_id)


def get_cvss_score(cve_id: str, version: str = 'v3', **kwargs) -> Optional[float]:
    """
    Get CVSS score for a CVE (convenience function)
    
    Args:
        cve_id: CVE identifier
        version: CVSS version ('v2' or 'v3')
        **kwargs: Additional arguments passed to get_cve_info
        
    Returns:
        CVSS score or None if not found
    """
    cve_data = get_cve_info(cve_id, **kwargs)
    if not cve_data:
        return None
    
    if version.lower() == 'v2':
        return cve_data.get('cvss_v2_score')
    else:
        return cve_data.get('cvss_v3_score')


def update_database(years: Optional[List[int]] = None, include_modified: bool = True):
    """
    Update local database from NVD feeds
    
    Args:
        years: List of years to download (default: current and previous year)
        include_modified: Whether to include modified and recent feeds
    """
    feed_manager = NVDFeedManager(use_local_db=True)
    feed_manager.update_database_from_feeds(years=years, include_modified=include_modified)


def print_cve_info(cve_data: Dict):
    """Pretty print CVE information"""
    print(f"\n=== {cve_data['id']} ===")
    print(f"Published: {cve_data.get('published', 'N/A')}")
    print(f"Last Modified: {cve_data.get('lastModified', 'N/A')}")
    print(f"Status: {cve_data.get('vulnStatus', 'N/A')}")
    
    if cve_data.get('cvss_v3_score'):
        print(f"CVSS v3 Score: {cve_data['cvss_v3_score']} ({cve_data.get('cvss_v3_severity', 'N/A')})")
    
    if cve_data.get('cvss_v2_score'):
        print(f"CVSS v2 Score: {cve_data['cvss_v2_score']} ({cve_data.get('cvss_v2_severity', 'N/A')})")
    
    print(f"Vendor: {cve_data.get('vendor_name', 'N/A')}")
    print(f"Product: {cve_data.get('product_name', 'N/A')}")
    
    if cve_data.get('cwe_ids'):
        print(f"CWE IDs: {', '.join(cve_data['cwe_ids'])}")
    
    print(f"\nDescription:")
    print(f"{cve_data.get('description', 'N/A')}")
    
    if cve_data.get('references'):
        print(f"\nReferences:")
        for ref in cve_data['references'][:5]:  # Show first 5 references
            print(f"  - {ref['url']}")


def print_cwe_info(cwe_data: Dict):
    """Pretty print CWE information"""
    print(f"\n=== {cwe_data['cwe_id']} ===")
    print(f"Name: {cwe_data['name']}")
    print(f"Source: {cwe_data['source']}")


def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description="SeeVee - CVE and CWE Vulnerability Information Tool"
    )
    
    # CVE options
    parser.add_argument('--cve', type=str, help='CVE identifier to lookup (e.g., CVE-2021-44228)')
    parser.add_argument('--cwe', type=str, help='CWE identifier to lookup (e.g., CWE-79 or 79)')
    
    # Database management
    parser.add_argument('--update-db', action='store_true', help='Update local database from NVD feeds')
    parser.add_argument('--years', type=int, nargs='+', help='Years to download (default: current and previous year)')
    parser.add_argument('--no-modified', action='store_true', help='Skip modified and recent feeds when updating')
    
    # API options
    parser.add_argument('--api-key', type=str, help='NVD API key for higher rate limits')
    parser.add_argument('--no-local-db', action='store_true', help='Disable local database storage')
    parser.add_argument('--force-api', action='store_true', help='Force API call even if local data exists')
    
    # Output options
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--cvss-only', action='store_true', help='Output only CVSS score')
    
    args = parser.parse_args()
    
    if args.update_db:
        print("Updating local database from NVD feeds...")
        update_database(
            years=args.years, 
            include_modified=not args.no_modified
        )
        return
    
    if not args.cve and not args.cwe:
        parser.print_help()
        return
    
    try:
        if args.cve:
            print(f"Looking up CVE: {args.cve}")
            cve_data = get_cve_info(
                args.cve,
                api_key=args.api_key,
                use_local_db=not args.no_local_db,
                force_api=args.force_api
            )
            
            if not cve_data:
                print(f"No data found for {args.cve}")
                sys.exit(1)
            
            if args.cvss_only:
                cvss_score = cve_data.get('cvss_v3_score') or cve_data.get('cvss_v2_score')
                print(cvss_score if cvss_score else 'N/A')
            elif args.json:
                print(json.dumps(cve_data, indent=2))
            else:
                print_cve_info(cve_data)
        
        if args.cwe:
            print(f"Looking up CWE: {args.cwe}")
            cwe_data = get_cwe_info(args.cwe)
            
            if not cwe_data:
                print(f"No data found for {args.cwe}")
                sys.exit(1)
            
            if args.json:
                print(json.dumps(cwe_data, indent=2))
            else:
                print_cwe_info(cwe_data)
                
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
