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
import csv
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
from tqdm import tqdm
import time


class SeeVeeError(Exception):
    """Custom exception for SeeVee operations"""
    pass


class CVEDatabase:
    """Handles local SQLite database operations for CVE data"""
    
    def __init__(self, db_path: str = "cve_database.db"):
        self.db_path = Path(db_path)
        self.is_initialized = False
        self.init_database()
    
    def init_database(self):
        """Initialize the SQLite database with required tables"""
        # Try multiple database locations in case of permission issues
        db_locations = [
            self.db_path,
            Path.home() / "seevee_database.db",  # User home directory
            Path.cwd() / "temp_database.db"      # Temporary alternative
        ]
        
        for db_path in db_locations:
            try:
                # Store the working database path
                self.db_path = db_path
                
                # Ensure the parent directory exists
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
                
                # If database file exists but is corrupt, try to remove it
                if self.db_path.exists():
                    try:
                        # Test if we can open the existing database
                        test_conn = sqlite3.connect(str(self.db_path))
                        test_conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
                        test_conn.close()
                    except sqlite3.Error:
                        # Database is corrupt, try to remove it
                        try:
                            print(f"Removing corrupted database file: {self.db_path}")
                            self.db_path.unlink()
                        except PermissionError:
                            print(f"Cannot remove corrupted database due to permissions: {self.db_path}")
                            # Try next location instead
                            continue
                
                # Create database with proper error handling
                with sqlite3.connect(str(self.db_path)) as conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS cve_data (
                            cve_id TEXT PRIMARY KEY,
                            published_date TEXT,
                            last_modified TEXT,
                            cvss_v3_score REAL,
                            cvss_v3_severity TEXT,
                            cvss_v3_vector TEXT,
                            cvss_v3_details TEXT,
                            cvss_v2_score REAL,
                            cvss_v2_severity TEXT,
                            cvss_v2_vector TEXT,
                            cvss_v2_details TEXT,
                            description TEXT,
                            reference_urls TEXT,
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
                    
                    # Table for CWE data
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS cwe_data (
                            cwe_id TEXT PRIMARY KEY,
                            name TEXT,
                            weakness_abstraction TEXT,
                            status TEXT,
                            description TEXT,
                            extended_description TEXT,
                            last_updated TEXT
                        )
                    """)
                    conn.commit()
                    self.is_initialized = True
                    print(f"Database initialized successfully at: {self.db_path}")
                    return  # Success, exit the loop
                    
            except Exception as e:
                print(f"Could not initialize database at {db_path}: {e}")
                continue  # Try next location
        
        # If we get here, all locations failed
        print("Warning: Could not initialize database at any location.")
        print("Database operations will be disabled. The tool will use NVD API instead.")
        self.is_initialized = False
    
    def store_cve(self, cve_data: Dict) -> bool:
        """Store CVE data in the local database"""
        if not self.is_initialized:
            return False
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO cve_data 
                    (cve_id, published_date, last_modified, cvss_v3_score, cvss_v3_severity,
                     cvss_v3_vector, cvss_v3_details, cvss_v2_score, cvss_v2_severity,
                     cvss_v2_vector, cvss_v2_details, description, reference_urls, cwe_ids,
                     vendor_name, product_name, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cve_data.get('id'),
                    cve_data.get('published'),
                    cve_data.get('lastModified'),
                    cve_data.get('cvss_v3_score'),
                    cve_data.get('cvss_v3_severity'),
                    cve_data.get('cvss_v3_vector'),
                    json.dumps(cve_data.get('cvss_v3_details', {})),
                    cve_data.get('cvss_v2_score'),
                    cve_data.get('cvss_v2_severity'),
                    cve_data.get('cvss_v2_vector'),
                    json.dumps(cve_data.get('cvss_v2_details', {})),
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

    def store_cwe(self, cwe_data: Dict) -> bool:
        """Store CWE data in the local database"""
        if not self.is_initialized:
            return False
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO cwe_data 
                    (cwe_id, name, weakness_abstraction, status, description, extended_description, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    f"CWE-{cwe_data.get('CWE-ID')}",
                    cwe_data.get('Name'),
                    cwe_data.get('Weakness Abstraction'),
                    cwe_data.get('Status'),
                    cwe_data.get('Description'),
                    cwe_data.get('Extended Description'),
                    datetime.now().isoformat()
                ))
                conn.commit()
                return True
        except Exception as e:
            print(f"Error storing CWE data: {e}")
            return False
    
    def get_cve(self, cve_id: str) -> Optional[Dict]:
        """Retrieve CVE data from the local database"""
        if not self.is_initialized:
            return None
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
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

    def get_cwe(self, cwe_id: str) -> Optional[Dict]:
        """Retrieve CWE data from the local database"""
        if not self.is_initialized:
            return None
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.execute(
                    "SELECT cwe_id, name, weakness_abstraction, status, description, extended_description FROM cwe_data WHERE cwe_id = ?", 
                    (cwe_id,)
                )
                result = cursor.fetchone()
                if result:
                    return {
                        'cwe_id': result[0],
                        'name': result[1],
                        'weakness_abstraction': result[2],
                        'status': result[3],
                        'description': result[4],
                        'extended_description': result[5],
                        'source': 'database'
                    }
                return None
        except Exception as e:
            print(f"Error retrieving CWE data: {e}")
            return None

    def get_cwe_count(self) -> int:
        """Get the number of CWE entries in the database"""
        if not self.is_initialized:
            return 0
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM cwe_data")
                result = cursor.fetchone()
                return result[0] if result else 0
        except Exception as e:
            print(f"Error counting CWE entries: {e}")
            return 0
    
    def store_feed_metadata(self, feed_name: str, last_modified: str, sha256: str):
        """Store feed metadata to track updates"""
        if not self.is_initialized:
            return
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
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
        if not self.is_initialized:
            return None
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
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
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive'
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
            
            # Download with progress bar
            response = self.session.get(url, timeout=300, stream=True)  # 5 minute timeout for large files
            response.raise_for_status()
            
            # Get total file size if available
            total_size = int(response.headers.get('content-length', 0))
            
            # Download with progress bar
            downloaded_data = b""
            with tqdm(total=total_size, unit='B', unit_scale=True, desc=f"Downloading {feed_name}") as pbar:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        downloaded_data += chunk
                        pbar.update(len(chunk))
            
            # Extract and parse the data
            print(f"Extracting and parsing {feed_name}...")
            if format_type == 'gz':
                data = gzip.decompress(downloaded_data).decode('utf-8')
            elif format_type == 'zip':
                with zipfile.ZipFile(io.BytesIO(downloaded_data)) as zf:
                    data = zf.read(f"{feed_name}.json").decode('utf-8')
            else:
                data = downloaded_data.decode('utf-8')
            
            # Verify SHA256 if available
            if self.use_local_db and remote_meta and 'sha256' in remote_meta:
                print("Verifying file integrity...")
                actual_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
                if actual_hash != remote_meta['sha256']:
                    print(f"Warning: SHA256 mismatch for {feed_name}")
            
            print("Parsing JSON data...")
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
        """
        Update local database from NVD feeds
        
        Args:
            years: List of specific years to download. If None, downloads all years from 2002 to current year.
            include_modified: Whether to include modified and recent feeds for latest updates.
        """
        start_time = time.time()
        
        if not self.use_local_db:
            print("Database not enabled")
            return
        
        # Determine which feeds to download
        feeds_to_download = []
        current_year = datetime.now().year
        
        if years:
            # Sort years chronologically (old to new)
            sorted_years = sorted(years)
            for year in sorted_years:
                feeds_to_download.append(f'nvdcve-2.0-{year}')
        else:
            # Default to all years from 2002 to current year (chronological order)
            print(f"No specific years specified. Downloading all historical data from 2002 to {current_year}...")
            for year in range(2002, current_year + 1):
                feeds_to_download.append(f'nvdcve-2.0-{year}')
        
        # Add modified/recent feeds at the end to get latest updates
        if include_modified:
            feeds_to_download.extend(['nvdcve-2.0-modified', 'nvdcve-2.0-recent'])
        
        if years:
            print(f"Updating database from {len(feeds_to_download)} specified feed(s)")
        else:
            year_count = current_year - 2002 + 1
            print(f"Building comprehensive vulnerability database:")
            print(f"  • Historical feeds: {year_count} years (2002-{current_year})")
            if include_modified:
                print(f"  • Recent updates: modified and recent feeds")
            print(f"  • Total feeds to process: {len(feeds_to_download)}")
            print(f"  • Processing order: chronological (oldest to newest)")
        
        print(f"\nFeed processing order: {feeds_to_download}")
        
        total_imported = 0
        feed_times = {}
        
        with tqdm(total=len(feeds_to_download), desc="Processing feeds", unit="feed") as feed_pbar:
            for feed_name in feeds_to_download:
                feed_start_time = time.time()
                feed_pbar.set_description(f"Processing {feed_name}")
                vulnerabilities = self.download_feed(feed_name)
                if vulnerabilities:
                    imported = self._import_vulnerabilities(vulnerabilities)
                    total_imported += imported
                    feed_duration = time.time() - feed_start_time
                    feed_times[feed_name] = feed_duration
                    tqdm.write(f"Imported {imported} vulnerabilities from {feed_name} ({format_duration(feed_duration)})")
                else:
                    feed_duration = time.time() - feed_start_time
                    feed_times[feed_name] = feed_duration
                    tqdm.write(f"No new data to import from {feed_name} ({format_duration(feed_duration)})")
                feed_pbar.update(1)
        
        total_duration = time.time() - start_time
        print(f"\n=== Database Update Summary ===")
        print(f"Total vulnerabilities imported: {total_imported}")
        print(f"Total time: {format_duration(total_duration)}")
        
        if len(feeds_to_download) > 1:
            print(f"\nPer-feed timing:")
            for feed_name in feeds_to_download:
                if feed_name in feed_times:
                    print(f"  {feed_name}: {format_duration(feed_times[feed_name])}")
                    
        print(f"Average time per feed: {format_duration(total_duration / len(feeds_to_download))}")
    
    def _import_vulnerabilities(self, vulnerabilities: List[Dict]) -> int:
        """Import vulnerabilities into the database"""
        imported_count = 0
        client = NVDClient(use_local_db=True)
        
        # Import with progress bar
        with tqdm(total=len(vulnerabilities), desc="Importing vulnerabilities", unit="CVE") as pbar:
            for vuln in vulnerabilities:
                try:
                    cve_data = client._parse_cve_data(vuln)
                    if self.db.store_cve(cve_data):
                        imported_count += 1
                except Exception as e:
                    cve_id = vuln.get('cve', {}).get('id', 'unknown')
                    tqdm.write(f"Error importing vulnerability {cve_id}: {e}")
                finally:
                    pbar.update(1)
        
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
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive'
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
            
            # Extract detailed CVSS v3 components
            cve_data['cvss_v3_details'] = {
                'version': cvss_data.get('version'),
                'attackVector': cvss_data.get('attackVector'),
                'attackComplexity': cvss_data.get('attackComplexity'),
                'privilegesRequired': cvss_data.get('privilegesRequired'),
                'userInteraction': cvss_data.get('userInteraction'),
                'scope': cvss_data.get('scope'),
                'confidentialityImpact': cvss_data.get('confidentialityImpact'),
                'integrityImpact': cvss_data.get('integrityImpact'),
                'availabilityImpact': cvss_data.get('availabilityImpact'),
                'baseScore': cvss_data.get('baseScore'),
                'baseSeverity': cvss_data.get('baseSeverity'),
                'exploitabilityScore': cvss_data.get('exploitabilityScore'),
                'impactScore': cvss_data.get('impactScore')
            }
        
        # CVSS v2
        cvss_v2 = metrics.get('cvssMetricV2')
        if cvss_v2:
            cvss_data = cvss_v2[0]['cvssData']
            cve_data['cvss_v2_score'] = cvss_data.get('baseScore')
            cve_data['cvss_v2_severity'] = cvss_data.get('baseSeverity')
            cve_data['cvss_v2_vector'] = cvss_data.get('vectorString')
            
            # Extract detailed CVSS v2 components
            cve_data['cvss_v2_details'] = {
                'version': cvss_data.get('version'),
                'accessVector': cvss_data.get('accessVector'),
                'accessComplexity': cvss_data.get('accessComplexity'),
                'authentication': cvss_data.get('authentication'),
                'confidentialityImpact': cvss_data.get('confidentialityImpact'),
                'integrityImpact': cvss_data.get('integrityImpact'),
                'availabilityImpact': cvss_data.get('availabilityImpact'),
                'baseScore': cvss_data.get('baseScore'),
                'baseSeverity': cvss_data.get('baseSeverity'),
                'exploitabilityScore': cvss_data.get('exploitabilityScore'),
                'impactScore': cvss_data.get('impactScore')
            }
        
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
    
    def __init__(self, use_local_db: bool = True):
        self.use_local_db = use_local_db
        self.db = CVEDatabase() if use_local_db else None
        
        # Fallback CWE mappings for cases where database is not available
        self.fallback_mappings = {
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
    
    def download_and_import_cwe_data(self) -> bool:
        """
        Download the latest CWE data from MITRE and import it into the database
        
        Returns:
            True if successful, False otherwise
        """
        start_time = time.time()
        
        if not self.use_local_db or not self.db:
            print("Local database not available for CWE import")
            return False
            
        try:
            print("Downloading CWE data from MITRE...")
            download_start = time.time()
            url = "https://cwe.mitre.org/data/csv/1000.csv.zip"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'application/zip, */*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive'
            }
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            download_duration = time.time() - download_start
            
            print(f"Extracting and parsing CWE data... (download took {format_duration(download_duration)})")
            parsing_start = time.time()
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
                # Look for CSV files in the ZIP (should be 1000.csv for the full dataset)
                csv_files = [f for f in zip_file.namelist() if f.endswith('.csv')]
                if csv_files:
                    csv_filename = csv_files[0]  # Use the first CSV file found
                    print(f"Found CSV file: {csv_filename}")
                    csv_content = zip_file.read(csv_filename).decode('utf-8')
                    csv_reader = csv.DictReader(io.StringIO(csv_content))
                    
                    # Convert to list to get count for progress bar
                    rows = list(csv_reader)
                    print(f"Processing {len(rows)} CWE entries...")
                    
                    imported_count = 0
                    with tqdm(total=len(rows), desc="Importing CWE entries", unit="CWE") as pbar:
                        for row in rows:
                            if row.get('CWE-ID') and row.get('Name'):
                                if self.db.store_cwe(row):
                                    imported_count += 1
                            pbar.update(1)
                    
                    parsing_duration = time.time() - parsing_start
                    total_duration = time.time() - start_time
                    
                    print(f"Successfully imported {imported_count} CWE entries")
                    print(f"=== CWE Update Summary ===")
                    print(f"Download time: {format_duration(download_duration)}")
                    print(f"Processing time: {format_duration(parsing_duration)}")
                    print(f"Total time: {format_duration(total_duration)}")
                    return True
                else:
                    print(f"No CSV files found in ZIP archive")
                    print(f"Available files: {zip_file.namelist()}")
                    return False
                    
        except Exception as e:
            print(f"Error downloading/importing CWE data: {e}")
            return False
    
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
        
        # Try database first if available
        if self.use_local_db and self.db:
            cwe_data = self.db.get_cwe(cwe_key)
            if cwe_data:
                return cwe_data
        
        # Fallback to built-in mappings
        description = self.fallback_mappings.get(cwe_key)
        if description:
            return {
                'cwe_id': cwe_key,
                'name': description,
                'source': 'fallback mapping'
            }
        
        # Return unknown CWE info
        return {
            'cwe_id': cwe_key,
            'name': f'Unknown CWE (not in database or fallback mapping)',
            'source': 'unknown'
        }


def get_cve_info(cve_id: str, api_key: Optional[str] = None, use_local_db: bool = True, force_api: bool = False, include_cwe_details: bool = False) -> Optional[Dict]:
    """
    Get CVE information (module function)
    
    Args:
        cve_id: CVE identifier
        api_key: NVD API key (optional)
        use_local_db: Whether to use local database
        force_api: Force API call even if local data exists
        include_cwe_details: Whether to include detailed CWE information
        
    Returns:
        Dictionary containing CVE information or None if not found
    """
    client = NVDClient(api_key=api_key, use_local_db=use_local_db)
    cve_data = client.get_cve_info(cve_id, force_api=force_api)
    
    if cve_data and include_cwe_details:
        cve_data = enrich_cve_with_cwe_details(cve_data, include_cwe_details)
    
    return cve_data


def enrich_cve_with_cwe_details(cve_data: Dict, include_cwe_details: bool = True) -> Dict:
    """
    Enrich CVE data with detailed CWE information
    
    Args:
        cve_data: CVE data dictionary
        include_cwe_details: Whether to include detailed CWE information
        
    Returns:
        Enhanced CVE data with CWE details
    """
    if not include_cwe_details or not cve_data.get('cwe_ids'):
        return cve_data
    
    cwe_client = CWEClient()
    cwe_details = []
    
    for cwe_id in cve_data.get('cwe_ids', []):
        cwe_info = cwe_client.get_cwe_info(cwe_id)
        if cwe_info:
            cwe_details.append({
                'cwe_id': cwe_info['cwe_id'],
                'name': cwe_info['name'],
                'weakness_abstraction': cwe_info.get('weakness_abstraction'),
                'status': cwe_info.get('status'),
                'source': cwe_info.get('source')
            })
        else:
            # Fallback for unknown CWEs
            cwe_details.append({
                'cwe_id': cwe_id,
                'name': 'Unknown CWE',
                'source': 'unknown'
            })
    
    # Add enriched CWE details while preserving original cwe_ids
    # Filter out any None values to prevent errors
    cwe_details = [cwe for cwe in cwe_details if cwe is not None]
    
    enhanced_cve_data = cve_data.copy()
    enhanced_cve_data['cwe_details'] = cwe_details
    return enhanced_cve_data


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


def get_cvss_vector(cve_id: str, version: str = 'v3', **kwargs) -> Optional[str]:
    """
    Get CVSS vector string for a CVE
    
    Args:
        cve_id: CVE identifier
        version: CVSS version ('v2' or 'v3')
        **kwargs: Additional arguments passed to get_cve_info
        
    Returns:
        CVSS vector string or None if not found
    """
    cve_data = get_cve_info(cve_id, **kwargs)
    if not cve_data:
        return None
    
    if version.lower() == 'v2':
        return cve_data.get('cvss_v2_vector')
    else:
        return cve_data.get('cvss_v3_vector')


def get_cvss_details(cve_id: str, version: str = 'v3', **kwargs) -> Optional[Dict]:
    """
    Get detailed CVSS components for a CVE
    
    Args:
        cve_id: CVE identifier
        version: CVSS version ('v2' or 'v3')
        **kwargs: Additional arguments passed to get_cve_info
        
    Returns:
        Dictionary containing detailed CVSS components or None if not found
    """
    cve_data = get_cve_info(cve_id, **kwargs)
    if not cve_data:
        return None
    
    if version.lower() == 'v2':
        return cve_data.get('cvss_v2_details')
    else:
        return cve_data.get('cvss_v3_details')


def parse_cvss_vector(vector_string: str) -> Optional[Dict]:
    """
    Parse a CVSS vector string into its components
    
    Args:
        vector_string: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
        
    Returns:
        Dictionary with parsed components or None if invalid
    """
    if not vector_string:
        return None
    
    try:
        # Remove the CVSS version prefix
        if vector_string.startswith('CVSS:'):
            parts = vector_string.split('/', 1)
            if len(parts) > 1:
                version = parts[0].replace('CVSS:', '')
                vector_parts = parts[1].split('/')
            else:
                return None
        else:
            vector_parts = vector_string.split('/')
            version = 'unknown'
        
        components = {'version': version}
        
        # CVSS v3.x mappings
        v3_mappings = {
            'AV': 'attackVector',
            'AC': 'attackComplexity', 
            'PR': 'privilegesRequired',
            'UI': 'userInteraction',
            'S': 'scope',
            'C': 'confidentialityImpact',
            'I': 'integrityImpact',
            'A': 'availabilityImpact'
        }
        
        # CVSS v2 mappings
        v2_mappings = {
            'AV': 'accessVector',
            'AC': 'accessComplexity',
            'Au': 'authentication',
            'C': 'confidentialityImpact',
            'I': 'integrityImpact',
            'A': 'availabilityImpact'
        }
        
        # Value mappings for human-readable output
        value_mappings = {
            # Attack/Access Vector
            'N': 'NETWORK',
            'A': 'ADJACENT_NETWORK',
            'L': 'LOCAL',
            'P': 'PHYSICAL',
            # Attack/Access Complexity
            'L': 'LOW',
            'H': 'HIGH',
            # Privileges Required / Authentication
            'N': 'NONE',
            'L': 'LOW',
            'H': 'HIGH',
            'S': 'SINGLE',
            'M': 'MULTIPLE',
            # User Interaction
            'N': 'NONE',
            'R': 'REQUIRED',
            # Scope
            'U': 'UNCHANGED',
            'C': 'CHANGED',
            # Impact levels
            'N': 'NONE',
            'L': 'LOW',
            'H': 'HIGH'
        }
        
        # Determine which mapping to use based on version
        if version.startswith('3'):
            metric_mappings = v3_mappings
        else:
            metric_mappings = v2_mappings
        
        for part in vector_parts:
            if ':' in part:
                key, value = part.split(':', 1)
                metric_name = metric_mappings.get(key, key)
                readable_value = value_mappings.get(value, value)
                components[metric_name] = readable_value
        
        return components
        
    except Exception:
        return None


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.1f}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = seconds % 60
        return f"{hours}h {minutes}m {secs:.1f}s"


def analyze_cvss_risk(cve_id: str, version: str = 'v3', **kwargs) -> Optional[Dict]:
    """
    Analyze CVSS risk factors for a CVE
    
    Args:
        cve_id: CVE identifier
        version: CVSS version ('v2' or 'v3')
        **kwargs: Additional arguments passed to get_cve_info
        
    Returns:
        Dictionary with risk analysis or None if not found
    """
    cvss_details = get_cvss_details(cve_id, version, **kwargs)
    if not cvss_details:
        return None
    
    risk_factors = {
        'cve_id': cve_id,
        'cvss_version': version,
        'base_score': cvss_details.get('baseScore'),
        'severity': cvss_details.get('baseSeverity'),
        'risk_factors': []
    }
    
    if version.lower() == 'v3':
        # Analyze v3 risk factors
        if cvss_details.get('attackVector') == 'NETWORK':
            risk_factors['risk_factors'].append('Network accessible')
        
        if cvss_details.get('attackComplexity') == 'LOW':
            risk_factors['risk_factors'].append('Low attack complexity')
            
        if cvss_details.get('privilegesRequired') == 'NONE':
            risk_factors['risk_factors'].append('No privileges required')
            
        if cvss_details.get('userInteraction') == 'NONE':
            risk_factors['risk_factors'].append('No user interaction required')
            
        if cvss_details.get('scope') == 'CHANGED':
            risk_factors['risk_factors'].append('Scope changed (privilege escalation)')
            
        # Check impact levels
        high_impacts = []
        for impact_type in ['confidentialityImpact', 'integrityImpact', 'availabilityImpact']:
            if cvss_details.get(impact_type) == 'HIGH':
                impact_name = impact_type.replace('Impact', '').capitalize()
                high_impacts.append(impact_name)
        
        if high_impacts:
            risk_factors['risk_factors'].append(f'High impact on: {", ".join(high_impacts)}')
    
    else:
        # Analyze v2 risk factors
        if cvss_details.get('accessVector') == 'NETWORK':
            risk_factors['risk_factors'].append('Network accessible')
            
        if cvss_details.get('accessComplexity') == 'LOW':
            risk_factors['risk_factors'].append('Low access complexity')
            
        if cvss_details.get('authentication') == 'NONE':
            risk_factors['risk_factors'].append('No authentication required')
            
        # Check impact levels
        high_impacts = []
        for impact_type in ['confidentialityImpact', 'integrityImpact', 'availabilityImpact']:
            if cvss_details.get(impact_type) == 'COMPLETE':
                impact_name = impact_type.replace('Impact', '').capitalize()
                high_impacts.append(impact_name)
        
        if high_impacts:
            risk_factors['risk_factors'].append(f'Complete impact on: {", ".join(high_impacts)}')
    
    return risk_factors


def update_database(years: Optional[List[int]] = None, include_modified: bool = True):
    """
    Update local database from NVD feeds
    
    Args:
        years: List of years to download (default: all years from 2002 to current year)
        include_modified: Whether to include modified and recent feeds
    """
    feed_manager = NVDFeedManager(use_local_db=True)
    feed_manager.update_database_from_feeds(years=years, include_modified=include_modified)


def update_cwe_database() -> bool:
    """
    Update the local database with the latest CWE data from MITRE (module function)
    
    Returns:
        True if successful, False otherwise
    """
    client = CWEClient()
    return client.download_and_import_cwe_data()


def print_cve_info(cve_data: Dict):
    """Pretty print CVE information"""
    print(f"\n=== {cve_data['id']} ===")
    print(f"Published: {cve_data.get('published', 'N/A')}")
    print(f"Last Modified: {cve_data.get('lastModified', 'N/A')}")
    print(f"Status: {cve_data.get('vulnStatus', 'N/A')}")
    
    if cve_data.get('cvss_v3_score'):
        print(f"CVSS v3 Score: {cve_data['cvss_v3_score']} ({cve_data.get('cvss_v3_severity', 'N/A')})")
        if cve_data.get('cvss_v3_vector'):
            print(f"CVSS v3 Vector: {cve_data['cvss_v3_vector']}")
    
    if cve_data.get('cvss_v2_score'):
        print(f"CVSS v2 Score: {cve_data['cvss_v2_score']} ({cve_data.get('cvss_v2_severity', 'N/A')})")
        if cve_data.get('cvss_v2_vector'):
            print(f"CVSS v2 Vector: {cve_data['cvss_v2_vector']}")
    
    print(f"Vendor: {cve_data.get('vendor_name', 'N/A')}")
    print(f"Product: {cve_data.get('product_name', 'N/A')}")
    
    if cve_data.get('cwe_details'):
        # Show detailed CWE information
        print(f"CWE Information:")
        for cwe in cve_data['cwe_details']:
            print(f"  {cwe['cwe_id']}: {cwe['name']}")
    elif cve_data.get('cwe_ids'):
        # Fallback to just CWE IDs if no detailed info
        print(f"CWE IDs: {', '.join(cve_data['cwe_ids'])}")
    
    print(f"\nDescription:")
    print(f"{cve_data.get('description', 'N/A')}")
    
    if cve_data.get('references'):
        print(f"\nReferences:")
        for ref in cve_data['references'][:5]:  # Show first 5 references
            print(f"  - {ref['url']}")


def print_cvss_details(cve_id: str, version: str = 'v3', **kwargs):
    """Pretty print detailed CVSS information"""
    cvss_details = get_cvss_details(cve_id, version, **kwargs)
    vector = get_cvss_vector(cve_id, version, **kwargs)
    
    if not cvss_details:
        print(f"No CVSS {version.upper()} details found for {cve_id}")
        return
    
    print(f"\n=== CVSS {version.upper()} Details for {cve_id} ===")
    print(f"Vector String: {vector or 'N/A'}")
    print(f"Base Score: {cvss_details.get('baseScore', 'N/A')}")
    print(f"Severity: {cvss_details.get('baseSeverity', 'N/A')}")
    
    if version.lower() == 'v3':
        print(f"\nAttack Vector: {cvss_details.get('attackVector', 'N/A')}")
        print(f"Attack Complexity: {cvss_details.get('attackComplexity', 'N/A')}")
        print(f"Privileges Required: {cvss_details.get('privilegesRequired', 'N/A')}")
        print(f"User Interaction: {cvss_details.get('userInteraction', 'N/A')}")
        print(f"Scope: {cvss_details.get('scope', 'N/A')}")
        print(f"Confidentiality Impact: {cvss_details.get('confidentialityImpact', 'N/A')}")
        print(f"Integrity Impact: {cvss_details.get('integrityImpact', 'N/A')}")
        print(f"Availability Impact: {cvss_details.get('availabilityImpact', 'N/A')}")
    else:
        print(f"\nAccess Vector: {cvss_details.get('accessVector', 'N/A')}")
        print(f"Access Complexity: {cvss_details.get('accessComplexity', 'N/A')}")
        print(f"Authentication: {cvss_details.get('authentication', 'N/A')}")
        print(f"Confidentiality Impact: {cvss_details.get('confidentialityImpact', 'N/A')}")
        print(f"Integrity Impact: {cvss_details.get('integrityImpact', 'N/A')}")
        print(f"Availability Impact: {cvss_details.get('availabilityImpact', 'N/A')}")
    
    if cvss_details.get('exploitabilityScore'):
        print(f"Exploitability Score: {cvss_details['exploitabilityScore']}")
    if cvss_details.get('impactScore'):
        print(f"Impact Score: {cvss_details['impactScore']}")


def print_cvss_risk_analysis(cve_id: str, version: str = 'v3', **kwargs):
    """Pretty print CVSS risk analysis"""
    risk_analysis = analyze_cvss_risk(cve_id, version, **kwargs)
    
    if not risk_analysis:
        print(f"No CVSS {version.upper()} risk analysis available for {cve_id}")
        return
    
    print(f"\n=== CVSS {version.upper()} Risk Analysis for {cve_id} ===")
    print(f"Base Score: {risk_analysis.get('base_score', 'N/A')}")
    print(f"Severity: {risk_analysis.get('severity', 'N/A')}")
    
    if risk_analysis.get('risk_factors'):
        print(f"\nKey Risk Factors:")
        for factor in risk_analysis['risk_factors']:
            print(f"  • {factor}")
    else:
        print(f"\nNo significant risk factors identified.")


def print_cwe_info(cwe_data: Dict):
    """Pretty print CWE information"""
    print(f"\n=== {cwe_data['cwe_id']} ===")
    print(f"Name: {cwe_data['name']}")
    
    if cwe_data.get('weakness_abstraction'):
        print(f"Weakness Abstraction: {cwe_data['weakness_abstraction']}")
    
    if cwe_data.get('status'):
        print(f"Status: {cwe_data['status']}")
    
    if cwe_data.get('description'):
        print(f"\nDescription:")
        print(f"{cwe_data['description']}")
    
    if cwe_data.get('extended_description'):
        print(f"\nExtended Description:")
        print(f"{cwe_data['extended_description']}")
    
    print(f"\nSource: {cwe_data['source']}")


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
    parser.add_argument('--update-cwe', action='store_true', help='Update local database with latest CWE data from MITRE')
    parser.add_argument('--years', type=int, nargs='+', help='Years to download (default: all years from 2002 to current year)')
    parser.add_argument('--no-modified', action='store_true', help='Skip modified and recent feeds when updating')
    
    # API options
    parser.add_argument('--api-key', type=str, help='NVD API key for higher rate limits')
    parser.add_argument('--no-local-db', action='store_true', help='Disable local database storage')
    parser.add_argument('--force-api', action='store_true', help='Force API call even if local data exists')
    
    # Output options
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--cvss-only', action='store_true', help='Output only CVSS score')
    parser.add_argument('--cvss-details', action='store_true', help='Show detailed CVSS vector components')
    parser.add_argument('--cvss-risk', action='store_true', help='Show CVSS risk analysis')
    
    args = parser.parse_args()
    
    if args.update_db:
        print("Updating local database from NVD feeds...")
        update_database(
            years=args.years, 
            include_modified=not args.no_modified
        )
        return
    
    if args.update_cwe:
        print("Updating local database with latest CWE data...")
        success = update_cwe_database()
        if success:
            db = CVEDatabase()
            count = db.get_cwe_count()
            print(f"CWE database update completed. Total CWE entries: {count}")
        else:
            print("CWE database update failed.")
            sys.exit(1)
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
                force_api=args.force_api,
                include_cwe_details=True  # Enable CWE details by default for CLI
            )
            
            if not cve_data:
                print(f"No data found for {args.cve}")
                sys.exit(1)
            
            if args.cvss_only:
                cvss_score = cve_data.get('cvss_v3_score') or cve_data.get('cvss_v2_score')
                print(cvss_score if cvss_score else 'N/A')
            elif args.cvss_details:
                # Show detailed CVSS components
                if cve_data.get('cvss_v3_score'):
                    print_cvss_details(args.cve, 'v3', api_key=args.api_key, 
                                     use_local_db=not args.no_local_db, force_api=args.force_api)
                if cve_data.get('cvss_v2_score'):
                    print_cvss_details(args.cve, 'v2', api_key=args.api_key,
                                     use_local_db=not args.no_local_db, force_api=args.force_api)
            elif args.cvss_risk:
                # Show CVSS risk analysis
                if cve_data.get('cvss_v3_score'):
                    print_cvss_risk_analysis(args.cve, 'v3', api_key=args.api_key,
                                           use_local_db=not args.no_local_db, force_api=args.force_api)
                if cve_data.get('cvss_v2_score'):
                    print_cvss_risk_analysis(args.cve, 'v2', api_key=args.api_key,
                                           use_local_db=not args.no_local_db, force_api=args.force_api)
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
