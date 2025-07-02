#!/usr/bin/env python3
"""
SeeVee API Client Example
Demonstrates how to use the SeeVee API service for CVE and CWE lookups
"""

import requests
import json
from typing import List, Dict, Any


class SeeVeeAPIClient:
    """Simple client for SeeVee API"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
    
    def health_check(self) -> Dict[str, Any]:
        """Check API health"""
        response = self.session.get(f"{self.base_url}/health")
        response.raise_for_status()
        return response.json()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        response = self.session.get(f"{self.base_url}/stats")
        response.raise_for_status()
        return response.json()
    
    def lookup_cve(self, cve_id: str, include_cvss_details: bool = False, 
                   include_risk_analysis: bool = False, include_references: bool = True) -> Dict[str, Any]:
        """Lookup a single CVE"""
        params = {
            'include_cvss_details': include_cvss_details,
            'include_risk_analysis': include_risk_analysis,
            'include_references': include_references
        }
        response = self.session.get(f"{self.base_url}/cve/{cve_id}", params=params)
        response.raise_for_status()
        return response.json()
    
    def batch_lookup_cve(self, cve_ids: List[str], include_cvss_details: bool = False,
                         include_risk_analysis: bool = False, include_references: bool = True) -> Dict[str, Any]:
        """Batch lookup multiple CVEs"""
        payload = {
            "cve_ids": cve_ids,
            "include_cvss_details": include_cvss_details,
            "include_risk_analysis": include_risk_analysis,
            "include_references": include_references
        }
        response = self.session.post(f"{self.base_url}/cve/batch", json=payload)
        response.raise_for_status()
        return response.json()
    
    def lookup_cwe(self, cwe_id: str) -> Dict[str, Any]:
        """Lookup a single CWE"""
        response = self.session.get(f"{self.base_url}/cwe/{cwe_id}")
        response.raise_for_status()
        return response.json()
    
    def batch_lookup_cwe(self, cwe_ids: List[str]) -> Dict[str, Any]:
        """Batch lookup multiple CWEs"""
        payload = {"cwe_ids": cwe_ids}
        response = self.session.post(f"{self.base_url}/cwe/batch", json=payload)
        response.raise_for_status()
        return response.json()
    
    def trigger_update(self, years: List[int] = None, include_modified: bool = True, update_cwe: bool = True) -> Dict[str, Any]:
        """Trigger database update"""
        params = {
            'include_modified': include_modified,
            'update_cwe': update_cwe
        }
        if years:
            params['years'] = years
        
        response = self.session.post(f"{self.base_url}/update", params=params)
        response.raise_for_status()
        return response.json()


def main():
    """Example usage of the SeeVee API"""
    
    # Initialize client
    client = SeeVeeAPIClient()
    
    try:
        # Check API health
        print("🔍 Checking API health...")
        health = client.health_check()
        print(f"✅ API Status: {health['status']}")
        print(f"⏰ Uptime: {health.get('uptime', 'Unknown')}")
        
        # Get database statistics
        print("\n📊 Database Statistics:")
        stats = client.get_stats()
        print(f"   CVE Count: {stats['cve_count']:,}")
        print(f"   CWE Count: {stats['cwe_count']:,}")
        print(f"   Database Size: {stats['database_size_mb']:.1f} MB")
        print(f"   Last Updated: {stats.get('last_updated', 'Unknown')}")
        
        # Single CVE lookup
        print("\n🔍 Single CVE Lookup (Log4Shell):")
        cve_result = client.lookup_cve("CVE-2021-44228", include_risk_analysis=True)
        if cve_result['found']:
            data = cve_result['data']
            print(f"   CVE: {data['id']}")
            print(f"   CVSS v3: {data.get('cvss_v3_score', 'N/A')} ({data.get('cvss_v3_severity', 'N/A')})")
            print(f"   Description: {data.get('description', 'N/A')[:100]}...")
            
            if cve_result.get('risk_analysis', {}).get('v3'):
                risk_factors = cve_result['risk_analysis']['v3'].get('risk_factors', [])
                if risk_factors:
                    print(f"   Risk Factors: {len(risk_factors)} identified")
                    for factor in risk_factors[:3]:  # Show first 3
                        print(f"     • {factor}")
        
        # Batch CVE lookup
        print("\n📋 Batch CVE Lookup (High-profile vulnerabilities):")
        batch_cves = ["CVE-2021-44228", "CVE-2022-22965", "CVE-2014-0160", "CVE-2017-5638"]
        batch_result = client.batch_lookup_cve(batch_cves, include_cvss_details=True)
        
        print(f"   Processing Time: {batch_result['processing_time']:.3f}s")
        print(f"   Success Rate: {batch_result['summary']['success_rate']}")
        
        for result in batch_result['results']:
            if result['found']:
                data = result['data']
                cvss_score = data.get('cvss_v3_score') or data.get('cvss_v2_score', 'N/A')
                print(f"   {result['cve_id']}: {cvss_score}")
        
        # CWE lookup
        print("\n🛡️ CWE Lookup:")
        cwe_result = client.lookup_cwe("CWE-79")
        if cwe_result['found']:
            data = cwe_result['data']
            print(f"   {data['cwe_id']}: {data['name']}")
            if data.get('weakness_abstraction'):
                print(f"   Abstraction: {data['weakness_abstraction']}")
        
        # Batch CWE lookup
        print("\n📚 Batch CWE Lookup:")
        batch_cwes = ["CWE-79", "CWE-89", "CWE-502", "CWE-787"]
        cwe_batch_result = client.batch_lookup_cwe(batch_cwes)
        
        for result in cwe_batch_result['results']:
            if result['found']:
                data = result['data']
                print(f"   {data['cwe_id']}: {data['name'][:50]}...")
        
        print(f"\n✅ All examples completed successfully!")
        
    except requests.exceptions.ConnectionError:
        print("❌ Error: Cannot connect to SeeVee API. Make sure the service is running on http://localhost:8000")
        print("   Start with: docker-compose up -d")
    except requests.exceptions.HTTPError as e:
        print(f"❌ HTTP Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


if __name__ == "__main__":
    main() 