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


def display_cve_with_cwe_details(cve_result: Dict[str, Any], show_description: bool = True):
    """Helper function to display CVE results with enhanced CWE details"""
    if not cve_result['found']:
        print(f"   ❌ {cve_result['cve_id']}: {cve_result.get('error', 'Not found')}")
        return
    
    data = cve_result['data']
    print(f"   ✅ {data['id']}")
    
    # Basic CVE info
    cvss_score = data.get('cvss_v3_score') or data.get('cvss_v2_score', 'N/A')
    cvss_severity = data.get('cvss_v3_severity') or data.get('cvss_v2_severity', 'N/A')
    print(f"      CVSS: {cvss_score} ({cvss_severity})")
    
    if show_description:
        description = data.get('description', 'N/A')
        print(f"      Description: {description[:100]}...")
    
    # Enhanced CWE details
    if data.get('cwe_details'):
        print(f"      🛡️  CWE Details (Enhanced):")
        for cwe_info in data['cwe_details']:
            cwe_id = cwe_info.get('cwe_id', 'Unknown')
            cwe_name = cwe_info.get('name', 'Unknown')
            print(f"        • {cwe_id}: {cwe_name}")
            if cwe_info.get('weakness_abstraction'):
                print(f"          Abstraction: {cwe_info['weakness_abstraction']}")
            if cwe_info.get('status'):
                print(f"          Status: {cwe_info['status']}")
    elif data.get('cwe_ids'):
        print(f"      🛡️  CWE IDs: {', '.join(data['cwe_ids'])}")
    else:
        print(f"      🛡️  No CWE mappings available")
    
    # Risk analysis if available
    if cve_result.get('risk_analysis', {}).get('v3'):
        risk_factors = cve_result['risk_analysis']['v3'].get('risk_factors', [])
        if risk_factors:
            print(f"      ⚠️   Risk Factors: {len(risk_factors)} identified")
            for factor in risk_factors[:2]:  # Show first 2
                print(f"        • {factor}")


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
        
        # Single CVE lookup with enhanced CWE details
        print("\n🔍 Single CVE Lookup with CWE Details (Log4Shell):")
        cve_result = client.lookup_cve("CVE-2021-44228", include_risk_analysis=True)
        display_cve_with_cwe_details(cve_result)
        
        # Demonstrate CWE integration showcase
        print("\n🛡️  CWE Integration Showcase:")
        showcase_cves = ["CVE-2021-44228", "CVE-2022-22965", "CVE-2014-0160", "CVE-2017-5638"]
        print("   Demonstrating enhanced CWE details in CVE responses...")
        
        for cve_id in showcase_cves:
            cve_result = client.lookup_cve(cve_id)
            if cve_result['found']:
                data = cve_result['data']
                cwe_count = len(data.get('cwe_details', {}))
                basic_cwe_count = len(data.get('cwe_ids', []))
                print(f"   {cve_id}: {cwe_count} enhanced CWE details, {basic_cwe_count} basic CWE IDs")
        
        # Batch CVE lookup
        print("\n📋 Batch CVE Lookup (High-profile vulnerabilities):")
        batch_cves = ["CVE-2021-44228", "CVE-2022-22965", "CVE-2014-0160", "CVE-2017-5638"]
        batch_result = client.batch_lookup_cve(batch_cves, include_cvss_details=True)
        
        print(f"   Processing Time: {batch_result['processing_time']:.3f}s")
        print(f"   Success Rate: {batch_result['summary']['success_rate']}")
        print(f"   Performance: ~{len(batch_cves) / batch_result['processing_time']:.0f} CVEs/second")
        
        print("\n   Detailed Results with CWE Information:")
        for result in batch_result['results']:
            display_cve_with_cwe_details(result, show_description=False)
        
        # CWE-focused analysis
        print("\n🔬 CWE Analysis Examples:")
        
        # Extract CWE IDs from our CVE results
        all_cwe_ids = set()
        for result in batch_result['results']:
            if result['found'] and result['data'].get('cwe_details'):
                for cwe_info in result['data']['cwe_details']:
                    cwe_id = cwe_info.get('cwe_id')
                    if cwe_id:
                        all_cwe_ids.add(cwe_id)
        
        if all_cwe_ids:
            print(f"   Found {len(all_cwe_ids)} unique CWE types across vulnerabilities")
            
            # Lookup detailed CWE information
            cwe_batch_result = client.batch_lookup_cwe(list(all_cwe_ids)[:5])  # Limit to first 5
            
            print("   Detailed CWE Information:")
            for cwe_result in cwe_batch_result['results']:
                if cwe_result['found']:
                    data = cwe_result['data']
                    print(f"   {data['cwe_id']}: {data['name']}")
                    if data.get('weakness_abstraction'):
                        print(f"      Abstraction: {data['weakness_abstraction']}")
                    if data.get('status'):
                        print(f"      Status: {data['status']}")
        
        # Advanced analysis example
        print("\n📈 Advanced CVE + CWE Analysis:")
        analysis_cve = "CVE-2021-44228"  # Log4Shell
        
        # Get full details
        full_result = client.lookup_cve(analysis_cve, 
                                       include_cvss_details=True, 
                                       include_risk_analysis=True)
        
        if full_result['found']:
            data = full_result['data']
            print(f"   Analyzing {analysis_cve} (Log4Shell):")
            
            # CVSS Analysis
            if full_result.get('cvss_details', {}).get('v3'):
                cvss_v3 = full_result['cvss_details']['v3']
                print(f"   📊 CVSS v3 Analysis:")
                print(f"      Base Score: {cvss_v3.get('baseScore')} ({cvss_v3.get('baseSeverity')})")
                print(f"      Attack Vector: {cvss_v3.get('attackVector')}")
                print(f"      Attack Complexity: {cvss_v3.get('attackComplexity')}")
            
            # CWE Analysis
            if data.get('cwe_details'):
                print(f"   🛡️  CWE Analysis:")
                for cwe_info in data['cwe_details']:
                    cwe_id = cwe_info.get('cwe_id', 'Unknown')
                    cwe_name = cwe_info.get('name', 'Unknown')
                    print(f"      {cwe_id}: {cwe_name}")
                    if cwe_info.get('description'):
                        print(f"        {cwe_info['description'][:100]}...")
            
            # Risk Factors
            if full_result.get('risk_analysis', {}).get('v3', {}).get('risk_factors'):
                risk_factors = full_result['risk_analysis']['v3']['risk_factors']
                print(f"   ⚠️   Key Risk Factors ({len(risk_factors)}):")
                for factor in risk_factors[:3]:
                    print(f"      • {factor}")
        
        print(f"\n✅ All examples completed successfully!")
        print(f"\n💡 Key Enhancements Demonstrated:")
        print(f"   • CVE responses now include detailed CWE information")
        print(f"   • Enhanced CWE details: name, abstraction, status, description")
        print(f"   • Integrated CVE + CWE analysis for comprehensive security assessment")
        print(f"   • High-performance batch processing with CWE enrichment")
        
    except requests.exceptions.ConnectionError:
        print("❌ Error: Cannot connect to SeeVee API. Make sure the service is running on http://localhost:8000")
        print("   Start with: docker-compose up -d")
    except requests.exceptions.HTTPError as e:
        print(f"❌ HTTP Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


if __name__ == "__main__":
    main() 