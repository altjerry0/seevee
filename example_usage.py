#!/usr/bin/env python3
"""
Example: Using SeeVee for Security Assessment

This script demonstrates how to use SeeVee programmatically to assess
multiple vulnerabilities and generate a security report.
"""

from seevee import get_cve_info, get_cwe_info, get_cvss_score, get_cvss_vector, get_cvss_details, analyze_cvss_risk, parse_cvss_vector

def assess_vulnerability_severity(cvss_score):
    """Categorize vulnerability severity based on CVSS score"""
    if not cvss_score:
        return "UNKNOWN", "gray"
    
    if cvss_score >= 9.0:
        return "CRITICAL", "red"
    elif cvss_score >= 7.0:
        return "HIGH", "orange"
    elif cvss_score >= 4.0:
        return "MEDIUM", "yellow"
    else:
        return "LOW", "green"

def generate_vulnerability_report(cve_list):
    """Generate a detailed vulnerability report"""
    print("=" * 80)
    print("                    VULNERABILITY ASSESSMENT REPORT")
    print("=" * 80)
    
    vulnerabilities = []
    
    for cve_id in cve_list:
        print(f"\nProcessing {cve_id}...")
        
        # Get CVE information with CWE details
        cve_data = get_cve_info(cve_id, include_cwe_details=True)
        
        if not cve_data:
            print(f"  ❌ Could not retrieve data for {cve_id}")
            continue
        
        # Extract key information
        cvss_score = cve_data.get('cvss_v3_score') or cve_data.get('cvss_v2_score')
        severity, color = assess_vulnerability_severity(cvss_score)
        
        vulnerability = {
            'cve_id': cve_id,
            'cvss_score': cvss_score,
            'severity': severity,
            'description': cve_data.get('description', 'N/A')[:100] + '...',
            'cwe_ids': cve_data.get('cwe_ids', []),
            'cwe_details': cve_data.get('cwe_details', []),
            'published': cve_data.get('published', 'N/A'),
            'vendor': cve_data.get('vendor_name', 'N/A'),
            'product': cve_data.get('product_name', 'N/A')
        }
        
        vulnerabilities.append(vulnerability)
    
    # Sort by CVSS score (highest first)
    vulnerabilities.sort(key=lambda x: x['cvss_score'] or 0, reverse=True)
    
    # Generate summary
    print("\n" + "=" * 80)
    print("                           EXECUTIVE SUMMARY")
    print("=" * 80)
    
    severity_counts = {}
    for vuln in vulnerabilities:
        severity = vuln['severity']
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print(f"Total Vulnerabilities Assessed: {len(vulnerabilities)}")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            print(f"  {severity}: {count}")
    
    # Detailed findings
    print("\n" + "=" * 80)
    print("                          DETAILED FINDINGS")
    print("=" * 80)
    
    for vuln in vulnerabilities:
        print(f"\n[{vuln['severity']}] {vuln['cve_id']}")
        print(f"  CVSS Score: {vuln['cvss_score'] or 'N/A'}")
        print(f"  Published: {vuln['published']}")
        print(f"  Vendor/Product: {vuln['vendor']} / {vuln['product']}")
        
        # Enhanced CWE details display
        if vuln['cwe_details']:
            print(f"  CWE Types (Enhanced):")
            for cwe_data in vuln['cwe_details']:
                cwe_id = cwe_data.get('cwe_id', 'Unknown')
                cwe_name = cwe_data.get('name', 'Unknown')
                print(f"    • {cwe_id}: {cwe_name}")
                if cwe_data.get('weakness_abstraction'):
                    print(f"      Abstraction: {cwe_data['weakness_abstraction']}")
                if cwe_data.get('status'):
                    print(f"      Status: {cwe_data['status']}")
        elif vuln['cwe_ids']:
            print(f"  CWE Types (Basic):")
            for cwe_id in vuln['cwe_ids'][:3]:  # Show first 3 CWEs
                cwe_info = get_cwe_info(cwe_id)
                if cwe_info:
                    print(f"    • {cwe_id}: {cwe_info['name']}")
        
        print(f"  Description: {vuln['description']}")
    
    # CWE Analysis Section
    print("\n" + "=" * 80)
    print("                        CWE WEAKNESS ANALYSIS")
    print("=" * 80)
    
    all_cwe_details = {}
    for vuln in vulnerabilities:
        for cwe_data in vuln.get('cwe_details', []):
            cwe_id = cwe_data.get('cwe_id', 'Unknown')
            if cwe_id not in all_cwe_details:
                all_cwe_details[cwe_id] = {
                    'data': cwe_data,
                    'affected_cves': []
                }
            all_cwe_details[cwe_id]['affected_cves'].append(vuln['cve_id'])
    
    if all_cwe_details:
        print("Common Weakness Patterns Found:")
        for cwe_id, info in sorted(all_cwe_details.items(), key=lambda x: len(x[1]['affected_cves']), reverse=True):
            cwe_data = info['data']
            affected_cves = info['affected_cves']
            print(f"\n  {cwe_id}: {cwe_data.get('name', 'Unknown')}")
            print(f"    Affected CVEs: {', '.join(affected_cves)}")
            if cwe_data.get('weakness_abstraction'):
                print(f"    Abstraction: {cwe_data['weakness_abstraction']}")
            if cwe_data.get('description'):
                print(f"    Description: {cwe_data['description'][:150]}...")
    
    # Recommendations
    print("\n" + "=" * 80)
    print("                           RECOMMENDATIONS")
    print("=" * 80)
    
    critical_high = [v for v in vulnerabilities if v['severity'] in ['CRITICAL', 'HIGH']]
    if critical_high:
        print("🚨 IMMEDIATE ACTION REQUIRED:")
        print("  - Prioritize patching for CRITICAL and HIGH severity vulnerabilities")
        print(f"  - {len(critical_high)} vulnerabilities require immediate attention")
    
    medium_vuln = [v for v in vulnerabilities if v['severity'] == 'MEDIUM']
    if medium_vuln:
        print("⚠️  SCHEDULED PATCHING:")
        print(f"  - Plan remediation for {len(medium_vuln)} MEDIUM severity vulnerabilities")
    
    if all_cwe_details:
        print("\n🛡️  SECURITY CONTROLS:")
        common_patterns = sorted(all_cwe_details.items(), key=lambda x: len(x[1]['affected_cves']), reverse=True)[:3]
        for cwe_id, info in common_patterns:
            cwe_name = info['data'].get('name', 'Unknown')
            print(f"  - Address {cwe_id} ({cwe_name}) - affects {len(info['affected_cves'])} CVEs")
    
    print("\n  - Monitor vendor security advisories for patches")
    print("  - Consider implementing additional security controls")
    print("  - Regular vulnerability assessments recommended")

def demonstrate_cwe_analysis():
    """Demonstrate CWE analysis capabilities"""
    print("\n" + "=" * 80)
    print("                        CWE ANALYSIS EXAMPLE")
    print("=" * 80)
    
    # Check CWE database status
    from seevee import CVEDatabase
    db = CVEDatabase()
    cwe_count = db.get_cwe_count()
    
    if cwe_count > 0:
        print(f"CWE Database Status: {cwe_count} entries available from MITRE")
    else:
        print("CWE Database Status: Not populated (run 'python seevee.py --update-cwe')")
    
    common_cwes = [79, 89, 22, 352, 502, 287, 200, 434]
    
    print("\nCommon Web Application Vulnerabilities:")
    for cwe_num in common_cwes:
        cwe_info = get_cwe_info(cwe_num)
        if cwe_info:
            print(f"  {cwe_info['cwe_id']}: {cwe_info['name']}")
            if cwe_info.get('weakness_abstraction'):
                print(f"    Abstraction: {cwe_info['weakness_abstraction']}")
            if cwe_info.get('status'):
                print(f"    Status: {cwe_info['status']}")
            print(f"    Source: {cwe_info['source']}")
            print()
    
    # Demonstrate detailed CWE lookup
    if cwe_count > 0:
        print("\nDetailed CWE Information Example (from database):")
        detailed_cwe = get_cwe_info("CWE-79")
        if detailed_cwe and detailed_cwe.get('description'):
            print(f"  CWE-79 Description: {detailed_cwe['description'][:200]}...")
            if detailed_cwe.get('extended_description'):
                print(f"  Extended: {detailed_cwe['extended_description'][:100]}...")
    
    print(f"\nNote: To access the complete MITRE CWE database with 399+ entries,")
    print("run: python seevee.py --update-cwe")


def demonstrate_cwe_integration():
    """Demonstrate enhanced CWE integration in CVE responses"""
    print("\n" + "=" * 80)
    print("                    CWE INTEGRATION DEMONSTRATION")
    print("=" * 80)
    
    # Example CVEs that have CWE mappings
    example_cves = [
        "CVE-2021-44228",  # Log4Shell - has CWE mappings
        "CVE-2022-22965",  # Spring4Shell - has CWE mappings  
        "CVE-2014-0160",   # Heartbleed - has CWE mappings
    ]
    
    print("Demonstrating CVE lookups with enhanced CWE details:")
    
    for cve_id in example_cves:
        print(f"\n📋 {cve_id}:")
        
        # Get CVE with CWE details
        cve_data = get_cve_info(cve_id, include_cwe_details=True)
        
        if not cve_data:
            print(f"  ❌ Could not retrieve data for {cve_id}")
            continue
        
        # Show basic info
        cvss_score = cve_data.get('cvss_v3_score') or cve_data.get('cvss_v2_score')
        print(f"  CVSS Score: {cvss_score}")
        print(f"  Description: {cve_data.get('description', 'N/A')[:100]}...")
        
        # Show CWE details
        if cve_data.get('cwe_details'):
            print(f"  🛡️  CWE Details (Enhanced):")
            for cwe_info in cve_data['cwe_details']:
                cwe_id = cwe_info.get('cwe_id', 'Unknown')
                cwe_name = cwe_info.get('name', 'Unknown')
                print(f"    • {cwe_id}: {cwe_name}")
                if cwe_info.get('weakness_abstraction'):
                    print(f"      Abstraction: {cwe_info['weakness_abstraction']}")
                if cwe_info.get('status'):
                    print(f"      Status: {cwe_info['status']}")
                if cwe_info.get('description'):
                    print(f"      Description: {cwe_info['description'][:100]}...")
        elif cve_data.get('cwe_ids'):
            print(f"  🛡️  CWE IDs (Basic): {', '.join(cve_data['cwe_ids'])}")
        else:
            print(f"  🛡️  No CWE mappings found")
    
    # Show comparison
    print(f"\n" + "-" * 60)
    print("CWE Integration Comparison:")
    print("• include_cwe_details=True: Full CWE database information")
    print("• include_cwe_details=False: Just CWE IDs (if available)")
    print("• Enhanced details include: name, abstraction, status, description")

def demonstrate_cvss_analysis():
    """Demonstrate detailed CVSS analysis capabilities"""
    print("\n" + "=" * 80)
    print("                       CVSS ANALYSIS EXAMPLE")
    print("=" * 80)
    
    # Analyze Log4Shell as an example
    cve_id = "CVE-2021-44228"
    print(f"Detailed CVSS Analysis for {cve_id} (Log4Shell):")
    
    # Get CVSS details
    cvss_details = get_cvss_details(cve_id)
    vector_string = get_cvss_vector(cve_id)
    
    if cvss_details and vector_string:
        print(f"\nCVSS Vector: {vector_string}")
        print(f"Base Score: {cvss_details.get('baseScore')} ({cvss_details.get('baseSeverity')})")
        
        # Show attack characteristics
        print(f"\nAttack Characteristics:")
        print(f"  Attack Vector: {cvss_details.get('attackVector')}")
        print(f"  Attack Complexity: {cvss_details.get('attackComplexity')}")
        print(f"  Privileges Required: {cvss_details.get('privilegesRequired')}")
        print(f"  User Interaction: {cvss_details.get('userInteraction')}")
        print(f"  Scope: {cvss_details.get('scope')}")
        
        # Show impact levels
        print(f"\nImpact Assessment:")
        print(f"  Confidentiality: {cvss_details.get('confidentialityImpact')}")
        print(f"  Integrity: {cvss_details.get('integrityImpact')}")
        print(f"  Availability: {cvss_details.get('availabilityImpact')}")
        
        # Risk analysis
        risk_analysis = analyze_cvss_risk(cve_id)
        if risk_analysis and risk_analysis.get('risk_factors'):
            print(f"\nKey Risk Factors:")
            for factor in risk_analysis['risk_factors']:
                print(f"  • {factor}")
        
        # Demonstrate vector parsing
        parsed_vector = parse_cvss_vector(vector_string)
        if parsed_vector:
            print(f"\nParsed Vector Components:")
            for key, value in parsed_vector.items():
                if key != 'version':
                    print(f"  {key}: {value}")
    
    else:
        print("  Could not retrieve CVSS details for demonstration")
    
    # Quick comparison of multiple CVEs
    print(f"\n" + "-" * 60)
    print("CVSS Score Comparison:")
    comparison_cves = ["CVE-2021-44228", "CVE-2022-22965", "CVE-2014-0160"]
    
    for cve in comparison_cves:
        score = get_cvss_score(cve)
        vector = get_cvss_vector(cve)
        details = get_cvss_details(cve)
        
        if score and details:
            attack_vector = details.get('attackVector', 'Unknown')
            complexity = details.get('attackComplexity', 'Unknown')
            print(f"  {cve}: {score} ({attack_vector}, {complexity} complexity)")
        else:
            print(f"  {cve}: Score not available")

def main():
    """Main function demonstrating SeeVee usage"""
    
    # Example vulnerability list (mix of severities)
    vulnerabilities_to_assess = [
        "CVE-2021-44228",  # Log4Shell (Critical)
        "CVE-2022-22965",  # Spring4Shell (High)
        "CVE-2014-0160",   # Heartbleed (High)
        "CVE-2017-5638",   # Apache Struts (High)
        "CVE-2020-1472",   # Zerologon (Critical)
    ]
    
    print("🔍 SeeVee Vulnerability Assessment Tool - Example Usage")
    
    # Generate vulnerability report
    generate_vulnerability_report(vulnerabilities_to_assess)
    
    # Demonstrate CWE analysis
    demonstrate_cwe_analysis()
    
    # Demonstrate CWE integration
    demonstrate_cwe_integration()
    
    # Demonstrate CVSS analysis
    demonstrate_cvss_analysis()
    
    # Show how to get specific data
    print("\n" + "=" * 80)
    print("                    PROGRAMMATIC ACCESS EXAMPLES")
    print("=" * 80)
    
    print("\nExample: Getting just CVSS scores")
    for cve in vulnerabilities_to_assess[:3]:
        score = get_cvss_score(cve)
        print(f"  {cve}: {score}")
    
    print("\nExample: Quick severity check")
    cve = "CVE-2021-44228"
    score = get_cvss_score(cve)
    severity, _ = assess_vulnerability_severity(score)
    print(f"  {cve} is rated as {severity} (CVSS: {score})")
    
    print("\nExample: CVSS vector analysis")
    vector = get_cvss_vector(cve)
    details = get_cvss_details(cve)
    if vector and details:
        print(f"  {cve} vector: {vector}")
        print(f"  Attack vector: {details.get('attackVector')}")
        print(f"  Requires privileges: {details.get('privilegesRequired')}")
    
    print("\nExample: Risk factor analysis")
    risk = analyze_cvss_risk(cve)
    if risk and risk.get('risk_factors'):
        print(f"  {cve} key risks: {', '.join(risk['risk_factors'][:2])}")

if __name__ == "__main__":
    main() 