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
        
        # Get CVE information
        cve_data = get_cve_info(cve_id)
        
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
        
        if vuln['cwe_ids']:
            print(f"  CWE Types:")
            for cwe_id in vuln['cwe_ids'][:3]:  # Show first 3 CWEs
                cwe_info = get_cwe_info(cwe_id)
                if cwe_info:
                    print(f"    - {cwe_id}: {cwe_info['name']}")
        
        print(f"  Description: {vuln['description']}")
    
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
    
    print("\n  - Monitor vendor security advisories for patches")
    print("  - Consider implementing additional security controls")
    print("  - Regular vulnerability assessments recommended")

def demonstrate_cwe_analysis():
    """Demonstrate CWE analysis capabilities"""
    print("\n" + "=" * 80)
    print("                        CWE ANALYSIS EXAMPLE")
    print("=" * 80)
    
    common_cwes = [79, 89, 22, 352, 502, 287, 200]
    
    print("Common Web Application Vulnerabilities:")
    for cwe_num in common_cwes:
        cwe_info = get_cwe_info(cwe_num)
        if cwe_info:
            print(f"  {cwe_info['cwe_id']}: {cwe_info['name']}")


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