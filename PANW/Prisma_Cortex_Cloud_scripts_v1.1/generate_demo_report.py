#!/usr/bin/env python3
"""
Demo Report Generator
Generates a sample HTML report with dummy data to showcase visualizations and GRC features.
"""

import logging
from pathlib import Path
from PrismaCloud_migrationtool import HTMLReportGenerator

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_demo_data():
    """Create rich dummy data for demonstration"""
    
    # 1. Dummy Policies with Compliance mappings
    policies = [
        # NIST & ISO Related
        {
            "name": "Ensure S3 buckets are encrypted with KMS",
            "severity": "high",
            "description": "Data at rest must be encrypted. Maps to NIST 800-53 SC-28 and ISO 27001 A.10.1.1",
            "complianceMetadata": [{"standardId": "NIST 800-53"}, {"standardId": "ISO 27001"}]
        },
        {
            "name": "Ensure CloudTrail log file validation is enabled",
            "severity": "medium",
            "description": "Ensures integrity of log files. NIST SI-4",
            "complianceMetadata": [{"standardId": "NIST 800-53"}]
        },
        # PCI DSS Related
        {
            "name": "Restrict access to cardholder data",
            "severity": "critical",
            "description": "PCI DSS Requirement 7: Restrict access to cardholder data by business need to know",
            "complianceMetadata": [{"standardId": "PCI DSS 3.2"}]
        },
        {
            "name": "Ensure firewall rules do not allow 0.0.0.0/0 to SSH",
            "severity": "high",
            "description": "PCI DSS Requirement 1: Install and maintain a firewall configuration",
            "complianceMetadata": [{"standardId": "PCI DSS"}]
        },
        # HIPAA Related
        {
            "name": "Ensure ePHI is encrypted in transit",
            "severity": "high",
            "description": "HIPAA Technical Safeguards - Access Control",
            "complianceMetadata": [{"standardId": "HIPAA"}]
        },
        {
            "name": "Ensure audit logging for medical records access",
            "severity": "medium",
            "description": "HIPAA Audit Controls",
            "complianceMetadata": [{"standardId": "HIPAA"}]
        },
        # SOC 2 Related
        {
            "name": "Ensure MFA is enabled for all IAM users",
            "severity": "critical",
            "description": "Common Criteria for SOC 2 CC6.1",
            "complianceMetadata": [{"standardId": "SOC 2"}]
        },
        {
            "name": "Ensure database backups are retained for 30 days",
            "severity": "low",
            "description": "Availability criteria for SOC 2",
            "complianceMetadata": [{"standardId": "SOC 2"}]
        },
        # General / Unmapped (to show distribution)
        {
            "name": "Ensure unused security groups are deleted",
            "severity": "low",
            "description": "Housekeeping",
            "complianceMetadata": []
        },
        {
            "name": "Ensure excessive permissions are revoked",
            "severity": "high",
            "description": "Least privilege principle",
            "complianceMetadata": []
        }
    ]

    # Duplicate some policies to create volume for charts
    policies.extend(policies) # 20 policies
    policies.extend(policies[:5]) # 25 policies

    # 2. Alert Rules
    alert_rules = [
        {"name": "Production Environment - High Severity"},
        {"name": "Compliance - PCI DSS"},
        {"name": "Compliance - HIPAA"},
        {"name": "Suspicious User Activity"},
        {"name": "Network Anomalies"}
    ]

    # 3. Cloud Accounts
    cloud_accounts = [
        {"name": "AWS-Prod-01", "cloudType": "aws"},
        {"name": "AWS-Dev-01", "cloudType": "aws"},
        {"name": "Azure-Prod-01", "cloudType": "azure"},
        {"name": "GCP-Analytics", "cloudType": "gcp"}
    ]

    # Prisma Data (Source)
    prisma_data = {
        "policies": policies,
        "alert_rules": alert_rules,
        "cloud_accounts": cloud_accounts
    }

    # Cortex Data (Target) - Simulate a small discrepancy for demonstration
    cortex_data = {
        "policies": policies, # 100% match
        "alert_rules": alert_rules[:-1], # 1 missing rule (Discrepancy)
        "cloud_accounts": cloud_accounts # 100% match
    }

    return prisma_data, cortex_data

def main():
    output_dir = Path("demo_report_output")
    output_dir.mkdir(exist_ok=True)
    
    print("Generating demo data...")
    prisma_data, cortex_data = generate_demo_data()
    
    print(f"Policies: {len(prisma_data['policies'])}")
    print(f"Alert Rules: {len(prisma_data['alert_rules'])}")
    print(f"Cloud Accounts: {len(prisma_data['cloud_accounts'])}")
    
    print("\nGenerating HTML Report...")
    generator = HTMLReportGenerator(prisma_data, cortex_data, output_dir)
    generator.generate()
    
    report_path = output_dir / "migration_compliance_report.html"
    print(f"\nSUCCESS: Demo report generated at: {report_path.absolute()}")
    print("You can open this file in your browser to view the visualizations.")

if __name__ == "__main__":
    main()
