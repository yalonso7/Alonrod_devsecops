#!/usr/bin/env python3
"""
Terraform Policy as Code Scanner for AWS and GCP
Implements security controls based on OWASP Top 10 and CSA CCM
"""

import json
import re
import os
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

class TerraformSecurityScanner:
    def __init__(self):
        self.findings = []
        self.stats = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        # Security policy rules mapped to OWASP and CSA CCM
        self.rules = self._initialize_rules()
    
    def _initialize_rules(self) -> List[Dict]:
        """Initialize security rules with OWASP and CSA CCM mappings"""
        return [
            # AWS Security Rules
            {
                "id": "AWS-S3-001",
                "name": "S3 Bucket Public Access",
                "severity": "critical",
                "provider": "aws",
                "resource_type": "aws_s3_bucket",
                "pattern": r'resource\s+"aws_s3_bucket"\s+"[^"]+"\s*{[^}]*acl\s*=\s*"public-read',
                "owasp": ["A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"],
                "csa_ccm": ["IAM-02", "DSI-02", "GRM-06"],
                "description": "S3 bucket allows public read access",
                "recommendation": "Remove public ACL. Use bucket policies with principle of least privilege. Enable S3 Block Public Access."
            },
            {
                "id": "AWS-S3-002",
                "name": "S3 Bucket Encryption Disabled",
                "severity": "high",
                "provider": "aws",
                "resource_type": "aws_s3_bucket",
                "pattern": r'resource\s+"aws_s3_bucket"\s+"([^"]+)"\s*{(?:(?!server_side_encryption_configuration).)*}',
                "owasp": ["A02:2021-Cryptographic Failures"],
                "csa_ccm": ["EKM-01", "EKM-02", "DSI-01"],
                "description": "S3 bucket does not have encryption enabled",
                "recommendation": "Enable server-side encryption using aws_s3_bucket_server_side_encryption_configuration with AES256 or aws:kms."
            },
            {
                "id": "AWS-EC2-001",
                "name": "EC2 Instance Public IP",
                "severity": "high",
                "provider": "aws",
                "resource_type": "aws_instance",
                "pattern": r'associate_public_ip_address\s*=\s*true',
                "owasp": ["A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"],
                "csa_ccm": ["IVS-01", "IAM-09"],
                "description": "EC2 instance has public IP enabled",
                "recommendation": "Avoid public IPs. Use NAT Gateway or VPN for outbound access. Place instances in private subnets."
            },
            {
                "id": "AWS-SG-001",
                "name": "Security Group Unrestricted Ingress",
                "severity": "critical",
                "provider": "aws",
                "resource_type": "aws_security_group",
                "pattern": r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
                "owasp": ["A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"],
                "csa_ccm": ["IVS-01", "IVS-02", "IAM-09"],
                "description": "Security group allows unrestricted ingress (0.0.0.0/0)",
                "recommendation": "Restrict ingress to specific IP ranges. Use least privilege principle for network access."
            },
            {
                "id": "AWS-RDS-001",
                "name": "RDS Instance Not Encrypted",
                "severity": "high",
                "provider": "aws",
                "resource_type": "aws_db_instance",
                "pattern": r'resource\s+"aws_db_instance"\s+"([^"]+)"\s*{(?:(?!storage_encrypted\s*=\s*true).)*}',
                "owasp": ["A02:2021-Cryptographic Failures"],
                "csa_ccm": ["EKM-01", "EKM-02", "DSI-01"],
                "description": "RDS instance does not have encryption enabled",
                "recommendation": "Enable storage_encrypted = true and specify kms_key_id for encryption at rest."
            },
            {
                "id": "AWS-RDS-002",
                "name": "RDS Publicly Accessible",
                "severity": "critical",
                "provider": "aws",
                "resource_type": "aws_db_instance",
                "pattern": r'publicly_accessible\s*=\s*true',
                "owasp": ["A01:2021-Broken Access Control"],
                "csa_ccm": ["IAM-02", "DSI-02"],
                "description": "RDS instance is publicly accessible",
                "recommendation": "Set publicly_accessible = false. Use private subnets and VPN/bastion for access."
            },
            {
                "id": "AWS-IAM-001",
                "name": "IAM Policy Wildcard Actions",
                "severity": "high",
                "provider": "aws",
                "resource_type": "aws_iam_policy",
                "pattern": r'"Action"\s*:\s*"[*]"',
                "owasp": ["A01:2021-Broken Access Control"],
                "csa_ccm": ["IAM-01", "IAM-02", "IAM-08"],
                "description": "IAM policy allows wildcard (*) actions",
                "recommendation": "Use specific actions instead of wildcards. Follow least privilege principle."
            },
            {
                "id": "AWS-LOG-001",
                "name": "CloudWatch Logs Not Configured",
                "severity": "medium",
                "provider": "aws",
                "resource_type": "aws_instance",
                "pattern": r'resource\s+"aws_instance"\s+"([^"]+)"\s*{(?:(?!cloudwatch).)*}',
                "owasp": ["A09:2021-Security Logging and Monitoring Failures"],
                "csa_ccm": ["LOG-01", "LOG-02", "SEF-01"],
                "description": "Instance does not have CloudWatch logging configured",
                "recommendation": "Configure CloudWatch Logs for monitoring and auditing. Enable detailed monitoring."
            },
            
            # GCP Security Rules
            {
                "id": "GCP-GCS-001",
                "name": "GCS Bucket Public Access",
                "severity": "critical",
                "provider": "gcp",
                "resource_type": "google_storage_bucket",
                "pattern": r'role\s*=\s*"roles/storage\.objectViewer"\s*\n\s*members\s*=\s*\[\s*"allUsers"',
                "owasp": ["A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"],
                "csa_ccm": ["IAM-02", "DSI-02", "GRM-06"],
                "description": "GCS bucket allows public access",
                "recommendation": "Remove allUsers and allAuthenticatedUsers from IAM bindings. Use specific service accounts."
            },
            {
                "id": "GCP-GCS-002",
                "name": "GCS Bucket Encryption Not Configured",
                "severity": "high",
                "provider": "gcp",
                "resource_type": "google_storage_bucket",
                "pattern": r'resource\s+"google_storage_bucket"\s+"([^"]+)"\s*{(?:(?!encryption).)*}',
                "owasp": ["A02:2021-Cryptographic Failures"],
                "csa_ccm": ["EKM-01", "EKM-02", "DSI-01"],
                "description": "GCS bucket does not have customer-managed encryption",
                "recommendation": "Configure encryption block with default_kms_key_name for CMEK encryption."
            },
            {
                "id": "GCP-GCE-001",
                "name": "GCE Instance External IP",
                "severity": "high",
                "provider": "gcp",
                "resource_type": "google_compute_instance",
                "pattern": r'access_config\s*{',
                "owasp": ["A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"],
                "csa_ccm": ["IVS-01", "IAM-09"],
                "description": "GCE instance has external IP address",
                "recommendation": "Remove access_config block. Use Cloud NAT or Identity-Aware Proxy for access."
            },
            {
                "id": "GCP-FW-001",
                "name": "Firewall Rule Allows All",
                "severity": "critical",
                "provider": "gcp",
                "resource_type": "google_compute_firewall",
                "pattern": r'source_ranges\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
                "owasp": ["A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"],
                "csa_ccm": ["IVS-01", "IVS-02", "IAM-09"],
                "description": "Firewall rule allows traffic from anywhere (0.0.0.0/0)",
                "recommendation": "Restrict source_ranges to specific IP ranges. Use Identity-Aware Proxy where possible."
            },
            {
                "id": "GCP-SQL-001",
                "name": "Cloud SQL Not Encrypted",
                "severity": "high",
                "provider": "gcp",
                "resource_type": "google_sql_database_instance",
                "pattern": r'resource\s+"google_sql_database_instance"\s+"([^"]+)"\s*{(?:(?!encryption_key_name).)*}',
                "owasp": ["A02:2021-Cryptographic Failures"],
                "csa_ccm": ["EKM-01", "EKM-02", "DSI-01"],
                "description": "Cloud SQL instance not using customer-managed encryption key",
                "recommendation": "Configure encryption_key_name for CMEK. Enable automated backups with encryption."
            },
            {
                "id": "GCP-SQL-002",
                "name": "Cloud SQL Public IP",
                "severity": "critical",
                "provider": "gcp",
                "resource_type": "google_sql_database_instance",
                "pattern": r'ip_configuration\s*{[^}]*ipv4_enabled\s*=\s*true',
                "owasp": ["A01:2021-Broken Access Control"],
                "csa_ccm": ["IAM-02", "DSI-02"],
                "description": "Cloud SQL instance has public IP enabled",
                "recommendation": "Set ipv4_enabled = false. Use Private IP and Cloud SQL Proxy for secure access."
            },
            {
                "id": "GCP-LOG-001",
                "name": "GCE No Logging Configured",
                "severity": "medium",
                "provider": "gcp",
                "resource_type": "google_compute_instance",
                "pattern": r'resource\s+"google_compute_instance"\s+"([^"]+)"\s*{(?:(?!logging).)*}',
                "owasp": ["A09:2021-Security Logging and Monitoring Failures"],
                "csa_ccm": ["LOG-01", "LOG-02", "SEF-01"],
                "description": "GCE instance does not have logging configured",
                "recommendation": "Enable Cloud Logging and Cloud Monitoring. Configure log sinks for security events."
            },
            
            # Cross-Provider Rules
            {
                "id": "GEN-001",
                "name": "Hardcoded Secrets",
                "severity": "critical",
                "provider": "all",
                "resource_type": "all",
                "pattern": r'(password|secret|api_key|token)\s*=\s*"[^$]',
                "owasp": ["A07:2021-Identification and Authentication Failures"],
                "csa_ccm": ["IAM-01", "EKM-03", "GRM-01"],
                "description": "Hardcoded secrets found in configuration",
                "recommendation": "Use secrets management services (AWS Secrets Manager, GCP Secret Manager). Reference secrets via variables."
            },
            {
                "id": "GEN-002",
                "name": "Missing Resource Tags",
                "severity": "low",
                "provider": "all",
                "resource_type": "all",
                "pattern": r'resource\s+"(?:aws_|google_)[^"]+"\s+"([^"]+)"\s*{(?:(?!tags).)*}',
                "owasp": ["A05:2021-Security Misconfiguration"],
                "csa_ccm": ["GRM-06", "GRM-08"],
                "description": "Resource missing required tags/labels for governance",
                "recommendation": "Add tags/labels for Environment, Owner, CostCenter, and DataClassification for proper governance."
            }
        ]
    
    def scan_file(self, filepath: str) -> None:
        """Scan a Terraform file for security issues"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                
            for rule in self.rules:
                if rule['provider'] != 'all':
                    # Check if file contains provider-specific resources
                    if rule['provider'] == 'aws' and 'provider "aws"' not in content:
                        continue
                    if rule['provider'] == 'gcp' and 'provider "google"' not in content:
                        continue
                
                matches = re.finditer(rule['pattern'], content, re.MULTILINE | re.DOTALL)
                
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    finding = {
                        "rule_id": rule['id'],
                        "rule_name": rule['name'],
                        "severity": rule['severity'],
                        "file": filepath,
                        "line": line_num,
                        "resource_type": rule['resource_type'],
                        "description": rule['description'],
                        "recommendation": rule['recommendation'],
                        "owasp_mapping": rule['owasp'],
                        "csa_ccm_mapping": rule['csa_ccm'],
                        "matched_text": match.group(0)[:100] + "..." if len(match.group(0)) > 100 else match.group(0)
                    }
                    
                    self.findings.append(finding)
                    self.stats[rule['severity']] += 1
                    
        except Exception as e:
            print(f"Error scanning {filepath}: {str(e)}")
    
    def scan_directory(self, directory: str) -> None:
        """Recursively scan directory for Terraform files"""
        path = Path(directory)
        
        # Find all .tf files
        tf_files = list(path.rglob("*.tf"))
        
        if not tf_files:
            print(f"No Terraform files found in {directory}")
            return
        
        print(f"Found {len(tf_files)} Terraform files. Scanning...")
        
        for tf_file in tf_files:
            print(f"Scanning: {tf_file}")
            self.scan_file(str(tf_file))
    
    def generate_report(self, output_file: str = "security_report.json") -> None:
        """Generate detailed JSON report"""
        
        # Group findings by severity
        findings_by_severity = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
        
        for finding in self.findings:
            findings_by_severity[finding['severity']].append(finding)
        
        # Create compliance mapping summary
        owasp_coverage = {}
        csa_ccm_coverage = {}
        
        for finding in self.findings:
            for owasp in finding['owasp_mapping']:
                owasp_coverage[owasp] = owasp_coverage.get(owasp, 0) + 1
            for ccm in finding['csa_ccm_mapping']:
                csa_ccm_coverage[ccm] = csa_ccm_coverage.get(ccm, 0) + 1
        
        report = {
            "scan_metadata": {
                "scan_date": datetime.now().isoformat(),
                "scanner_version": "1.0.0",
                "total_files_scanned": len(set([f['file'] for f in self.findings])),
                "total_findings": len(self.findings)
            },
            "executive_summary": {
                "severity_breakdown": self.stats,
                "risk_score": self._calculate_risk_score(),
                "compliance_status": self._assess_compliance()
            },
            "findings_by_severity": findings_by_severity,
            "compliance_mapping": {
                "owasp_top_10": {
                    "coverage": owasp_coverage,
                    "total_categories": len(owasp_coverage)
                },
                "csa_ccm": {
                    "coverage": csa_ccm_coverage,
                    "total_controls": len(csa_ccm_coverage)
                }
            },
            "recommendations": self._generate_recommendations(),
            "remediation_priority": self._prioritize_remediation()
        }
        
        # Write report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{'='*70}")
        print(f"Security Scan Complete!")
        print(f"{'='*70}")
        print(f"Total Findings: {len(self.findings)}")
        print(f"  Critical: {self.stats['critical']}")
        print(f"  High: {self.stats['high']}")
        print(f"  Medium: {self.stats['medium']}")
        print(f"  Low: {self.stats['low']}")
        print(f"  Info: {self.stats['info']}")
        print(f"\nRisk Score: {report['executive_summary']['risk_score']}/100")
        print(f"Report saved to: {output_file}")
        print(f"{'='*70}\n")
    
    def _calculate_risk_score(self) -> int:
        """Calculate overall risk score (0-100)"""
        score = 0
        score += self.stats['critical'] * 25
        score += self.stats['high'] * 10
        score += self.stats['medium'] * 5
        score += self.stats['low'] * 1
        
        return min(score, 100)
    
    def _assess_compliance(self) -> str:
        """Assess overall compliance status"""
        if self.stats['critical'] > 0:
            return "NON-COMPLIANT - Critical issues must be resolved"
        elif self.stats['high'] > 5:
            return "AT-RISK - Multiple high-severity issues detected"
        elif self.stats['high'] > 0 or self.stats['medium'] > 10:
            return "NEEDS IMPROVEMENT - Address high and medium issues"
        elif self.stats['medium'] > 0 or self.stats['low'] > 0:
            return "ACCEPTABLE - Minor issues remain"
        else:
            return "COMPLIANT - No security issues detected"
    
    def _generate_recommendations(self) -> List[Dict]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        # Count issues by type
        issue_counts = {}
        for finding in self.findings:
            key = finding['rule_id']
            if key not in issue_counts:
                issue_counts[key] = {
                    "count": 0,
                    "severity": finding['severity'],
                    "recommendation": finding['recommendation'],
                    "rule_name": finding['rule_name']
                }
            issue_counts[key]["count"] += 1
        
        # Sort by severity and count
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_issues = sorted(
            issue_counts.items(),
            key=lambda x: (severity_order[x[1]['severity']], -x[1]['count'])
        )
        
        for rule_id, data in sorted_issues[:10]:  # Top 10
            recommendations.append({
                "priority": len(recommendations) + 1,
                "rule_id": rule_id,
                "rule_name": data['rule_name'],
                "occurrences": data['count'],
                "severity": data['severity'],
                "action": data['recommendation']
            })
        
        return recommendations
    
    def _prioritize_remediation(self) -> Dict:
        """Create remediation roadmap"""
        return {
            "immediate_action_required": [
                f for f in self.findings if f['severity'] == 'critical'
            ][:5],
            "short_term_30_days": [
                f for f in self.findings if f['severity'] == 'high'
            ][:10],
            "medium_term_90_days": [
                f for f in self.findings if f['severity'] == 'medium'
            ][:10],
            "long_term_planning": [
                f for f in self.findings if f['severity'] in ['low', 'info']
            ][:10]
        }


def main():
    """Main execution function"""
    import sys
    
    scanner = TerraformSecurityScanner()
    
    # Get directory path from command line or use current directory
    if len(sys.argv) > 1:
        scan_path = sys.argv[1]
    else:
        scan_path = "."
    
    # Get output file from command line or use default
    if len(sys.argv) > 2:
        output_file = sys.argv[2]
    else:
        output_file = "terraform_security_report.json"
    
    print(f"\n{'='*70}")
    print("Terraform Infrastructure as Code Security Scanner")
    print("OWASP Top 10 & CSA CCM Compliance Checker")
    print(f"{'='*70}\n")
    
    # Scan the directory
    scanner.scan_directory(scan_path)
    
    # Generate report
    scanner.generate_report(output_file)
    
    # Print sample findings
    if scanner.findings:
        print("\nSample Critical/High Findings:")
        print("-" * 70)
        for finding in scanner.findings[:5]:
            if finding['severity'] in ['critical', 'high']:
                print(f"\n[{finding['severity'].upper()}] {finding['rule_name']}")
                print(f"  File: {finding['file']}:{finding['line']}")
                print(f"  OWASP: {', '.join(finding['owasp_mapping'])}")
                print(f"  CSA CCM: {', '.join(finding['csa_ccm_mapping'])}")
                print(f"  Issue: {finding['description']}")


if __name__ == "__main__":
    main()