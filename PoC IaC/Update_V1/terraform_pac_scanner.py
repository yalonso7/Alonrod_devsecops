#!/usr/bin/env python3
"""
Terraform Policy as Code Scanner for AWS and GCP
Implements security controls based on OWASP Top 10 and CSA CCM
"""

import json
import re
import os
import sys
import yaml
import argparse
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

class TerraformSecurityScanner:
    def __init__(self, rules_file: str = "rules.yaml"):
        self.findings = []
        self.stats = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        self.rules_file = rules_file
        self.rules = self._initialize_rules()
    
    def _initialize_rules(self) -> List[Dict]:
        """Initialize security rules from external YAML file"""
        if not os.path.exists(self.rules_file):
            print(f"Error: Rules file '{self.rules_file}' not found.")
            sys.exit(1)
            
        try:
            with open(self.rules_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                return data.get('rules', [])
        except Exception as e:
            print(f"Error loading rules from {self.rules_file}: {e}")
            sys.exit(1)
    
    def _check_ignore(self, content: str, line_num: int, rule_id: str) -> bool:
        """
        Check if a rule is ignored via comment.
        Look for comments like: # tf-scanner:ignore:RULE-ID
        Checks the line itself and the line above.
        """
        lines = content.splitlines()
        
        # Adjust for 0-based indexing
        current_line_idx = line_num - 1
        
        # Check current line (inline comment)
        if current_line_idx < len(lines):
            if f"tf-scanner:ignore:{rule_id}" in lines[current_line_idx]:
                return True
        
        # Check previous line
        if current_line_idx > 0:
            if f"tf-scanner:ignore:{rule_id}" in lines[current_line_idx - 1]:
                return True
                
        return False

    def scan_file(self, filepath: str) -> None:
        """Scan a Terraform file for security issues"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                
            for rule in self.rules:
                if rule['provider'] != 'all':
                    # Check if file contains provider-specific resources
                    if rule['provider'] == 'aws' and 'provider "aws"' not in content:
                        # Simple heuristic check, might need refinement for large modules
                        pass 
                    if rule['provider'] == 'gcp' and 'provider "google"' not in content:
                        pass
                
                matches = re.finditer(rule['pattern'], content, re.MULTILINE | re.DOTALL)
                
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    # Check for ignore comments
                    if self._check_ignore(content, line_num, rule['id']):
                        continue
                    
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
                "scanner_version": "1.1.0",
                "total_files_scanned": len(set([f['file'] for f in self.findings])) if self.findings else 0,
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
        
        self._print_summary(report, output_file)

    def generate_sarif_report(self, output_file: str = "security_report.sarif") -> None:
        """Generate SARIF format report"""
        sarif_log = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Terraform Policy Scanner",
                            "version": "1.1.0",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }
        
        # Add rules
        rules_map = {}
        for rule in self.rules:
            rules_map[rule['id']] = len(sarif_log["runs"][0]["tool"]["driver"]["rules"])
            sarif_log["runs"][0]["tool"]["driver"]["rules"].append({
                "id": rule['id'],
                "name": rule['name'],
                "shortDescription": {
                    "text": rule['name']
                },
                "fullDescription": {
                    "text": rule['description']
                },
                "help": {
                    "text": rule['recommendation']
                },
                "properties": {
                    "severity": rule['severity'],
                    "owasp": rule['owasp'],
                    "csa_ccm": rule['csa_ccm']
                }
            })
            
        # Add results
        for finding in self.findings:
            sarif_log["runs"][0]["results"].append({
                "ruleId": finding['rule_id'],
                "ruleIndex": rules_map.get(finding['rule_id'], -1),
                "level": "error" if finding['severity'] in ['critical', 'high'] else "warning",
                "message": {
                    "text": finding['description']
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding['file']
                            },
                            "region": {
                                "startLine": finding['line']
                            }
                        }
                    }
                ]
            })
            
        with open(output_file, 'w') as f:
            json.dump(sarif_log, f, indent=2)
            
        print(f"SARIF report saved to: {output_file}")

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
        
    def _print_summary(self, report, output_file):
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


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description="Terraform Security Scanner")
    parser.add_argument("directory", nargs="?", default=".", help="Directory to scan")
    parser.add_argument("-o", "--output", default="terraform_security_report.json", help="Output JSON report file")
    parser.add_argument("--sarif", action="store_true", help="Generate SARIF report")
    parser.add_argument("--rules", default="rules.yaml", help="Path to rules YAML file")
    
    args = parser.parse_args()
    
    print(f"\n{'='*70}")
    print("Terraform Infrastructure as Code Security Scanner")
    print("OWASP Top 10 & CSA CCM Compliance Checker")
    print(f"{'='*70}\n")
    
    scanner = TerraformSecurityScanner(rules_file=args.rules)
    
    # Scan the directory
    scanner.scan_directory(args.directory)
    
    # Generate report
    scanner.generate_report(args.output)
    
    if args.sarif:
        sarif_file = args.output.replace(".json", ".sarif")
        if sarif_file == args.output:
            sarif_file += ".sarif"
        scanner.generate_sarif_report(sarif_file)
    
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
