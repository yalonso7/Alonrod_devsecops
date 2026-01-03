#!/usr/bin/env python3
"""
Prisma Cloud to Cortex Cloud Migration Tool
Helps security teams migrate policies, alerts, and compliance data
"""

import json
import requests
import argparse
import logging
from typing import Dict, List, Optional
from datetime import datetime
import csv
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PrismaCloudClient:
    """Client for interacting with Prisma Cloud API"""
    
    def __init__(self, api_url: str, access_key: str, secret_key: str):
        self.api_url = api_url.rstrip('/')
        self.access_key = access_key
        self.secret_key = secret_key
        self.token = None
        self.session = requests.Session()
    
    def authenticate(self) -> bool:
        """Authenticate with Prisma Cloud"""
        try:
            url = f"{self.api_url}/login"
            payload = {
                "username": self.access_key,
                "password": self.secret_key
            }
            response = self.session.post(url, json=payload, timeout=30)
            response.raise_for_status()
            self.token = response.json().get('token')
            self.session.headers.update({'x-redlock-auth': self.token})
            logger.info("Successfully authenticated with Prisma Cloud")
            return True
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return False

    def _paginated_request(self, endpoint: str, params: Dict = None) -> List[Dict]:
        """Helper for paginated requests"""
        if params is None:
            params = {}
            
        limit = 50
        offset = 0
        all_items = []
        
        while True:
            current_params = params.copy()
            current_params.update({'limit': limit, 'offset': offset})
            
            try:
                url = f"{self.api_url}/{endpoint}"
                response = self.session.get(url, params=current_params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                
                # Handle different response structures
                items = []
                if isinstance(data, list):
                    items = data
                elif isinstance(data, dict) and 'items' in data:
                    items = data['items']
                else:
                    # If structure is unknown or not paginated as expected, return what we got
                    if offset == 0:
                        if isinstance(data, dict):
                             # Some endpoints might return a single dict
                             return [data]
                        return data
                    else:
                        break

                if not items:
                    break
                    
                all_items.extend(items)
                
                if len(items) < limit:
                    break
                    
                offset += limit
                logger.info(f"Fetched {len(all_items)} items from {endpoint}...")
                
            except Exception as e:
                logger.error(f"Error fetching {endpoint} at offset {offset}: {e}")
                if offset == 0:
                    return []
                break
                
        return all_items
    
    def get_policies(self) -> List[Dict]:
        """Export all policies from Prisma Cloud"""
        try:
            policies = self._paginated_request("policy")
            logger.info(f"Retrieved {len(policies)} policies")
            return policies
        except Exception as e:
            logger.error(f"Failed to retrieve policies: {e}")
            return []
    
    def get_alert_rules(self) -> List[Dict]:
        """Export alert rules from Prisma Cloud"""
        try:
            rules = self._paginated_request("alert/rule")
            logger.info(f"Retrieved {len(rules)} alert rules")
            return rules
        except Exception as e:
            logger.error(f"Failed to retrieve alert rules: {e}")
            return []
    
    def get_compliance_standards(self) -> List[Dict]:
        """Export compliance standards"""
        try:
            # Compliance standards might not be paginated or might use different structure
            # but _paginated_request handles list response gracefully
            standards = self._paginated_request("compliance")
            logger.info(f"Retrieved {len(standards)} compliance standards")
            return standards
        except Exception as e:
            logger.error(f"Failed to retrieve compliance standards: {e}")
            return []
    
    def get_cloud_accounts(self) -> List[Dict]:
        """Export cloud account configurations"""
        try:
            accounts = self._paginated_request("cloud")
            logger.info(f"Retrieved {len(accounts)} cloud accounts")
            return accounts
        except Exception as e:
            logger.error(f"Failed to retrieve cloud accounts: {e}")
            return []


class CortexCloudTransformer:
    """Transform Prisma Cloud data to Cortex Cloud format"""
    
    @staticmethod
    def transform_policy(prisma_policy: Dict) -> Dict:
        """Transform Prisma Cloud policy to Cortex Cloud format"""
        return {
            "name": prisma_policy.get("name"),
            "description": prisma_policy.get("description"),
            "severity": prisma_policy.get("severity"),
            "policyType": prisma_policy.get("policyType"),
            "cloudType": prisma_policy.get("cloudType"),
            "rule": {
                "criteria": prisma_policy.get("rule", {}).get("criteria"),
                "parameters": prisma_policy.get("rule", {}).get("parameters"),
                "type": prisma_policy.get("rule", {}).get("type")
            },
            "recommendation": prisma_policy.get("recommendation"),
            "enabled": prisma_policy.get("enabled", True),
            "labels": prisma_policy.get("labels", []),
            "complianceMetadata": prisma_policy.get("complianceMetadata", [])
        }
    
    @staticmethod
    def transform_alert_rule(prisma_rule: Dict) -> Dict:
        """Transform Prisma Cloud alert rule to Cortex Cloud format"""
        return {
            "name": prisma_rule.get("name"),
            "description": prisma_rule.get("description"),
            "enabled": prisma_rule.get("enabled", True),
            "scanAll": prisma_rule.get("scanAll", False),
            "policies": prisma_rule.get("policies", []),
            "target": {
                "accountGroups": prisma_rule.get("target", {}).get("accountGroups", []),
                "regions": prisma_rule.get("target", {}).get("regions", []),
                "tags": prisma_rule.get("target", {}).get("tags", [])
            },
            "notificationConfig": prisma_rule.get("notificationConfig", []),
            "allowAutoRemediate": prisma_rule.get("allowAutoRemediate", False)
        }
    
    @staticmethod
    def transform_cloud_account(prisma_account: Dict) -> Dict:
        """Transform cloud account configuration"""
        return {
            "name": prisma_account.get("name"),
            "accountId": prisma_account.get("accountId"),
            "cloudType": prisma_account.get("cloudType"),
            "enabled": prisma_account.get("enabled", True),
            "groupIds": prisma_account.get("groupIds", []),
            "accountType": prisma_account.get("accountType"),
            "protectionMode": prisma_account.get("protectionMode")
        }


class HTMLReportGenerator:
    """Generates HTML reports for migration and compliance"""
    
    def __init__(self, prisma_data: Dict, cortex_data: Dict, output_dir: Path):
        self.prisma_data = prisma_data
        self.cortex_data = cortex_data
        self.output_dir = output_dir
        self.compliance_frameworks = ["HIPAA", "NIST", "ISO 27001", "SOC 2", "PCI DSS"]

    def _generate_compliance_heatmap_data(self) -> Dict:
        """Generate data for compliance heatmap"""
        # specialized logic to map policies to compliance frameworks
        # This is a simulation/approximation based on policy names or compliance metadata if available
        heatmap_data = {fw: {"High": 0, "Medium": 0, "Low": 0} for fw in self.compliance_frameworks}
        
        policies = self.prisma_data.get("policies", [])
        for policy in policies:
            severity = policy.get("severity", "Low").capitalize()
            if severity not in ["High", "Medium", "Low"]:
                severity = "Low"
                
            compliance_metadata = policy.get("complianceMetadata", [])
            # If metadata exists, check standard names
            mapped = False
            if compliance_metadata:
                for meta in compliance_metadata:
                    standard_id = meta.get("standardId", "")
                    for fw in self.compliance_frameworks:
                        if fw.replace(" ", "").lower() in standard_id.replace(" ", "").lower():
                            heatmap_data[fw][severity] += 1
                            mapped = True
            
            # Fallback: check policy name/description
            if not mapped:
                text = (policy.get("name", "") + " " + policy.get("description", "")).upper()
                for fw in self.compliance_frameworks:
                    if fw.upper() in text:
                        heatmap_data[fw][severity] += 1

        return heatmap_data

    def _generate_severity_distribution(self) -> Dict:
        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for policy in self.prisma_data.get("policies", []):
            sev = policy.get("severity", "low").lower()
            if sev in distribution:
                distribution[sev] += 1
        return distribution

    def generate(self):
        """Generate the HTML report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        severity_dist = self._generate_severity_distribution()
        compliance_data = self._generate_compliance_heatmap_data()
        
        # Prepare Chart Data
        sev_labels = list(severity_dist.keys())
        sev_values = list(severity_dist.values())
        
        comp_labels = list(compliance_data.keys())
        comp_high = [d["High"] for d in compliance_data.values()]
        comp_med = [d["Medium"] for d in compliance_data.values()]
        comp_low = [d["Low"] for d in compliance_data.values()]

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prisma to Cortex Migration & Compliance Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f7fa; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 8px 8px 0 0; display: flex; justify-content: space-between; align-items: center; }}
        .card {{ background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(500px, 1fr)); gap: 20px; }}
        h1, h2, h3 {{ margin-top: 0; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 20px; }}
        .stat-card {{ background: #eef2f7; padding: 15px; border-radius: 6px; text-align: center; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #2c3e50; }}
        .stat-label {{ color: #7f8c8d; font-size: 14px; }}
        .status-pass {{ color: #27ae60; }}
        .status-fail {{ color: #c0392b; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>Migration & Compliance Report</h1>
                <p>Generated on {timestamp}</p>
            </div>
            <div>
                <span style="background: #34495e; padding: 5px 10px; border-radius: 4px;">v1.0</span>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="card">
            <h2>Executive Summary</h2>
            <div class="stat-grid">
                <div class="stat-card">
                    <div class="stat-value">{len(self.prisma_data.get('policies', []))}</div>
                    <div class="stat-label">Total Policies</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{len(self.prisma_data.get('alert_rules', []))}</div>
                    <div class="stat-label">Alert Rules</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{len(self.prisma_data.get('cloud_accounts', []))}</div>
                    <div class="stat-label">Cloud Accounts</div>
                </div>
            </div>
        </div>

        <!-- Visualizations -->
        <div class="grid">
            <div class="card">
                <h3>Policy Severity Distribution</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="card">
                <h3>Compliance Framework Coverage (Heatmap Proxy)</h3>
                <canvas id="complianceChart"></canvas>
            </div>
        </div>

        <!-- Compliance Details -->
        <div class="card">
            <h2>Regulatory Compliance Alignment</h2>
            <p>Analysis of policies against key regulatory frameworks: {', '.join(self.compliance_frameworks)}</p>
            <table>
                <thead>
                    <tr>
                        <th>Framework</th>
                        <th>High Severity Policies</th>
                        <th>Medium Severity Policies</th>
                        <th>Low Severity Policies</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
"""
        for fw in self.compliance_frameworks:
            data = compliance_data[fw]
            total = data['High'] + data['Medium'] + data['Low']
            status = '<span class="status-pass">Active</span>' if total > 0 else '<span class="status-fail">No Coverage</span>'
            html_content += f"""
                    <tr>
                        <td>{fw}</td>
                        <td>{data['High']}</td>
                        <td>{data['Medium']}</td>
                        <td>{data['Low']}</td>
                        <td>{status}</td>
                    </tr>
            """

        html_content += """
                </tbody>
            </table>
        </div>

        <!-- Migration Details -->
        <div class="card">
            <h2>Migration Verification</h2>
            <table>
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Prisma Source</th>
                        <th>Cortex Target</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
"""
        # Migration verification logic
        categories = [
            ("Policies", "policies"),
            ("Alert Rules", "alert_rules"),
            ("Cloud Accounts", "cloud_accounts")
        ]
        
        for name, key in categories:
            src_count = len(self.prisma_data.get(key, []))
            dst_count = len(self.cortex_data.get(key, []))
            status = '<span class="status-pass">Verified</span>' if src_count == dst_count else '<span class="status-fail">Discrepancy</span>'
            html_content += f"""
                    <tr>
                        <td>{name}</td>
                        <td>{src_count}</td>
                        <td>{dst_count}</td>
                        <td>{status}</td>
                    </tr>
            """

        html_content += f"""
                </tbody>
            </table>
        </div>
    </div>

    <script>
        // Severity Chart
        new Chart(document.getElementById('severityChart'), {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(sev_labels)},
                datasets: [{{
                    data: {json.dumps(sev_values)},
                    backgroundColor: ['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71', '#3498db']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'right' }}
                }}
            }}
        }});

        // Compliance Chart
        new Chart(document.getElementById('complianceChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(comp_labels)},
                datasets: [
                    {{
                        label: 'High Severity',
                        data: {json.dumps(comp_high)},
                        backgroundColor: '#e74c3c'
                    }},
                    {{
                        label: 'Medium Severity',
                        data: {json.dumps(comp_med)},
                        backgroundColor: '#e67e22'
                    }},
                    {{
                        label: 'Low Severity',
                        data: {json.dumps(comp_low)},
                        backgroundColor: '#2ecc71'
                    }}
                ]
            }},
            options: {{
                responsive: true,
                scales: {{
                    x: {{ stacked: true }},
                    y: {{ stacked: true }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
        
        output_file = self.output_dir / "migration_compliance_report.html"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logging.info(f"HTML Report generated: {output_file}")


class MigrationTool:
    """Main migration orchestrator"""
    
    def __init__(self, prisma_client: PrismaCloudClient, output_dir: str):
        self.prisma_client = prisma_client
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.transformer = CortexCloudTransformer()
    
    def export_data(self) -> Dict:
        """Export all data from Prisma Cloud"""
        logger.info("Starting data export from Prisma Cloud...")
        
        data = {
            "export_timestamp": datetime.now().isoformat(),
            "policies": self.prisma_client.get_policies(),
            "alert_rules": self.prisma_client.get_alert_rules(),
            "compliance_standards": self.prisma_client.get_compliance_standards(),
            "cloud_accounts": self.prisma_client.get_cloud_accounts()
        }
        
        # Save raw export
        raw_file = self.output_dir / "prisma_export_raw.json"
        with open(raw_file, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Raw export saved to {raw_file}")
        
        return data
    
    def transform_data(self, prisma_data: Dict) -> Dict:
        """Transform Prisma Cloud data to Cortex Cloud format"""
        logger.info("Transforming data for Cortex Cloud...")
        
        cortex_data = {
            "migration_timestamp": datetime.now().isoformat(),
            "policies": [],
            "alert_rules": [],
            "cloud_accounts": [],
            "compliance_standards": prisma_data.get("compliance_standards", [])
        }
        
        # Transform policies
        for policy in prisma_data.get("policies", []):
            try:
                cortex_data["policies"].append(
                    self.transformer.transform_policy(policy)
                )
            except Exception as e:
                logger.warning(f"Failed to transform policy {policy.get('name')}: {e}")
        
        # Transform alert rules
        for rule in prisma_data.get("alert_rules", []):
            try:
                cortex_data["alert_rules"].append(
                    self.transformer.transform_alert_rule(rule)
                )
            except Exception as e:
                logger.warning(f"Failed to transform alert rule {rule.get('name')}: {e}")
        
        # Transform cloud accounts
        for account in prisma_data.get("cloud_accounts", []):
            try:
                cortex_data["cloud_accounts"].append(
                    self.transformer.transform_cloud_account(account)
                )
            except Exception as e:
                logger.warning(f"Failed to transform account {account.get('name')}: {e}")
        
        # Save transformed data
        cortex_file = self.output_dir / "cortex_import_ready.json"
        with open(cortex_file, 'w') as f:
            json.dump(cortex_data, f, indent=2)
        logger.info(f"Transformed data saved to {cortex_file}")
        
        return cortex_data
    
    def generate_migration_report(self, prisma_data: Dict, cortex_data: Dict):
        """Generate a migration summary report"""
        # Generate CSV report
        report_file = self.output_dir / "migration_report.csv"
        
        with open(report_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Category", "Prisma Count", "Cortex Count", "Status"])
            
            writer.writerow([
                "Policies",
                len(prisma_data.get("policies", [])),
                len(cortex_data.get("policies", [])),
                "✓" if len(prisma_data.get("policies", [])) == len(cortex_data.get("policies", [])) else "⚠"
            ])
            
            writer.writerow([
                "Alert Rules",
                len(prisma_data.get("alert_rules", [])),
                len(cortex_data.get("alert_rules", [])),
                "✓" if len(prisma_data.get("alert_rules", [])) == len(cortex_data.get("alert_rules", [])) else "⚠"
            ])
            
            writer.writerow([
                "Cloud Accounts",
                len(prisma_data.get("cloud_accounts", [])),
                len(cortex_data.get("cloud_accounts", [])),
                "✓" if len(prisma_data.get("cloud_accounts", [])) == len(cortex_data.get("cloud_accounts", [])) else "⚠"
            ])
        
        logger.info(f"Migration report saved to {report_file}")

        # Generate HTML Compliance Report
        html_reporter = HTMLReportGenerator(prisma_data, cortex_data, self.output_dir)
        html_reporter.generate()
    
    def run(self):
        """Execute the full migration workflow"""
        logger.info("=" * 60)
        logger.info("Starting Prisma Cloud to Cortex Cloud Migration")
        logger.info("=" * 60)
        
        # Authenticate
        if not self.prisma_client.authenticate():
            logger.error("Authentication failed. Aborting migration.")
            return False
        
        # Export data
        prisma_data = self.export_data()
        
        # Transform data
        cortex_data = self.transform_data(prisma_data)
        
        # Generate report
        self.generate_migration_report(prisma_data, cortex_data)
        
        logger.info("=" * 60)
        logger.info("Migration completed successfully!")
        logger.info(f"Output files saved to: {self.output_dir}")
        logger.info("=" * 60)
        
        return True


def main():
    parser = argparse.ArgumentParser(
        description="Migrate from Prisma Cloud to Cortex Cloud"
    )
    parser.add_argument(
        "--prisma-url",
        required=True,
        help="Prisma Cloud API URL (e.g., https://api.prismacloud.io)"
    )
    parser.add_argument(
        "--access-key",
        required=True,
        help="Prisma Cloud Access Key"
    )
    parser.add_argument(
        "--secret-key",
        required=True,
        help="Prisma Cloud Secret Key"
    )
    parser.add_argument(
        "--output-dir",
        default="./migration_output",
        help="Output directory for migration files"
    )
    
    args = parser.parse_args()
    
    # Create Prisma Cloud client
    prisma_client = PrismaCloudClient(
        api_url=args.prisma_url,
        access_key=args.access_key,
        secret_key=args.secret_key
    )
    
    # Create and run migration tool
    migration_tool = MigrationTool(prisma_client, args.output_dir)
    success = migration_tool.run()
    
    exit(0 if success else 1)


if __name__ == "__main__":
    main()
