#!/usr/bin/env python3
"""
Prisma Cloud to Cortex Cloud Migration Tool
Helps security teams migrate policies, alerts, and compliance data
Security hardened for OWASP Top 10 and CSA CCM compliance
"""

import json
import requests
import argparse
import logging
import structlog
import os
import sys
import re
from typing import Dict, List, Optional
from datetime import datetime
import csv
from pathlib import Path
from urllib.parse import urlparse
import ssl
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

# Import security utilities
try:
    from security_utils import (
        SecurityAwareException, TLSAdapter, validate_api_url,
        sanitize_policy_name, sanitize_log_data, SecureTokenManager,
        verify_file_integrity, create_backup_with_checksum,
        get_security_headers, safe_error_response, DEFAULT_SECURITY_CONFIG
    )
except ImportError:
    # Fallback if security_utils not available
    print("Warning: security_utils module not found. Some security features may be disabled.")
    SecurityAwareException = Exception
    def validate_api_url(url): return True
    def sanitize_policy_name(name): return name
    def sanitize_log_data(data): return data
    DEFAULT_SECURITY_CONFIG = {'verify_ssl': True, 'timeout': 30}

# Configure structured logging
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
)

# Standard logging for compatibility
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
security_logger = structlog.get_logger()


class TLSEnforcingAdapter(HTTPAdapter):
    """HTTP Adapter that enforces TLS 1.2+"""
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)


class PrismaCloudClient:
    """Client for interacting with Prisma Cloud API - Security Hardened"""
    
    def __init__(self, api_url: str, access_key: Optional[str] = None, 
                 secret_key: Optional[str] = None, verify_ssl: bool = True):
        """
        Initialize Prisma Cloud client
        
        Args:
            api_url: Prisma Cloud API URL
            access_key: Access key (prefer environment variables)
            secret_key: Secret key (prefer environment variables)
            verify_ssl: Verify SSL certificates (default: True for security)
        """
        # Validate URL (SSRF protection)
        if not validate_api_url(api_url):
            raise SecurityAwareException(
                f"Invalid API URL: {api_url}. URL must be from allowed domains."
            )
        
        self.api_url = api_url.rstrip('/')
        
        # Get credentials from environment if not provided (more secure)
        self.access_key = access_key or os.getenv('PRISMA_ACCESS_KEY')
        self.secret_key = secret_key or os.getenv('PRISMA_SECRET_KEY')
        
        if not self.access_key or not self.secret_key:
            raise SecurityAwareException(
                "Credentials not provided. Set PRISMA_ACCESS_KEY and PRISMA_SECRET_KEY environment variables."
            )
        
        self.verify_ssl = verify_ssl
        self.token_manager = SecureTokenManager(token_ttl=DEFAULT_SECURITY_CONFIG.get('token_ttl', 3600))
        self.session = requests.Session()
        
        # Enforce TLS 1.2+
        self.session.mount('https://', TLSEnforcingAdapter())
        
        # Add security headers
        self.session.headers.update(get_security_headers())
    
    def authenticate(self) -> bool:
        """Authenticate with Prisma Cloud - Security Hardened"""
        try:
            url = f"{self.api_url}/login"
            payload = {
                "username": self.access_key,
                "password": self.secret_key
            }
            
            # Log authentication attempt (sanitized)
            security_logger.info(
                "authentication_attempt",
                url=self.api_url,
                username=self.access_key[:3] + "***" if self.access_key else "***"
            )
            
            response = self.session.post(
                url, 
                json=payload, 
                timeout=DEFAULT_SECURITY_CONFIG.get('timeout', 30),
                verify=self.verify_ssl
            )
            response.raise_for_status()
            
            token = response.json().get('token')
            if not token:
                raise SecurityAwareException("No token received from authentication")
            
            self.token_manager.set_token(token)
            self.session.headers.update({'x-redlock-auth': token})
            
            # Log successful authentication
            security_logger.info("authentication_success", url=self.api_url)
            logger.info("Successfully authenticated with Prisma Cloud")
            return True
            
        except requests.exceptions.SSLError as e:
            error_msg = "SSL verification failed. This may indicate a security issue."
            security_logger.error("authentication_ssl_error", error=str(e))
            logger.error(error_msg)
            raise SecurityAwareException(error_msg)
        except requests.exceptions.RequestException as e:
            error_msg = "Authentication failed"
            security_logger.error("authentication_failed", error=str(e))
            logger.error(f"{error_msg}: {safe_error_response(e)}")
            return False
        except Exception as e:
            error_msg = "Unexpected authentication error"
            security_logger.error("authentication_error", error=str(e))
            logger.error(f"{error_msg}: {safe_error_response(e)}")
            return False

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers with valid token"""
        token = self.token_manager.get_valid_token()
        if not token:
            # Token expired, re-authenticate
            if not self.authenticate():
                raise SecurityAwareException("Authentication required")
            token = self.token_manager.get_valid_token()
        
        return {
            'x-redlock-auth': token,
            **get_security_headers()
        }
    
    def _paginated_request(self, endpoint: str, params: Dict = None) -> List[Dict]:
        """Helper for paginated requests - Security Hardened"""
        if params is None:
            params = {}
        
        # Validate endpoint to prevent injection
        if not re.match(r'^[a-zA-Z0-9_/]+$', endpoint):
            raise SecurityAwareException(f"Invalid endpoint format: {endpoint}")
            
        limit = 50
        offset = 0
        all_items = []
        
        while True:
            current_params = params.copy()
            current_params.update({'limit': limit, 'offset': offset})
            
            try:
                url = f"{self.api_url}/{endpoint}"
                headers = self._get_auth_headers()
                response = self.session.get(
                    url, 
                    params=current_params, 
                    headers=headers,
                    timeout=DEFAULT_SECURITY_CONFIG.get('timeout', 30),
                    verify=self.verify_ssl
                )
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
                
            except requests.exceptions.RequestException as e:
                error_msg = f"Error fetching {endpoint}"
                security_logger.error("api_request_failed", endpoint=endpoint, error=str(e))
                logger.error(f"{error_msg}: {safe_error_response(e)}")
                if offset == 0:
                    return []
                break
            except Exception as e:
                error_msg = f"Unexpected error fetching {endpoint}"
                security_logger.error("api_error", endpoint=endpoint, error=str(e))
                logger.error(f"{error_msg}: {safe_error_response(e)}")
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
        """Export all data from Prisma Cloud - Security Hardened"""
        logger.info("Starting data export from Prisma Cloud...")
        
        # Log export operation
        security_logger.info("data_export_started", output_dir=str(self.output_dir))
        
        data = {
            "export_timestamp": datetime.now().isoformat(),
            "policies": self.prisma_client.get_policies(),
            "alert_rules": self.prisma_client.get_alert_rules(),
            "compliance_standards": self.prisma_client.get_compliance_standards(),
            "cloud_accounts": self.prisma_client.get_cloud_accounts()
        }
        
        # Save raw export with integrity checksum
        raw_file = self.output_dir / "prisma_export_raw.json"
        try:
            checksum = create_backup_with_checksum(data, str(raw_file), encrypt=False)
            security_logger.info(
                "data_export_completed",
                file=str(raw_file),
                checksum=checksum,
                policies_count=len(data.get('policies', [])),
                alert_rules_count=len(data.get('alert_rules', []))
            )
            logger.info(f"Raw export saved to {raw_file} (checksum: {checksum[:16]}...)")
        except Exception as e:
            security_logger.error("data_export_failed", error=str(e))
            logger.error(f"Failed to save export: {safe_error_response(e)}")
            raise
        
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
        
        # Transform policies with input validation
        for policy in prisma_data.get("policies", []):
            try:
                # Validate policy name
                policy_name = policy.get('name', '')
                if policy_name:
                    sanitized_name = sanitize_policy_name(policy_name)
                    policy['name'] = sanitized_name
                
                cortex_data["policies"].append(
                    self.transformer.transform_policy(policy)
                )
            except ValueError as e:
                # Input validation error
                security_logger.warning("policy_validation_failed", policy_name=policy.get('name'), error=str(e))
                logger.warning(f"Failed to transform policy {policy.get('name')}: {e}")
            except Exception as e:
                security_logger.error("policy_transformation_failed", policy_name=policy.get('name'), error=str(e))
                logger.warning(f"Failed to transform policy {policy.get('name')}: {safe_error_response(e)}")
        
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
        
        # Save transformed data with integrity checksum
        cortex_file = self.output_dir / "cortex_import_ready.json"
        try:
            checksum = create_backup_with_checksum(cortex_data, str(cortex_file), encrypt=False)
            security_logger.info(
                "transformed_data_saved",
                file=str(cortex_file),
                checksum=checksum,
                policies_count=len(cortex_data.get('policies', []))
            )
            logger.info(f"Transformed data saved to {cortex_file} (checksum: {checksum[:16]}...)")
        except Exception as e:
            security_logger.error("save_transformed_data_failed", error=str(e))
            logger.error(f"Failed to save transformed data: {safe_error_response(e)}")
            raise
        
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
        description="Migrate from Prisma Cloud to Cortex Cloud (Security Hardened)"
    )
    parser.add_argument(
        "--prisma-url",
        required=True,
        help="Prisma Cloud API URL (e.g., https://api.prismacloud.io)"
    )
    parser.add_argument(
        "--access-key",
        required=False,
        help="Prisma Cloud Access Key (prefer PRISMA_ACCESS_KEY env var)"
    )
    parser.add_argument(
        "--secret-key",
        required=False,
        help="Prisma Cloud Secret Key (prefer PRISMA_SECRET_KEY env var)"
    )
    parser.add_argument(
        "--output-dir",
        default="./migration_output",
        help="Output directory for migration files"
    )
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        default=True,
        help="Verify SSL certificates (default: True, recommended for security)"
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_false",
        dest="verify_ssl",
        help="Disable SSL verification (NOT RECOMMENDED - security risk)"
    )
    
    args = parser.parse_args()
    
    # Validate output directory
    try:
        output_path = Path(args.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.error(f"Invalid output directory: {e}")
        sys.exit(1)
    
    # Create Prisma Cloud client (credentials from env vars preferred)
    try:
        prisma_client = PrismaCloudClient(
            api_url=args.prisma_url,
            access_key=args.access_key,
            secret_key=args.secret_key,
            verify_ssl=args.verify_ssl
        )
    except SecurityAwareException as e:
        logger.error(f"Security error: {e.message}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to initialize client: {safe_error_response(e)}")
        sys.exit(1)
    
    # Create and run migration tool
    try:
        migration_tool = MigrationTool(prisma_client, args.output_dir)
        success = migration_tool.run()
        
        if success:
            security_logger.info("migration_completed_successfully", output_dir=str(args.output_dir))
        else:
            security_logger.error("migration_failed", output_dir=str(args.output_dir))
        
        exit(0 if success else 1)
    except SecurityAwareException as e:
        logger.error(f"Security error: {e.message}")
        security_logger.error("migration_security_error", error=e.message)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Migration failed: {safe_error_response(e)}")
        security_logger.error("migration_error", error=str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
