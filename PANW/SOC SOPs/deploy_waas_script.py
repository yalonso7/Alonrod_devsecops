#!/usr/bin/env python3
"""
Prisma Cloud WAAS Policy Deployment Tool
=========================================

This script converts YAML policy definitions to Prisma Cloud API format
and deploys them to your Prisma Cloud Console.

Usage:
    python deploy_waas_policy.py <console_url> <username> <password> <policy_type> <yaml_file>

Policy Types:
    - container: For containerized applications (Kubernetes, Docker, ECS)
    - host: For VM-based applications (EC2, Azure VMs)
    - serverless: For serverless functions (Lambda, Azure Functions)
    - app-embedded: For applications with embedded defenders

Example:
    python deploy_waas_policy.py https://console.prismacloud.io admin MyP@ssw0rd container production-policy.yaml

Requirements:
    pip install requests pyyaml
"""

import requests
import json
import yaml
import sys
import os
from urllib3.exceptions import InsecureRequestWarning
from typing import Dict, Any, Optional, List, Tuple

# Disable SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class PrismaCloudWAASDeployer:
    """Handles deployment of WAAS policies to Prisma Cloud"""
    
    def __init__(self, console_url: str, username: str, password: str, verify_ssl: bool = False):
        """
        Initialize the deployer
        
        Args:
            console_url: Prisma Cloud console URL (e.g., https://console.prismacloud.io)
            username: Prisma Cloud username
            password: Prisma Cloud password
            verify_ssl: Whether to verify SSL certificates (default: False)
        """
        self.console_url = console_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.token = None
        self.username = username
        self.password = password
        
        # Authenticate
        print(f"🔐 Authenticating to {self.console_url}...")
        self.token = self._authenticate(username, password)
        print("✓ Authentication successful")
    
    def _authenticate(self, username: str, password: str) -> str:
        """
        Authenticate and get API token
        
        Args:
            username: Prisma Cloud username
            password: Prisma Cloud password
            
        Returns:
            API token string
            
        Raises:
            Exception: If authentication fails
        """
        url = f"{self.console_url}/api/v1/authenticate"
        payload = {"username": username, "password": password}
        
        try:
            response = requests.post(url, json=payload, verify=self.verify_ssl, timeout=30)
            response.raise_for_status()
            return response.json()['token']
        except requests.exceptions.RequestException as e:
            raise Exception(f"Authentication failed: {str(e)}")
    
    def get_headers(self) -> Dict[str, str]:
        """Return headers with authentication token"""
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
    
    def load_yaml_policy(self, yaml_file: str) -> Dict[str, Any]:
        """
        Load YAML policy file and convert to Prisma Cloud format
        
        Args:
            yaml_file: Path to YAML policy file
            
        Returns:
            Policy data in Prisma Cloud API format
        """
        print(f"📄 Loading policy from {yaml_file}...")
        
        if not os.path.exists(yaml_file):
            raise FileNotFoundError(f"Policy file not found: {yaml_file}")
        
        with open(yaml_file, 'r') as f:
            yaml_data = yaml.safe_load(f)
        
        print("✓ YAML loaded successfully")
        return self._convert_to_prisma_format(yaml_data)
    
    def _convert_to_prisma_format(self, yaml_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert YAML structure to Prisma Cloud API JSON format
        
        Args:
            yaml_data: Parsed YAML policy data
            
        Returns:
            Policy in Prisma Cloud API format
        """
        print("🔄 Converting policy to Prisma Cloud format...")
        
        metadata = yaml_data.get('metadata', {})
        spec = yaml_data.get('spec', {})
        
        # Get first ruleset (simplified - could iterate through all)
        ruleset = spec.get('rulesets', [{}])[0]
        
        # Build the rule
        rule = {
            "name": metadata.get('name', 'default-rule'),
            "notes": metadata.get('description', ''),
            "previousName": "",
            
            # Scope/Collections
            "collections": self._convert_collections(spec.get('appScope', {})),
            "applicationsSpec": self._convert_applications(spec.get('appScope', {})),
            
            # Certificate and TLS
            "certificate": {
                "encrypted": ""
            },
            "tlsConfig": {
                "metadata": {
                    "notAfter": "",
                    "issuerName": "",
                    "subjectName": ""
                },
                "HSTSConfig": {
                    "enabled": False,
                    "maxAgeSeconds": 31536000,
                    "includeSubdomains": False,
                    "preload": False
                },
                "minTLSVersion": "1.2"
            },
            
            # HTTP Protection (OWASP Top 10)
            **self._convert_http_protection(ruleset.get('httpProtection', {})),
            
            # API Protection
            "apiSpec": self._convert_api_protection(ruleset.get('apiProtection', {})),
            
            # DoS Protection (includes rate limiting)
            "dosConfig": self._convert_dos_protection(ruleset.get('rateLimiting', {})),
            
            # Bot Protection
            "botProtectionSpec": self._convert_bot_protection(ruleset.get('botProtection', {})),
            
            # Custom Rules
            "customRules": self._convert_custom_rules(ruleset.get('customRules', [])),
            
            # Network Controls
            "allowedIPs": ruleset.get('accessControl', {}).get('allowedIPs', []),
            "deniedIPs": ruleset.get('accessControl', {}).get('deniedIPs', []),
            "allowedCountries": ruleset.get('accessControl', {}).get('allowedCountries', []),
            "deniedCountries": ruleset.get('accessControl', {}).get('deniedCountries', []),
            
            # Intelligence Gathering
            "intelGathering": {
                "infoLeakage": {
                    "effect": "alert",
                    "exceptionFields": []
                },
                "removeFingerprintsEnabled": True
            },
            
            # Advanced Protection
            "advancedProtection": {
                "effect": ruleset.get('advancedProtection', {}).get('effect', 'alert'),
                "exceptionFields": []
            },
            
            # Response headers
            "headers": [],
            "responseHeaderSpecs": self._convert_response_headers(ruleset.get('securityHeaders', {})),
            
            # Timeouts
            "readTimeoutSeconds": 5,
            "writeTimeoutSeconds": 5,
            "idleTimeoutSeconds": 120
        }
        
        print("✓ Conversion complete")
        return {"rules": [rule]}
    
    def _convert_collections(self, app_scope: Dict[str, Any]) -> List[Dict[str, str]]:
        """Convert appScope to collections format"""
        collections = []
        environments = app_scope.get('environments', [])
        
        for env in environments:
            collections.append({"name": env})
        
        # If no environments specified, use applications
        if not collections:
            applications = app_scope.get('applications', [])
            for app in applications:
                collections.append({"name": app})
        
        return collections if collections else [{"name": "*"}]
    
    def _convert_applications(self, app_scope: Dict[str, Any]) -> List[str]:
        """Convert appScope to applicationsSpec format"""
        return app_scope.get('applications', ["*"])
    
    def _convert_http_protection(self, http_protection: Dict[str, Any]) -> Dict[str, Any]:
        """Convert HTTP protection settings"""
        if not http_protection.get('enabled', True):
            return {}
        
        effects = {
            "sqlInjection": {
                "effect": http_protection.get('sqli', 'alert'),
                "exceptionFields": []
            },
            "xss": {
                "effect": http_protection.get('xss', 'alert'),
                "exceptionFields": []
            },
            "attackTools": {
                "effect": http_protection.get('attackTools', 'alert'),
                "exceptionFields": []
            },
            "shellshock": {
                "effect": http_protection.get('shellshock', 'alert'),
                "exceptionFields": []
            },
            "malformedReq": {
                "effect": http_protection.get('malformedRequest', 'alert'),
                "exceptionFields": []
            },
            "cmdi": {
                "effect": http_protection.get('cmdi', 'alert'),
                "exceptionFields": []
            },
            "lfi": {
                "effect": http_protection.get('lfi', 'alert'),
                "exceptionFields": []
            },
            "codeInjection": {
                "effect": http_protection.get('codeInjection', 'alert'),
                "exceptionFields": []
            }
        }
        
        return effects
    
    def _convert_api_protection(self, api_protection: Dict[str, Any]) -> Dict[str, Any]:
        """Convert API protection settings"""
        if not api_protection.get('enabled', False):
            return {
                "effect": "disable",
                "endpoints": [],
                "paths": [],
                "skipAPILearning": False,
                "fallbackEffect": "disable"
            }
        
        return {
            "effect": api_protection.get('schemaValidation', 'alert'),
            "endpoints": [],
            "paths": [],
            "skipAPILearning": not api_protection.get('apiDiscovery', True),
            "fallbackEffect": api_protection.get('fallbackEffect', 'alert')
        }
    
    def _convert_dos_protection(self, rate_limiting: Dict[str, Any]) -> Dict[str, Any]:
        """Convert DoS/Rate limiting settings"""
        if not rate_limiting.get('enabled', False):
            return {
                "enabled": False,
                "alert": {},
                "ban": {},
                "matchConditions": []
            }
        
        # Extract rate limit configuration
        per_client = rate_limiting.get('perClient', {})
        if isinstance(per_client, str):
            # Parse format like "100/m"
            limit, period = self._parse_rate_limit(per_client)
        else:
            limit = per_client.get('limit', 100)
            period = self._period_to_seconds(per_client.get('period', '1m'))
        
        burst = per_client.get('burst', limit + 50) if isinstance(per_client, dict) else limit + 50
        
        return {
            "enabled": True,
            "alert": {
                "rate": limit,
                "burstSize": burst
            },
            "ban": {
                "enabled": True,
                "rate": limit,
                "burstSize": burst,
                "banDurationMinutes": self._duration_to_minutes(
                    per_client.get('banDuration', '30m') if isinstance(per_client, dict) else '30m'
                )
            },
            "matchConditions": []
        }
    
    def _parse_rate_limit(self, rate_str: str) -> Tuple[int, int]:
        """Parse rate limit string like '100/m' to (limit, period_seconds)"""
        parts = rate_str.split('/')
        limit = int(parts[0])
        period = self._period_to_seconds(parts[1]) if len(parts) > 1 else 60
        return limit, period
    
    def _period_to_seconds(self, period: str) -> int:
        """Convert period string to seconds (e.g., '1m' -> 60, '1h' -> 3600)"""
        period = period.strip()
        if period.endswith('s'):
            return int(period[:-1])
        elif period.endswith('m'):
            return int(period[:-1]) * 60
        elif period.endswith('h'):
            return int(period[:-1]) * 3600
        elif period.endswith('d'):
            return int(period[:-1]) * 86400
        else:
            return int(period)
    
    def _duration_to_minutes(self, duration: str) -> int:
        """Convert duration string to minutes"""
        return self._period_to_seconds(duration) // 60
    
    def _convert_bot_protection(self, bot_protection: Dict[str, Any]) -> Dict[str, Any]:
        """Convert bot protection settings"""
        if not bot_protection.get('enabled', False):
            return {
                "userDefinedBots": [],
                "knownBotProtectionsSpec": {},
                "unknownBotProtectionSpec": {},
                "sessionValidation": "disable",
                "interstitialPage": False,
                "jsInjectionSpec": {
                    "enabled": False
                },
                "reCAPTCHASpec": {
                    "enabled": False
                }
            }
        
        mode = bot_protection.get('mode', 'detect')
        unknown_bots = bot_protection.get('unknownBots', 'alert')
        known_bots = bot_protection.get('knownBots', 'allow')
        
        return {
            "userDefinedBots": [],
            "knownBotProtectionsSpec": {
                "searchEngineCrawlers": known_bots,
                "businessAnalytics": known_bots,
                "educational": known_bots,
                "news": known_bots,
                "financial": known_bots,
                "contentFeedClients": known_bots,
                "archiving": known_bots,
                "careerSearch": known_bots,
                "mediaSearch": known_bots
            },
            "unknownBotProtectionSpec": {
                "generic": unknown_bots,
                "webAutomationTools": "prevent" if mode == "block" else unknown_bots,
                "webScrapers": "prevent" if mode == "block" else unknown_bots,
                "apiLibraries": unknown_bots,
                "httpLibraries": unknown_bots,
                "botImpersonation": "prevent" if mode == "block" else unknown_bots,
                "browserImpersonation": "prevent" if mode == "block" else unknown_bots,
                "requestAnomalies": {
                    "threshold": 9,
                    "effect": unknown_bots
                }
            },
            "sessionValidation": "disable",
            "interstitialPage": mode == "challenge",
            "jsInjectionSpec": {
                "enabled": mode == "challenge",
                "timeoutEffect": "disable"
            },
            "reCAPTCHASpec": {
                "enabled": False,
                "siteKey": "",
                "secretKey": {},
                "type": "checkbox",
                "allSessions": False,
                "successExpirationHours": 24
            }
        }
    
    def _convert_custom_rules(self, custom_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert custom rules"""
        converted_rules = []
        
        for rule in custom_rules:
            converted_rule = {
                "_id": rule.get('name', '').replace('-', '_').replace(' ', '_'),
                "action": rule.get('action', 'alert'),
                "effect": rule.get('action', 'alert'),
                "methods": rule.get('methods', ["*"])
            }
            
            # Add conditions based on scope
            conditions = []
            scope = rule.get('scope', 'url')
            pattern = rule.get('pattern', '')
            
            if scope in ['url', 'path']:
                conditions.append({
                    "type": "path",
                    "operator": "contains",
                    "value": pattern
                })
            elif scope == 'body':
                conditions.append({
                    "type": "requestBody",
                    "operator": "contains",
                    "value": pattern
                })
            elif scope == 'header':
                conditions.append({
                    "type": "requestHeader",
                    "operator": "contains",
                    "value": pattern
                })
            
            converted_rule["conditions"] = conditions
            converted_rules.append(converted_rule)
        
        return converted_rules
    
    def _convert_response_headers(self, security_headers: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert security headers configuration"""
        if not security_headers.get('enforcement', {}).get('enabled', False):
            return []
        
        headers = []
        required_headers = security_headers.get('enforcement', {}).get('requiredHeaders', {}).get('response', {})
        
        for header_name, header_value in required_headers.items():
            headers.append({
                "name": header_name,
                "value": header_value,
                "action": "add"
            })
        
        return headers
    
    def deploy_policy(self, policy_type: str, policy_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deploy WAAS policy to Prisma Cloud
        
        Args:
            policy_type: Type of policy (container, host, serverless, app-embedded)
            policy_data: Policy data in Prisma Cloud format
            
        Returns:
            Deployment result
        """
        endpoint_map = {
            'container': '/api/v1/policies/firewall/app/container',
            'host': '/api/v1/policies/firewall/app/host',
            'serverless': '/api/v1/policies/firewall/app/serverless',
            'app-embedded': '/api/v1/policies/firewall/app/app-embedded'
        }
        
        if policy_type not in endpoint_map:
            raise ValueError(f"Invalid policy type: {policy_type}. Must be one of: {', '.join(endpoint_map.keys())}")
        
        url = f"{self.console_url}{endpoint_map[policy_type]}"
        policy_name = policy_data['rules'][0]['name']
        
        print(f"📤 Deploying {policy_type} WAAS policy '{policy_name}'...")
        
        # GET existing policies
        try:
            response = requests.get(url, headers=self.get_headers(), verify=self.verify_ssl, timeout=30)
            response.raise_for_status()
            existing_policy = response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to retrieve existing policies: {str(e)}")
        
        # Check if rule already exists and merge/replace
        rule_exists = False
        
        if 'rules' not in existing_policy:
            existing_policy['rules'] = []
        
        for i, rule in enumerate(existing_policy['rules']):
            if rule['name'] == policy_name:
                print(f"  ℹ Rule '{policy_name}' exists, updating...")
                existing_policy['rules'][i] = policy_data['rules'][0]
                rule_exists = True
                break
        
        if not rule_exists:
            print(f"  ℹ Creating new rule '{policy_name}'...")
            existing_policy['rules'].append(policy_data['rules'][0])
        
        # PUT updated policy
        try:
            response = requests.put(
                url, 
                headers=self.get_headers(), 
                json=existing_policy,
                verify=self.verify_ssl,
                timeout=30
            )
            response.raise_for_status()
            print(f"✓ Policy deployed successfully")
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to deploy policy: {str(e)}")
    
    def verify_deployment(self, policy_type: str, policy_name: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Verify policy was deployed successfully
        
        Args:
            policy_type: Type of policy
            policy_name: Name of the policy to verify
            
        Returns:
            Tuple of (success: bool, deployed_policy: dict or None)
        """
        endpoint_map = {
            'container': '/api/v1/policies/firewall/app/container',
            'host': '/api/v1/policies/firewall/app/host',
            'serverless': '/api/v1/policies/firewall/app/serverless',
            'app-embedded': '/api/v1/policies/firewall/app/app-embedded'
        }
        
        print(f"🔍 Verifying deployment of '{policy_name}'...")
        
        url = f"{self.console_url}{endpoint_map[policy_type]}"
        
        try:
            response = requests.get(url, headers=self.get_headers(), verify=self.verify_ssl, timeout=30)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"✗ Verification failed: {str(e)}")
            return False, None
        
        policies = response.json()
        for rule in policies.get('rules', []):
            if rule['name'] == policy_name:
                print(f"✓ Policy '{policy_name}' verified successfully")
                return True, rule
        
        print(f"✗ Policy '{policy_name}' not found after deployment")
        return False, None
    
    def export_existing_policy(self, policy_type: str, output_file: str = "exported-policy.json"):
        """
        Export existing WAAS policies
        
        Args:
            policy_type: Type of policy to export
            output_file: Output file path
        """
        endpoint_map = {
            'container': '/api/v1/policies/firewall/app/container',
            'host': '/api/v1/policies/firewall/app/host',
            'serverless': '/api/v1/policies/firewall/app/serverless',
            'app-embedded': '/api/v1/policies/firewall/app/app-embedded'
        }
        
        print(f"📥 Exporting {policy_type} policies...")
        
        url = f"{self.console_url}{endpoint_map[policy_type]}"
        
        try:
            response = requests.get(url, headers=self.get_headers(), verify=self.verify_ssl, timeout=30)
            response.raise_for_status()
            
            with open(output_file, 'w') as f:
                json.dump(response.json(), f, indent=2)
            
            print(f"✓ Policies exported to {output_file}")
        except Exception as e:
            print(f"✗ Export failed: {str(e)}")


def print_usage():
    """Print usage information"""
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║             Prisma Cloud WAAS Policy Deployment Tool                       ║
╚════════════════════════════════════════════════════════════════════════════╝

Usage:
    python deploy_waas_policy.py <console_url> <username> <password> <policy_type> <yaml_file>

Arguments:
    console_url    : Prisma Cloud console URL (e.g., https://console.prismacloud.io)
    username       : Prisma Cloud username
    password       : Prisma Cloud password
    policy_type    : Policy type (container, host, serverless, app-embedded)
    yaml_file      : Path to YAML policy file

Options:
    --export       : Export existing policies instead of deploying
    --verify-only  : Only verify deployment without deploying
    --help         : Show this help message

Examples:
    # Deploy container WAAS policy
    python deploy_waas_policy.py https://console.prismacloud.io admin MyP@ss container policy.yaml

    # Deploy serverless WAAS policy
    python deploy_waas_policy.py https://console.prismacloud.io admin MyP@ss serverless lambda-policy.yaml

    # Export existing policies
    python deploy_waas_policy.py https://console.prismacloud.io admin MyP@ss container --export

Policy Types:
    container      : For Kubernetes, Docker, ECS containerized applications
    host           : For VM-based applications (EC2, Azure VMs, GCP Compute)
    serverless     : For serverless functions (Lambda, Azure Functions, Cloud Functions)
    app-embedded   : For applications with embedded defenders

Requirements:
    pip install requests pyyaml
    """)


def main():
    """Main function"""
    if len(sys.argv) < 2 or '--help' in sys.argv or '-h' in sys.argv:
        print_usage()
        sys.exit(0)
    
    if len(sys.argv) < 5:
        print("❌ Error: Insufficient arguments")
        print_usage()
        sys.exit(1)
    
    console_url = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    policy_type = sys.argv[4]
    
    try:
        deployer = PrismaCloudWAASDeployer(console_url, username, password)
        
        # Check for export flag
        if '--export' in sys.argv or (len(sys.argv) > 5 and sys.argv[5] == '--export'):
            output_file = sys.argv[6] if len(sys.argv) > 6 else f"{policy_type}-policies-export.json"
            deployer.export_existing_policy(policy_type, output_file)
            sys.exit(0)
        
        if len(sys.argv) < 6:
            print("❌ Error: YAML file path required")
            print_usage()
            sys.exit(1)
        
        yaml_file = sys.argv[5]
        
        # Load and convert policy
        policy_data = deployer.load_yaml_policy(yaml_file)
        
        # Deploy policy
        result = deployer.deploy_policy(policy_type, policy_data)
        
        # Verify deployment
        policy_name = policy_data['rules'][0]['name']
        success, deployed_policy = deployer.verify_deployment(policy_type, policy_name)
        
        if success:
            print("\n" + "="*80)
            print("✅ DEPLOYMENT SUCCESSFUL")
            print("="*80)
            print(f"Policy Name: {policy_name}")
            print(f"Policy Type: {policy_type}")
            print(f"Collections: {deployed_policy.get('collections', [])}")
            print(f"Applications: {deployed_policy.get('applicationsSpec', [])}")
            print("="*80)
        else:
            print("\n" + "="*80)
            print("❌ DEPLOYMENT VERIFICATION FAILED")
            print("="*80)
            print(f"Policy '{policy_name}' was not found after deployment")
            print("Please check the Prisma Cloud console manually")
            print("="*80)
            sys.exit(1)
            
    except FileNotFoundError as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        print("\nFull error traceback:")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
