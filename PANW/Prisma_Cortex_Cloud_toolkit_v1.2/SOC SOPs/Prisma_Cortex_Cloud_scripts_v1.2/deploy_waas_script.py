#!/usr/bin/env python3
"""
Prisma Cloud WAAS Policy Deployment Tool v1.2
Enhanced with RBAC, threat detection, secrets management, and monitoring
"""

import requests
import json
import yaml
import sys
import os
import ssl
import re
import logging
import structlog
from urllib3.exceptions import InsecureRequestWarning
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
from tenacity import retry, stop_after_attempt, wait_exponential

# Import security utilities
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../'))
    from security_utils import (
        SecurityAwareException, validate_api_url, validate_file_path,
        sanitize_policy_name, sanitize_log_data, SecureTokenManager,
        get_security_headers, safe_error_response, DEFAULT_SECURITY_CONFIG,
        RBACManager, ThreatDetector, SecretsManager, RateLimiter,
        CircuitBreaker, MetricsCollector
    )
    from config_manager import ConfigManager
except ImportError:
    # Fallback if security_utils not available
    SecurityAwareException = Exception
    def validate_api_url(url): return True
    def validate_file_path(path, allowed_dir=None): return Path(path)
    def sanitize_policy_name(name): return name
    def sanitize_log_data(data): return data
    DEFAULT_SECURITY_CONFIG = {'verify_ssl': True, 'timeout': 30}
    RBACManager = None
    ThreatDetector = None
    SecretsManager = None
    RateLimiter = None
    CircuitBreaker = None
    MetricsCollector = None
    ConfigManager = None

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

# Configure logging
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


class EnhancedPrismaCloudWAASDeployer:
    """Enhanced WAAS Deployer with V2 features"""
    
    def __init__(self, console_url: str, username: Optional[str] = None, 
                 password: Optional[str] = None, verify_ssl: bool = True,
                 config=None):
        """
        Initialize the enhanced deployer
        
        Args:
            console_url: Prisma Cloud console URL
            username: Prisma Cloud username (prefer secrets management)
            password: Prisma Cloud password (prefer secrets management)
            verify_ssl: Whether to verify SSL certificates
            config: Application configuration
        """
        # Validate URL (SSRF protection)
        if not validate_api_url(console_url):
            raise SecurityAwareException(
                f"Invalid console URL: {console_url}. URL must be from allowed domains."
            )
        
        self.console_url = console_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.config = config
        
        # Initialize secrets manager
        secrets_provider = os.getenv('SECRETS_PROVIDER', 'env')
        secrets_manager = SecretsManager(provider=secrets_provider) if SecretsManager else None
        
        # Get credentials from secrets manager or environment
        if secrets_manager:
            self.username = username or secrets_manager.get_secret('PRISMA_USERNAME')
            self.password = password or secrets_manager.get_secret('PRISMA_PASSWORD')
        else:
            self.username = username or os.getenv('PRISMA_USERNAME')
            self.password = password or os.getenv('PRISMA_PASSWORD')
        
        if not self.username or not self.password:
            raise SecurityAwareException(
                "Credentials not provided. Set PRISMA_USERNAME and PRISMA_PASSWORD environment variables or use secrets management."
            )
        
        token_ttl = config.security.token_ttl if config else DEFAULT_SECURITY_CONFIG.get('token_ttl', 3600)
        self.token_manager = SecureTokenManager(token_ttl=token_ttl)
        
        # Enhanced session with connection pooling
        self.session = requests.Session()
        pool_size = config.performance.connection_pool_size if config else 10
        adapter = HTTPAdapter(
            pool_connections=pool_size,
            pool_maxsize=pool_size * 2,
            max_retries=3
        )
        self.session.mount('https://', TLSEnforcingAdapter())
        self.session.mount('http://', adapter)
        
        # Add security headers
        self.session.headers.update(get_security_headers())
        
        # Initialize V2 enhancements
        self.rbac_manager = RBACManager(api_client=self) if RBACManager else None
        self.threat_detector = ThreatDetector() if ThreatDetector else None
        self.rate_limiter = RateLimiter(
            max_calls=config.performance.rate_limit if config else 5,
            period=1.0
        ) if RateLimiter else None
        self.circuit_breaker = CircuitBreaker() if CircuitBreaker else None
        self.metrics = MetricsCollector() if MetricsCollector else None
        
        # Authenticate
        print(f"🔐 Authenticating to {self.console_url}...")
        try:
            token = self._authenticate(self.username, self.password)
            self.token_manager.set_token(token)
            print("✓ Authentication successful")
        except Exception as e:
            logger.error(f"Authentication failed: {safe_error_response(e)}")
            raise
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    def _authenticate(self, username: str, password: str) -> str:
        """Authenticate and get API token - Enhanced with retry and metrics"""
        url = f"{self.console_url}/api/v1/authenticate"
        payload = {"username": username, "password": password}
        
        # Record authentication attempt
        if self.metrics:
            self.metrics.record_authentication(False)
        
        try:
            start_time = __import__('datetime').datetime.now()
            
            # Use circuit breaker if available
            if self.circuit_breaker:
                response = self.circuit_breaker.call(
                    self.session.post,
                    url,
                    json=payload,
                    verify=self.verify_ssl,
                    timeout=self.config.performance.timeout if self.config else 30
                )
            else:
                response = self.session.post(
                    url,
                    json=payload,
                    verify=self.verify_ssl,
                    timeout=self.config.performance.timeout if self.config else 30
                )
            
            response.raise_for_status()
            
            token = response.json().get('token')
            if not token:
                raise SecurityAwareException("No token received from authentication")
            
            # Record metrics
            if self.metrics:
                duration = (__import__('datetime').datetime.now() - start_time).total_seconds()
                self.metrics.record_api_request(True, duration)
                self.metrics.record_authentication(True)
            
            return token
        except requests.exceptions.SSLError as e:
            if self.metrics:
                self.metrics.record_authentication(False)
            raise SecurityAwareException("SSL verification failed. This may indicate a security issue.")
        except requests.exceptions.RequestException as e:
            if self.metrics:
                self.metrics.record_authentication(False)
            raise SecurityAwareException(f"Authentication failed: {safe_error_response(e)}")
        except Exception as e:
            if self.metrics:
                self.metrics.record_authentication(False)
            raise SecurityAwareException(f"Unexpected authentication error: {safe_error_response(e)}")
    
    def get_headers(self) -> Dict[str, str]:
        """Return headers with authentication token and security headers"""
        token = self.token_manager.get_valid_token()
        if not token:
            # Token expired, re-authenticate
            token = self._authenticate(self.username, self.password)
            self.token_manager.set_token(token)
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            **get_security_headers()
        }
        return headers
    
    def load_yaml_policy(self, yaml_file: str) -> Dict[str, Any]:
        """Load YAML policy file - Enhanced with validation"""
        print(f"📄 Loading policy from {yaml_file}...")
        
        # Validate file path (injection protection)
        try:
            validated_path = validate_file_path(yaml_file)
        except Exception as e:
            raise SecurityAwareException(f"Invalid file path: {safe_error_response(e)}")
        
        if not validated_path.exists():
            raise FileNotFoundError(f"Policy file not found: {yaml_file}")
        
        try:
            with open(validated_path, 'r', encoding='utf-8') as f:
                yaml_data = yaml.safe_load(f)
            
            if not yaml_data:
                raise SecurityAwareException("Policy file is empty or invalid")
            
            print("✓ YAML loaded successfully")
            return self._convert_to_prisma_format(yaml_data)
        except yaml.YAMLError as e:
            raise SecurityAwareException(f"Invalid YAML format: {safe_error_response(e)}")
        except Exception as e:
            raise SecurityAwareException(f"Failed to load policy: {safe_error_response(e)}")
    
    def _convert_to_prisma_format(self, yaml_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert YAML structure to Prisma Cloud API JSON format"""
        print("🔄 Converting policy to Prisma Cloud format...")
        
        metadata = yaml_data.get('metadata', {})
        spec = yaml_data.get('spec', {})
        
        # Get first ruleset
        ruleset = spec.get('rulesets', [{}])[0]
        
        # Validate and sanitize policy name
        policy_name = metadata.get('name', 'default-rule')
        try:
            policy_name = sanitize_policy_name(policy_name)
        except ValueError as e:
            raise SecurityAwareException(f"Invalid policy name: {e}")
        
        # Build the rule (same as v1.1, but with enhanced validation)
        rule = {
            "name": policy_name,
            "notes": metadata.get('description', ''),
            "previousName": "",
            "collections": self._convert_collections(spec.get('appScope', {})),
            "applicationsSpec": self._convert_applications(spec.get('appScope', {})),
            "certificate": {"encrypted": ""},
            "tlsConfig": {
                "metadata": {"notAfter": "", "issuerName": "", "subjectName": ""},
                "HSTSConfig": {
                    "enabled": False,
                    "maxAgeSeconds": 31536000,
                    "includeSubdomains": False,
                    "preload": False
                },
                "minTLSVersion": "1.2"
            },
            **self._convert_http_protection(ruleset.get('httpProtection', {})),
            "apiSpec": self._convert_api_protection(ruleset.get('apiProtection', {})),
            "dosConfig": self._convert_dos_protection(ruleset.get('rateLimiting', {})),
            "botProtectionSpec": self._convert_bot_protection(ruleset.get('botProtection', {})),
            "customRules": self._convert_custom_rules(ruleset.get('customRules', [])),
            "allowedIPs": ruleset.get('accessControl', {}).get('allowedIPs', []),
            "deniedIPs": ruleset.get('accessControl', {}).get('deniedIPs', []),
            "allowedCountries": ruleset.get('accessControl', {}).get('allowedCountries', []),
            "deniedCountries": ruleset.get('accessControl', {}).get('deniedCountries', []),
            "intelGathering": {
                "infoLeakage": {"effect": "alert", "exceptionFields": []},
                "removeFingerprintsEnabled": True
            },
            "advancedProtection": {
                "effect": ruleset.get('advancedProtection', {}).get('effect', 'alert'),
                "exceptionFields": []
            },
            "headers": [],
            "responseHeaderSpecs": self._convert_response_headers(ruleset.get('securityHeaders', {})),
            "readTimeoutSeconds": 5,
            "writeTimeoutSeconds": 5,
            "idleTimeoutSeconds": 120
        }
        
        print("✓ Conversion complete")
        return {"rules": [rule]}
    
    # Include all the conversion helper methods from v1.1
    def _convert_collections(self, app_scope: Dict[str, Any]) -> List[Dict[str, str]]:
        """Convert appScope to collections format"""
        collections = []
        environments = app_scope.get('environments', [])
        
        for env in environments:
            collections.append({"name": env})
        
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
        
        return {
            "sqlInjection": {"effect": http_protection.get('sqli', 'alert'), "exceptionFields": []},
            "xss": {"effect": http_protection.get('xss', 'alert'), "exceptionFields": []},
            "attackTools": {"effect": http_protection.get('attackTools', 'alert'), "exceptionFields": []},
            "shellshock": {"effect": http_protection.get('shellshock', 'alert'), "exceptionFields": []},
            "malformedReq": {"effect": http_protection.get('malformedRequest', 'alert'), "exceptionFields": []},
            "cmdi": {"effect": http_protection.get('cmdi', 'alert'), "exceptionFields": []},
            "lfi": {"effect": http_protection.get('lfi', 'alert'), "exceptionFields": []},
            "codeInjection": {"effect": http_protection.get('codeInjection', 'alert'), "exceptionFields": []}
        }
    
    def _convert_api_protection(self, api_protection: Dict[str, Any]) -> Dict[str, Any]:
        """Convert API protection settings"""
        if not api_protection.get('enabled', False):
            return {"effect": "disable", "endpoints": [], "paths": [], "skipAPILearning": False, "fallbackEffect": "disable"}
        
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
            return {"enabled": False, "alert": {}, "ban": {}, "matchConditions": []}
        
        per_client = rate_limiting.get('perClient', {})
        if isinstance(per_client, str):
            limit, period = self._parse_rate_limit(per_client)
        else:
            limit = per_client.get('limit', 100)
            period = self._period_to_seconds(per_client.get('period', '1m'))
        
        burst = per_client.get('burst', limit + 50) if isinstance(per_client, dict) else limit + 50
        
        return {
            "enabled": True,
            "alert": {"rate": limit, "burstSize": burst},
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
        """Convert period string to seconds"""
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
                "jsInjectionSpec": {"enabled": False},
                "reCAPTCHASpec": {"enabled": False}
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
                "requestAnomalies": {"threshold": 9, "effect": unknown_bots}
            },
            "sessionValidation": "disable",
            "interstitialPage": mode == "challenge",
            "jsInjectionSpec": {"enabled": mode == "challenge", "timeoutEffect": "disable"},
            "reCAPTCHASpec": {"enabled": False, "siteKey": "", "secretKey": {}, "type": "checkbox", "allSessions": False, "successExpirationHours": 24}
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
            
            conditions = []
            scope = rule.get('scope', 'url')
            pattern = rule.get('pattern', '')
            
            if scope in ['url', 'path']:
                conditions.append({"type": "path", "operator": "contains", "value": pattern})
            elif scope == 'body':
                conditions.append({"type": "requestBody", "operator": "contains", "value": pattern})
            elif scope == 'header':
                conditions.append({"type": "requestHeader", "operator": "contains", "value": pattern})
            
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
            headers.append({"name": header_name, "value": header_value, "action": "add"})
        
        return headers
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    def deploy_policy(self, policy_type: str, policy_data: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy WAAS policy - Enhanced with RBAC, threat detection, and metrics"""
        endpoint_map = {
            'container': '/api/v1/policies/firewall/app/container',
            'host': '/api/v1/policies/firewall/app/host',
            'serverless': '/api/v1/policies/firewall/app/serverless',
            'app-embedded': '/api/v1/policies/firewall/app/app-embedded'
        }
        
        if policy_type not in endpoint_map:
            raise ValueError(f"Invalid policy type: {policy_type}")
        
        # Check RBAC permissions
        if self.rbac_manager:
            self.rbac_manager.require_permission('deploy', endpoint_map[policy_type])
        
        url = f"{self.console_url}{endpoint_map[policy_type]}"
        policy_name = policy_data['rules'][0]['name']
        
        # Validate policy name
        try:
            sanitize_policy_name(policy_name)
        except ValueError as e:
            raise SecurityAwareException(f"Invalid policy name: {e}")
        
        # Threat detection
        request_data = {
            'endpoint': endpoint_map[policy_type],
            'method': 'PUT',
            'user': self.username[:3] + "***" if self.username else "***"
        }
        
        if self.threat_detector:
            self.threat_detector.record_request(request_data)
            anomalies = self.threat_detector.detect_anomalies(request_data)
            if anomalies:
                self.threat_detector.log_threat_event('anomaly_detected', {
                    'anomalies': anomalies,
                    'endpoint': endpoint_map[policy_type]
                })
                if self.metrics:
                    self.metrics.record_security_event()
        
        print(f"📤 Deploying {policy_type} WAAS policy '{policy_name}'...")
        logger.info(f"Deployment started: {policy_type}/{policy_name}")
        
        start_time = __import__('datetime').datetime.now()
        
        # GET existing policies
        try:
            if self.rate_limiter:
                with self.rate_limiter:
                    response = self.session.get(
                        url,
                        headers=self.get_headers(),
                        verify=self.verify_ssl,
                        timeout=self.config.performance.timeout if self.config else 30
                    )
            else:
                response = self.session.get(
                    url,
                    headers=self.get_headers(),
                    verify=self.verify_ssl,
                    timeout=self.config.performance.timeout if self.config else 30
                )
            
            response.raise_for_status()
            existing_policy = response.json()
        except requests.exceptions.RequestException as e:
            if self.metrics:
                duration = (__import__('datetime').datetime.now() - start_time).total_seconds()
                self.metrics.record_api_request(False, duration)
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
            if self.rate_limiter:
                with self.rate_limiter:
                    response = self.session.put(
                        url,
                        headers=self.get_headers(),
                        json=existing_policy,
                        verify=self.verify_ssl,
                        timeout=self.config.performance.timeout if self.config else 30
                    )
            else:
                response = self.session.put(
                    url,
                    headers=self.get_headers(),
                    json=existing_policy,
                    verify=self.verify_ssl,
                    timeout=self.config.performance.timeout if self.config else 30
                )
            
            response.raise_for_status()
            
            # Record metrics
            if self.metrics:
                duration = (__import__('datetime').datetime.now() - start_time).total_seconds()
                self.metrics.record_api_request(True, duration)
                self.metrics.record_deployment(True)
            
            print(f"✓ Policy deployed successfully")
            return response.json()
        except requests.exceptions.RequestException as e:
            if self.metrics:
                duration = (__import__('datetime').datetime.now() - start_time).total_seconds()
                self.metrics.record_api_request(False, duration)
                self.metrics.record_deployment(False)
            raise Exception(f"Failed to deploy policy: {str(e)}")
    
    def verify_deployment(self, policy_type: str, policy_name: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Verify policy was deployed successfully"""
        endpoint_map = {
            'container': '/api/v1/policies/firewall/app/container',
            'host': '/api/v1/policies/firewall/app/host',
            'serverless': '/api/v1/policies/firewall/app/serverless',
            'app-embedded': '/api/v1/policies/firewall/app/app-embedded'
        }
        
        print(f"🔍 Verifying deployment of '{policy_name}'...")
        
        url = f"{self.console_url}{endpoint_map[policy_type]}"
        
        try:
            response = self.session.get(
                url,
                headers=self.get_headers(),
                verify=self.verify_ssl,
                timeout=self.config.performance.timeout if self.config else 30
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.error(f"Verification failed: {safe_error_response(e)}")
            print(f"✗ Verification failed: {safe_error_response(e)}")
            return False, None
        
        policies = response.json()
        for rule in policies.get('rules', []):
            if rule['name'] == policy_name:
                print(f"✓ Policy '{policy_name}' verified successfully")
                return True, rule
        
        print(f"✗ Policy '{policy_name}' not found after deployment")
        return False, None
    
    def export_existing_policy(self, policy_type: str, output_file: str = "exported-policy.json"):
        """Export existing WAAS policies"""
        endpoint_map = {
            'container': '/api/v1/policies/firewall/app/container',
            'host': '/api/v1/policies/firewall/app/host',
            'serverless': '/api/v1/policies/firewall/app/serverless',
            'app-embedded': '/api/v1/policies/firewall/app/app-embedded'
        }
        
        print(f"📥 Exporting {policy_type} policies...")
        
        url = f"{self.console_url}{endpoint_map[policy_type]}"
        
        try:
            output_path = validate_file_path(output_file)
            
            response = self.session.get(
                url,
                headers=self.get_headers(),
                verify=self.verify_ssl,
                timeout=self.config.performance.timeout if self.config else 30
            )
            response.raise_for_status()
            
            data = response.json()
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Policies exported to {output_file}")
            print(f"✓ Policies exported to {output_file}")
        except SecurityAwareException as e:
            logger.error(f"Export failed: {e.message}")
            print(f"✗ Export failed: {e.message}")
        except Exception as e:
            logger.error(f"Export failed: {safe_error_response(e)}")
            print(f"✗ Export failed: {safe_error_response(e)}")
    
    def get_metrics(self) -> Dict:
        """Get current metrics"""
        if self.metrics:
            return self.metrics.get_metrics()
        return {}


# Alias for backward compatibility
PrismaCloudWAASDeployer = EnhancedPrismaCloudWAASDeployer


def main():
    """Main function - Enhanced with configuration management"""
    if len(sys.argv) < 2 or '--help' in sys.argv or '-h' in sys.argv:
        print("""
╔════════════════════════════════════════════════════════════════════════════╗
║      Prisma Cloud WAAS Policy Deployment Tool v1.2                        ║
╚════════════════════════════════════════════════════════════════════════════╝

Usage:
    python deploy_waas_script.py <console_url> <username> <password> <policy_type> <yaml_file>

Options:
    --config FILE     : Path to configuration file
    --export          : Export existing policies
    --verify-only     : Only verify deployment
    --no-verify-ssl   : Disable SSL verification (NOT RECOMMENDED)
    --help            : Show this help message
        """)
        sys.exit(0)
    
    # Load configuration
    config = None
    config_file = None
    if '--config' in sys.argv:
        config_idx = sys.argv.index('--config')
        if config_idx + 1 < len(sys.argv):
            config_file = sys.argv[config_idx + 1]
    
    if ConfigManager and config_file:
        config_manager = ConfigManager(config_file=config_file)
        config = config_manager.get_config()
    elif ConfigManager:
        config_manager = ConfigManager()
        config = config_manager.get_config()
    
    # Parse arguments
    console_url = None
    username = None
    password = None
    policy_type = None
    yaml_file = None
    verify_ssl = True
    
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '--no-verify-ssl':
            verify_ssl = False
            logger.warning("SSL verification disabled - SECURITY RISK")
        elif arg == '--verify-ssl':
            verify_ssl = True
        elif arg == '--config':
            i += 1  # Skip config file path
        elif not console_url and not arg.startswith('-'):
            console_url = arg
        elif not username and not arg.startswith('-') and console_url:
            username = arg
        elif not password and not arg.startswith('-') and username:
            password = arg
        elif not policy_type and not arg.startswith('-') and password:
            policy_type = arg
        elif not yaml_file and not arg.startswith('-') and policy_type:
            yaml_file = arg
        i += 1
    
    if not console_url or not policy_type:
        print("❌ Error: Console URL and policy type are required")
        sys.exit(1)
    
    valid_types = ['container', 'host', 'serverless', 'app-embedded']
    if policy_type not in valid_types:
        print(f"❌ Error: Invalid policy type. Must be one of: {', '.join(valid_types)}")
        sys.exit(1)
    
    try:
        deployer = EnhancedPrismaCloudWAASDeployer(console_url, username, password, verify_ssl=verify_ssl, config=config)
        
        if '--export' in sys.argv:
            export_idx = sys.argv.index('--export')
            output_file = sys.argv[export_idx + 1] if export_idx + 1 < len(sys.argv) else f"{policy_type}-policies-export.json"
            deployer.export_existing_policy(policy_type, output_file)
            sys.exit(0)
        
        if not yaml_file:
            print("❌ Error: YAML file path required")
            sys.exit(1)
        
        policy_data = deployer.load_yaml_policy(yaml_file)
        result = deployer.deploy_policy(policy_type, policy_data)
        
        policy_name = policy_data['rules'][0]['name']
        success, deployed_policy = deployer.verify_deployment(policy_type, policy_name)
        
        if success:
            print("\n" + "="*80)
            print("✅ DEPLOYMENT SUCCESSFUL")
            print("="*80)
            print(f"Policy Name: {policy_name}")
            print(f"Policy Type: {policy_type}")
            
            # Display metrics if available
            metrics = deployer.get_metrics()
            if metrics:
                print(f"\nPerformance Metrics:")
                print(f"  API Requests: {metrics.get('api_requests_total', 0)}")
                print(f"  Deployments: {metrics.get('deployments_total', 0)}")
                print(f"  Avg Response Time: {metrics.get('response_time_avg', 0):.2f}s")
            
            print("="*80)
        else:
            print("\n" + "="*80)
            print("❌ DEPLOYMENT VERIFICATION FAILED")
            print("="*80)
            sys.exit(1)
            
    except SecurityAwareException as e:
        print(f"\n❌ Security Error: {e.message}")
        logger.error(f"Security error: {e.message}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {safe_error_response(e)}")
        logger.error(f"Unexpected error: {safe_error_response(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
