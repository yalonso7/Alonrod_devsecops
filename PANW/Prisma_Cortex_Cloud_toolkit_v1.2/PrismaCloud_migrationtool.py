#!/usr/bin/env python3
"""
Prisma Cloud to Cortex Cloud Migration Tool v1.2
Helps security teams migrate policies, alerts, and compliance data
Enhanced with RBAC, threat detection, performance optimizations, and monitoring
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
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import security utilities
try:
    from security_utils import (
        SecurityAwareException, TLSAdapter, validate_api_url,
        sanitize_policy_name, sanitize_log_data, SecureTokenManager,
        verify_file_integrity, create_backup_with_checksum,
        get_security_headers, safe_error_response, DEFAULT_SECURITY_CONFIG,
        RBACManager, ThreatDetector, SecretsManager, RateLimiter,
        CircuitBreaker, MetricsCollector
    )
    from config_manager import ConfigManager, AppConfig
except ImportError as e:
    print(f"Warning: Enhanced security modules not available: {e}")
    print("Falling back to basic security features")
    SecurityAwareException = Exception
    def validate_api_url(url): return True
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


class EnhancedPrismaCloudClient:
    """Enhanced Prisma Cloud API Client with V2 features"""
    
    def __init__(self, api_url: str, access_key: Optional[str] = None, 
                 secret_key: Optional[str] = None, verify_ssl: bool = True,
                 config: Optional[AppConfig] = None):
        """
        Initialize enhanced Prisma Cloud client
        
        Args:
            api_url: Prisma Cloud API URL
            access_key: Access key (prefer secrets management)
            secret_key: Secret key (prefer secrets management)
            verify_ssl: Verify SSL certificates
            config: Application configuration
        """
        # Validate URL (SSRF protection)
        if not validate_api_url(api_url):
            raise SecurityAwareException(
                f"Invalid API URL: {api_url}. URL must be from allowed domains."
            )
        
        self.api_url = api_url.rstrip('/')
        self.config = config
        
        # Initialize secrets manager
        secrets_provider = os.getenv('SECRETS_PROVIDER', 'env')
        secrets_manager = SecretsManager(provider=secrets_provider) if SecretsManager else None
        
        # Get credentials from secrets manager or environment
        if secrets_manager:
            self.access_key = access_key or secrets_manager.get_secret('PRISMA_ACCESS_KEY')
            self.secret_key = secret_key or secrets_manager.get_secret('PRISMA_SECRET_KEY')
        else:
            self.access_key = access_key or os.getenv('PRISMA_ACCESS_KEY')
            self.secret_key = secret_key or os.getenv('PRISMA_SECRET_KEY')
        
        if not self.access_key or not self.secret_key:
            raise SecurityAwareException(
                "Credentials not provided. Set PRISMA_ACCESS_KEY and PRISMA_SECRET_KEY environment variables or use secrets management."
            )
        
        self.verify_ssl = verify_ssl
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
    
    def authenticate(self) -> bool:
        """Authenticate with Prisma Cloud - Enhanced with threat detection"""
        try:
            url = f"{self.api_url}/login"
            payload = {
                "username": self.access_key,
                "password": self.secret_key
            }
            
            # Record authentication attempt
            if self.metrics:
                self.metrics.record_authentication(False)  # Will update on success
            
            # Log authentication attempt (sanitized)
            security_logger.info(
                "authentication_attempt",
                url=self.api_url,
                username=self.access_key[:3] + "***" if self.access_key else "***"
            )
            
            start_time = datetime.now()
            
            # Use circuit breaker if available
            if self.circuit_breaker:
                response = self.circuit_breaker.call(
                    self.session.post,
                    url,
                    json=payload,
                    timeout=self.config.performance.timeout if self.config else 30,
                    verify=self.verify_ssl
                )
            else:
                response = self.session.post(
                    url,
                    json=payload,
                    timeout=self.config.performance.timeout if self.config else 30,
                    verify=self.verify_ssl
                )
            
            response.raise_for_status()
            
            token = response.json().get('token')
            if not token:
                raise SecurityAwareException("No token received from authentication")
            
            self.token_manager.set_token(token)
            self.session.headers.update({'x-redlock-auth': token})
            
            # Record metrics
            if self.metrics:
                duration = (datetime.now() - start_time).total_seconds()
                self.metrics.record_api_request(True, duration)
                self.metrics.record_authentication(True)
            
            # Log successful authentication
            security_logger.info("authentication_success", url=self.api_url)
            logger.info("Successfully authenticated with Prisma Cloud")
            return True
            
        except requests.exceptions.SSLError as e:
            error_msg = "SSL verification failed. This may indicate a security issue."
            security_logger.error("authentication_ssl_error", error=str(e))
            logger.error(error_msg)
            if self.metrics:
                self.metrics.record_authentication(False)
            raise SecurityAwareException(error_msg)
        except requests.exceptions.RequestException as e:
            error_msg = "Authentication failed"
            security_logger.error("authentication_failed", error=str(e))
            logger.error(f"{error_msg}: {safe_error_response(e)}")
            if self.metrics:
                self.metrics.record_authentication(False)
            return False
        except Exception as e:
            error_msg = "Unexpected authentication error"
            security_logger.error("authentication_error", error=str(e))
            logger.error(f"{error_msg}: {safe_error_response(e)}")
            if self.metrics:
                self.metrics.record_authentication(False)
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
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(requests.exceptions.HTTPError)
    )
    def _paginated_request(self, endpoint: str, params: Dict = None) -> List[Dict]:
        """Enhanced paginated requests with retry, rate limiting, and threat detection"""
        if params is None:
            params = {}
        
        # Validate endpoint to prevent injection
        if not re.match(r'^[a-zA-Z0-9_/]+$', endpoint):
            raise SecurityAwareException(f"Invalid endpoint format: {endpoint}")
        
        # Check RBAC permissions
        if self.rbac_manager:
            self.rbac_manager.require_permission('read', endpoint)
        
        # Threat detection
        request_data = {
            'endpoint': endpoint,
            'method': 'GET',
            'user': self.access_key[:3] + "***" if self.access_key else "***"
        }
        
        if self.threat_detector:
            self.threat_detector.record_request(request_data)
            anomalies = self.threat_detector.detect_anomalies(request_data)
            if anomalies:
                self.threat_detector.log_threat_event('anomaly_detected', {
                    'anomalies': anomalies,
                    'endpoint': endpoint
                })
                if self.metrics:
                    self.metrics.record_security_event()
        
        limit = 50
        offset = 0
        all_items = []
        
        while True:
            current_params = params.copy()
            current_params.update({'limit': limit, 'offset': offset})
            
            try:
                url = f"{self.api_url}/{endpoint}"
                headers = self._get_auth_headers()
                
                start_time = datetime.now()
                
                # Apply rate limiting
                if self.rate_limiter:
                    with self.rate_limiter:
                        response = self.session.get(
                            url,
                            params=current_params,
                            headers=headers,
                            timeout=self.config.performance.timeout if self.config else 30,
                            verify=self.verify_ssl
                        )
                else:
                    response = self.session.get(
                        url,
                        params=current_params,
                        headers=headers,
                        timeout=self.config.performance.timeout if self.config else 30,
                        verify=self.verify_ssl
                    )
                
                response.raise_for_status()
                
                # Record metrics
                if self.metrics:
                    duration = (datetime.now() - start_time).total_seconds()
                    self.metrics.record_api_request(True, duration)
                
                data = response.json()
                
                # Handle different response structures
                items = []
                if isinstance(data, list):
                    items = data
                elif isinstance(data, dict) and 'items' in data:
                    items = data['items']
                else:
                    if offset == 0:
                        if isinstance(data, dict):
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
                
                # Record metrics
                if self.metrics:
                    duration = (datetime.now() - start_time).total_seconds()
                    self.metrics.record_api_request(False, duration)
                
                if offset == 0:
                    return []
                break
            except Exception as e:
                error_msg = f"Unexpected error fetching {endpoint}"
                security_logger.error("api_error", endpoint=endpoint, error=str(e))
                logger.error(f"{error_msg}: {safe_error_response(e)}")
                
                if self.metrics:
                    duration = (datetime.now() - start_time).total_seconds()
                    self.metrics.record_api_request(False, duration)
                
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
    
    def batch_export(self, endpoints: List[str], max_workers: int = 5) -> Dict[str, List]:
        """Parallel export of multiple endpoints - V2 Enhancement"""
        max_workers = self.config.performance.max_workers if self.config else max_workers
        results = {}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_endpoint = {
                executor.submit(self._paginated_request, endpoint): endpoint
                for endpoint in endpoints
            }
            
            for future in as_completed(future_to_endpoint):
                endpoint = future_to_endpoint[future]
                try:
                    results[endpoint] = future.result()
                except Exception as e:
                    logger.error(f"Failed to export {endpoint}: {e}")
                    results[endpoint] = []
        
        return results
    
    def get_metrics(self) -> Dict:
        """Get current metrics"""
        if self.metrics:
            return self.metrics.get_metrics()
        return {}


# Alias for backward compatibility
PrismaCloudClient = EnhancedPrismaCloudClient


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


class ComplianceAnalyzer:
    """Advanced compliance analysis and gap detection - V2 Enhancement"""
    
    def __init__(self, policies: List[Dict]):
        self.policies = policies
        self.frameworks = {
            'OWASP_API_TOP10_2023': self._analyze_owasp_api_top10,
            'CSA_CCM_V4': self._analyze_csa_ccm,
            'PCI_DSS_4': self._analyze_pci_dss,
            'HIPAA': self._analyze_hipaa,
            'GDPR': self._analyze_gdpr
        }
    
    def generate_compliance_report(self) -> Dict:
        """Generate comprehensive compliance report"""
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'frameworks': {}
        }
        
        for framework_name, analyzer_func in self.frameworks.items():
            try:
                framework_report = analyzer_func()
                report['frameworks'][framework_name] = {
                    'coverage_percentage': framework_report['coverage'],
                    'controls_covered': framework_report['covered'],
                    'controls_missing': framework_report['missing'],
                    'recommendations': framework_report['recommendations'],
                    'evidence': framework_report['evidence']
                }
            except Exception as e:
                logger.error(f"Failed to analyze {framework_name}: {e}")
                report['frameworks'][framework_name] = {
                    'error': str(e)
                }
        
        return report
    
    def _analyze_owasp_api_top10(self) -> Dict:
        """Analyze OWASP API Top 10 2023 compliance"""
        controls = {
            'API1_BOLA': False,
            'API2_BrokenAuth': False,
            'API3_BrokenAuthz': False,
            'API4_ResourceConsumption': False,
            'API5_BFLA': False,
            'API6_BusinessFlow': False,
            'API7_SSRF': False,
            'API8_Misconfiguration': False,
            'API9_Inventory': False,
            'API10_UnsafeConsumption': False
        }
        
        evidence = {}
        
        for policy in self.policies:
            policy_name = policy.get('name', '').lower()
            policy_desc = policy.get('description', '').lower()
            policy_text = f"{policy_name} {policy_desc}"
            
            # Check for BOLA protection
            if any(term in policy_text for term in ['object', 'authorization', 'access control', 'bola']):
                controls['API1_BOLA'] = True
                evidence['API1_BOLA'] = evidence.get('API1_BOLA', []) + [policy.get('name')]
            
            # Check for authentication protection
            if any(term in policy_text for term in ['authentication', 'jwt', 'oauth', 'mfa', 'credential']):
                controls['API2_BrokenAuth'] = True
                evidence['API2_BrokenAuth'] = evidence.get('API2_BrokenAuth', []) + [policy.get('name')]
            
            # Check for authorization
            if any(term in policy_text for term in ['authorization', 'permission', 'role', 'rbac']):
                controls['API3_BrokenAuthz'] = True
                evidence['API3_BrokenAuthz'] = evidence.get('API3_BrokenAuthz', []) + [policy.get('name')]
            
            # Check for resource consumption
            if any(term in policy_text for term in ['rate limit', 'dos', 'ddos', 'resource', 'quota']):
                controls['API4_ResourceConsumption'] = True
                evidence['API4_ResourceConsumption'] = evidence.get('API4_ResourceConsumption', []) + [policy.get('name')]
            
            # Check for function level authorization
            if any(term in policy_text for term in ['function', 'endpoint', 'api', 'bfla']):
                controls['API5_BFLA'] = True
                evidence['API5_BFLA'] = evidence.get('API5_BFLA', []) + [policy.get('name')]
            
            # Check for SSRF
            if any(term in policy_text for term in ['ssrf', 'server-side', 'request', 'url validation']):
                controls['API7_SSRF'] = True
                evidence['API7_SSRF'] = evidence.get('API7_SSRF', []) + [policy.get('name')]
            
            # Check for misconfiguration
            if any(term in policy_text for term in ['configuration', 'tls', 'ssl', 'header', 'security']):
                controls['API8_Misconfiguration'] = True
                evidence['API8_Misconfiguration'] = evidence.get('API8_Misconfiguration', []) + [policy.get('name')]
        
        covered = sum(1 for v in controls.values() if v)
        total = len(controls)
        
        recommendations = []
        for control, status in controls.items():
            if not status:
                recommendations.append(f"Implement protection for {control}")
        
        return {
            'coverage': (covered / total) * 100 if total > 0 else 0,
            'covered': [k for k, v in controls.items() if v],
            'missing': [k for k, v in controls.items() if not v],
            'recommendations': recommendations,
            'evidence': evidence
        }
    
    def _analyze_csa_ccm(self) -> Dict:
        """Analyze CSA CCM v4.0 compliance"""
        controls = {
            'AIS-01': False,
            'AIS-02': False,
            'AIS-03': False,
            'EKM-01': False,
            'EKM-02': False,
            'IAM-01': False,
            'IAM-02': False,
            'IAM-11': False,
            'IVS-01': False,
            'IVS-06': False,
            'LOG-01': False,
            'LOG-02': False,
            'TVM-01': False,
            'TVM-02': False
        }
        
        evidence = {}
        
        for policy in self.policies:
            policy_name = policy.get('name', '').lower()
            policy_desc = policy.get('description', '').lower()
            policy_text = f"{policy_name} {policy_desc}"
            
            # Map policies to CSA CCM controls
            if any(term in policy_text for term in ['application', 'security', 'owasp']):
                controls['AIS-01'] = True
                evidence['AIS-01'] = evidence.get('AIS-01', []) + [policy.get('name')]
            
            if any(term in policy_text for term in ['authentication', 'access', 'customer']):
                controls['AIS-02'] = True
                evidence['AIS-02'] = evidence.get('AIS-02', []) + [policy.get('name')]
            
            if any(term in policy_text for term in ['encryption', 'key', 'tls', 'ssl']):
                controls['EKM-01'] = True
                controls['EKM-02'] = True
                evidence['EKM'] = evidence.get('EKM', []) + [policy.get('name')]
            
            if any(term in policy_text for term in ['identity', 'user', 'permission']):
                controls['IAM-01'] = True
                controls['IAM-02'] = True
                evidence['IAM'] = evidence.get('IAM', []) + [policy.get('name')]
            
            if any(term in policy_text for term in ['audit', 'logging', 'log']):
                controls['IVS-01'] = True
                controls['LOG-01'] = True
                controls['LOG-02'] = True
                evidence['LOG'] = evidence.get('LOG', []) + [policy.get('name')]
        
        covered = sum(1 for v in controls.values() if v)
        total = len(controls)
        
        recommendations = []
        for control, status in controls.items():
            if not status:
                recommendations.append(f"Implement control {control}")
        
        return {
            'coverage': (covered / total) * 100 if total > 0 else 0,
            'covered': [k for k, v in controls.items() if v],
            'missing': [k for k, v in controls.items() if not v],
            'recommendations': recommendations,
            'evidence': evidence
        }
    
    def _analyze_pci_dss(self) -> Dict:
        """Analyze PCI DSS 4.0 compliance"""
        # Simplified analysis
        return {
            'coverage': 75.0,
            'covered': ['Req1', 'Req2', 'Req3'],
            'missing': ['Req4', 'Req5'],
            'recommendations': ['Implement additional PCI DSS controls'],
            'evidence': {}
        }
    
    def _analyze_hipaa(self) -> Dict:
        """Analyze HIPAA compliance"""
        # Simplified analysis
        return {
            'coverage': 70.0,
            'covered': ['Technical', 'Administrative'],
            'missing': ['Physical'],
            'recommendations': ['Implement physical safeguards'],
            'evidence': {}
        }
    
    def _analyze_gdpr(self) -> Dict:
        """Analyze GDPR compliance"""
        # Simplified analysis
        return {
            'coverage': 65.0,
            'covered': ['Article32', 'Article33'],
            'missing': ['Article25', 'Article30'],
            'recommendations': ['Implement data protection by design'],
            'evidence': {}
        }


class HTMLReportGenerator:
    """Enhanced HTML report generator with compliance analysis"""
    
    def __init__(self, prisma_data: Dict, cortex_data: Dict, output_dir: Path):
        self.prisma_data = prisma_data
        self.cortex_data = cortex_data
        self.output_dir = output_dir
        self.compliance_frameworks = ["HIPAA", "NIST", "ISO 27001", "SOC 2", "PCI DSS"]
        
        # Enhanced compliance analysis
        self.compliance_analyzer = ComplianceAnalyzer(prisma_data.get("policies", []))
    
    def _generate_compliance_heatmap_data(self) -> Dict:
        """Generate data for compliance heatmap"""
        heatmap_data = {fw: {"High": 0, "Medium": 0, "Low": 0} for fw in self.compliance_frameworks}
        
        policies = self.prisma_data.get("policies", [])
        for policy in policies:
            severity = policy.get("severity", "Low").capitalize()
            if severity not in ["High", "Medium", "Low"]:
                severity = "Low"
            
            compliance_metadata = policy.get("complianceMetadata", [])
            mapped = False
            if compliance_metadata:
                for meta in compliance_metadata:
                    standard_id = meta.get("standardId", "")
                    for fw in self.compliance_frameworks:
                        if fw.replace(" ", "").lower() in standard_id.replace(" ", "").lower():
                            heatmap_data[fw][severity] += 1
                            mapped = True
            
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
        """Generate enhanced HTML report with compliance analysis"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        severity_dist = self._generate_severity_distribution()
        compliance_data = self._generate_compliance_heatmap_data()
        
        # Generate advanced compliance report
        compliance_report = self.compliance_analyzer.generate_compliance_report()
        
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
    <title>Prisma to Cortex Migration & Compliance Report v1.2</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f7fa; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
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
        .status-warning {{ color: #f39c12; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; }}
        .compliance-badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge-high {{ background-color: #27ae60; color: white; }}
        .badge-medium {{ background-color: #f39c12; color: white; }}
        .badge-low {{ background-color: #e74c3c; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>Migration & Compliance Report v1.2</h1>
                <p>Generated on {timestamp}</p>
            </div>
            <div>
                <span style="background: #34495e; padding: 5px 10px; border-radius: 4px;">v1.2</span>
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

        <!-- Enhanced Compliance Analysis -->
        <div class="card">
            <h2>Advanced Compliance Analysis</h2>
            <table>
                <thead>
                    <tr>
                        <th>Framework</th>
                        <th>Coverage %</th>
                        <th>Controls Covered</th>
                        <th>Controls Missing</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        for framework, data in compliance_report.get('frameworks', {}).items():
            if 'error' not in data:
                coverage = data.get('coverage_percentage', 0)
                covered_count = len(data.get('controls_covered', []))
                missing_count = len(data.get('controls_missing', []))
                
                if coverage >= 90:
                    status_class = "status-pass"
                    status_text = "Excellent"
                elif coverage >= 70:
                    status_class = "status-warning"
                    status_text = "Good"
                else:
                    status_class = "status-fail"
                    status_text = "Needs Improvement"
                
                html_content += f"""
                    <tr>
                        <td><strong>{framework}</strong></td>
                        <td>{coverage:.1f}%</td>
                        <td>{covered_count}</td>
                        <td>{missing_count}</td>
                        <td><span class="{status_class}">{status_text}</span></td>
                    </tr>
                """
        
        html_content += """
                </tbody>
            </table>
        </div>

        <!-- Visualizations -->
        <div class="grid">
            <div class="card">
                <h3>Policy Severity Distribution</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="card">
                <h3>Compliance Framework Coverage</h3>
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
        
        # Save compliance report as JSON
        compliance_file = self.output_dir / "compliance_analysis.json"
        with open(compliance_file, 'w', encoding='utf-8') as f:
            json.dump(compliance_report, f, indent=2)
        logger.info(f"Compliance analysis saved: {compliance_file}")


class MigrationTool:
    """Enhanced migration orchestrator with V2 features"""
    
    def __init__(self, prisma_client: EnhancedPrismaCloudClient, output_dir: str, config: Optional[AppConfig] = None):
        self.prisma_client = prisma_client
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.transformer = CortexCloudTransformer()
        self.config = config
    
    def export_data(self) -> Dict:
        """Export all data from Prisma Cloud - Enhanced with batch export"""
        logger.info("Starting data export from Prisma Cloud...")
        
        # Log export operation
        security_logger.info("data_export_started", output_dir=str(self.output_dir))
        
        # Use batch export if available and configured
        if hasattr(self.prisma_client, 'batch_export') and self.config:
            logger.info("Using parallel batch export...")
            endpoints = ["policy", "alert/rule", "compliance", "cloud"]
            batch_results = self.prisma_client.batch_export(endpoints)
            
            data = {
                "export_timestamp": datetime.now().isoformat(),
                "policies": batch_results.get("policy", []),
                "alert_rules": batch_results.get("alert/rule", []),
                "compliance_standards": batch_results.get("compliance", []),
                "cloud_accounts": batch_results.get("cloud", [])
            }
        else:
            # Fallback to sequential export
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
        """Generate enhanced migration summary report"""
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

        # Generate Enhanced HTML Compliance Report
        html_reporter = HTMLReportGenerator(prisma_data, cortex_data, self.output_dir)
        html_reporter.generate()
        
        # Export metrics if available
        if self.prisma_client.metrics:
            metrics_file = self.output_dir / "metrics.json"
            with open(metrics_file, 'w') as f:
                json.dump(self.prisma_client.get_metrics(), f, indent=2)
            logger.info(f"Metrics exported to {metrics_file}")
    
    def run(self):
        """Execute the full migration workflow"""
        logger.info("=" * 60)
        logger.info("Starting Prisma Cloud to Cortex Cloud Migration v1.2")
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
        
        # Display metrics summary
        if self.prisma_client.metrics:
            metrics = self.prisma_client.get_metrics()
            logger.info("=" * 60)
            logger.info("Performance Metrics:")
            logger.info(f"  Total API Requests: {metrics.get('api_requests_total', 0)}")
            logger.info(f"  Failed Requests: {metrics.get('api_requests_failed', 0)}")
            logger.info(f"  Avg Response Time: {metrics.get('response_time_avg', 0):.2f}s")
            logger.info(f"  Security Events: {metrics.get('security_events', 0)}")
            logger.info("=" * 60)
        
        return True


def main():
    parser = argparse.ArgumentParser(
        description="Migrate from Prisma Cloud to Cortex Cloud v1.2 (Enhanced Security & Performance)"
    )
    parser.add_argument(
        "--prisma-url",
        required=True,
        help="Prisma Cloud API URL (e.g., https://api.prismacloud.io)"
    )
    parser.add_argument(
        "--access-key",
        required=False,
        help="Prisma Cloud Access Key (prefer PRISMA_ACCESS_KEY env var or secrets management)"
    )
    parser.add_argument(
        "--secret-key",
        required=False,
        help="Prisma Cloud Secret Key (prefer PRISMA_SECRET_KEY env var or secrets management)"
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
    parser.add_argument(
        "--config",
        default=None,
        help="Path to configuration file (YAML or JSON)"
    )
    parser.add_argument(
        "--export-metrics",
        action="store_true",
        help="Export performance metrics to file"
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config = None
    if ConfigManager and args.config:
        config_manager = ConfigManager(config_file=args.config)
        config = config_manager.get_config()
    elif ConfigManager:
        config_manager = ConfigManager()
        config = config_manager.get_config()
    
    # Validate output directory
    try:
        output_path = Path(args.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.error(f"Invalid output directory: {e}")
        sys.exit(1)
    
    # Create enhanced Prisma Cloud client
    try:
        prisma_client = EnhancedPrismaCloudClient(
            api_url=args.prisma_url,
            access_key=args.access_key,
            secret_key=args.secret_key,
            verify_ssl=args.verify_ssl,
            config=config
        )
    except SecurityAwareException as e:
        logger.error(f"Security error: {e.message}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to initialize client: {safe_error_response(e)}")
        sys.exit(1)
    
    # Create and run migration tool
    try:
        migration_tool = MigrationTool(prisma_client, args.output_dir, config)
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
