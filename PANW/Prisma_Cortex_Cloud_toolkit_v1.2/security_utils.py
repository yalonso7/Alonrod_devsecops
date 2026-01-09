#!/usr/bin/env python3
"""
Security Utilities Module v1.2
Provides comprehensive security functions for OWASP Top 10 and CSA CCM compliance
Enhanced with RBAC, threat detection, secrets management, and monitoring
"""

import ssl
import hashlib
import re
import ipaddress
import uuid
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable
from datetime import datetime, timedelta
from urllib.parse import urlparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import logging
from collections import deque
from threading import Lock

logger = logging.getLogger(__name__)

# Security Configuration
ALLOWED_PRISMA_DOMAINS = [
    'api.prismacloud.io',
    'app.prismacloud.io',
    'console.prismacloud.io'
]

PRIVATE_IP_RANGES = [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '127.0.0.0/8'
]

SENSITIVE_FIELDS = ['password', 'secret', 'token', 'api_key', 'credential', 'access_key', 'secret_key']

# Default security configuration
DEFAULT_SECURITY_CONFIG = {
    'verify_ssl': True,
    'min_tls_version': '1.2',
    'timeout': 30,
    'max_retries': 3,
    'rate_limit': 5,  # requests per second
    'enable_audit_logging': True,
    'encrypt_backups': True,
    'token_ttl': 3600,  # 1 hour
    'max_session_duration': 3600
}


class SecurityAwareException(Exception):
    """Base exception that doesn't leak sensitive information"""
    def __init__(self, message: str, internal_details: str = None):
        self.message = message
        self.internal_details = internal_details  # Log only, don't expose
        super().__init__(self.message)


class TLSAdapter:
    """Custom TLS adapter that enforces TLS 1.2+"""
    @staticmethod
    def create_ssl_context(min_version: str = '1.2'):
        """Create SSL context with TLS version enforcement"""
        context = ssl.create_default_context()
        if min_version == '1.2':
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        elif min_version == '1.3':
            context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        return context


def validate_api_url(url: str) -> bool:
    """Validate API URL against whitelist (SSRF protection)"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return domain in ALLOWED_PRISMA_DOMAINS
    except Exception as e:
        logger.error(f"URL validation failed: {e}")
        return False


def is_private_ip(ip: str) -> bool:
    """Check if IP is in private range (SSRF protection)"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for range_str in PRIVATE_IP_RANGES:
            if ip_obj in ipaddress.ip_network(range_str):
                return True
    except ValueError:
        return False
    return False


def validate_file_path(path: str, allowed_dir: Optional[Path] = None) -> Path:
    """Validate and sanitize file paths (injection protection)"""
    try:
        resolved = Path(path).resolve()
        
        # Check for path traversal
        if '..' in str(resolved):
            raise ValueError(f"Path traversal detected: {path}")
        
        # Check against allowed directory if provided
        if allowed_dir:
            allowed_resolved = Path(allowed_dir).resolve()
            if not str(resolved).startswith(str(allowed_resolved)):
                raise ValueError(f"Path outside allowed directory: {path}")
        
        return resolved
    except Exception as e:
        raise SecurityAwareException(f"Invalid file path", str(e))


def sanitize_policy_name(name: str) -> str:
    """Sanitize policy names to prevent injection"""
    if not name:
        raise ValueError("Policy name cannot be empty")
    
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        raise ValueError("Policy name contains invalid characters. Only alphanumeric, underscore, and hyphen allowed")
    
    if len(name) > 100:
        raise ValueError("Policy name too long (max 100 characters)")
    
    if len(name) < 1:
        raise ValueError("Policy name too short (min 1 character)")
    
    return name


def sanitize_log_data(data: dict) -> dict:
    """Remove sensitive data from logs"""
    sanitized = data.copy()
    for key, value in sanitized.items():
        key_lower = key.lower()
        if any(field in key_lower for field in SENSITIVE_FIELDS):
            sanitized[key] = "***REDACTED***"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_log_data(value)
        elif isinstance(value, list):
            sanitized[key] = [
                sanitize_log_data(item) if isinstance(item, dict) else "***REDACTED***" if any(field in str(item).lower() for field in SENSITIVE_FIELDS) else item
                for item in value
            ]
    return sanitized


class SecureCredentialStore:
    """Secure credential storage and retrieval"""
    
    def __init__(self, key_file: Optional[str] = None, key: Optional[bytes] = None):
        """Initialize credential store with encryption key"""
        if key:
            self.cipher = Fernet(key)
        elif key_file and Path(key_file).exists():
            with open(key_file, 'rb') as f:
                self.cipher = Fernet(f.read())
        else:
            # Generate new key if none provided
            self.cipher = Fernet.generate_key()
            if key_file:
                with open(key_file, 'wb') as f:
                    f.write(self.cipher)
            self.cipher = Fernet(self.cipher)
    
    def encrypt_credential(self, plaintext: str) -> bytes:
        """Encrypt credential"""
        return self.cipher.encrypt(plaintext.encode())
    
    def decrypt_credential(self, ciphertext: bytes) -> str:
        """Decrypt credential"""
        return self.cipher.decrypt(ciphertext).decode()
    
    @staticmethod
    def generate_key_from_password(password: str, salt: Optional[bytes] = None) -> bytes:
        """Generate encryption key from password"""
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key


def verify_file_integrity(file_path: str, expected_hash: Optional[str] = None) -> Tuple[bool, str]:
    """Verify file integrity using SHA-256"""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        calculated_hash = sha256_hash.hexdigest()
        
        if expected_hash:
            return calculated_hash == expected_hash, calculated_hash
        return True, calculated_hash
    except Exception as e:
        logger.error(f"File integrity check failed: {e}")
        return False, ""


def create_backup_with_checksum(data: dict, output_file: str, encrypt: bool = False, cipher: Optional[Fernet] = None) -> str:
    """Create backup with integrity checksum and optional encryption"""
    backup_data = {
        'data': data,
        'metadata': {
            'created': datetime.utcnow().isoformat(),
            'version': '1.2',
            'encrypted': encrypt
        }
    }
    
    json_str = json.dumps(backup_data, indent=2)
    checksum = hashlib.sha256(json_str.encode()).hexdigest()
    backup_data['metadata']['checksum'] = checksum
    
    if encrypt and cipher:
        encrypted_data = cipher.encrypt(json_str.encode())
        with open(output_file, 'wb') as f:
            f.write(encrypted_data)
    else:
        with open(output_file, 'w') as f:
            json.dump(backup_data, f, indent=2)
    
    return checksum


def verify_backup_integrity(backup_file: str, cipher: Optional[Fernet] = None) -> Tuple[bool, dict]:
    """Verify backup file integrity"""
    try:
        if cipher:
            # Encrypted backup
            with open(backup_file, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = cipher.decrypt(encrypted_data)
            backup_data = json.loads(decrypted_data.decode())
        else:
            # Plain backup
            with open(backup_file, 'r') as f:
                backup_data = json.load(f)
        
        expected_checksum = backup_data['metadata'].get('checksum')
        if not expected_checksum:
            return False, {}
        
        # Recalculate checksum
        data_str = json.dumps(backup_data['data'], sort_keys=True)
        calculated_checksum = hashlib.sha256(data_str.encode()).hexdigest()
        
        return calculated_checksum == expected_checksum, backup_data
    except Exception as e:
        logger.error(f"Backup integrity verification failed: {e}")
        return False, {}


class SecureTokenManager:
    """Manage API tokens with expiration"""
    
    def __init__(self, token_ttl: int = 3600):
        self.token_ttl = token_ttl
        self.token = None
        self.token_expiry = None
    
    def set_token(self, token: str):
        """Set token with expiration"""
        self.token = token
        self.token_expiry = datetime.utcnow() + timedelta(seconds=self.token_ttl)
    
    def get_valid_token(self) -> Optional[str]:
        """Get valid token, return None if expired"""
        if self.is_token_expired():
            return None
        return self.token
    
    def is_token_expired(self) -> bool:
        """Check if token is expired"""
        if not self.token or not self.token_expiry:
            return True
        return datetime.utcnow() >= self.token_expiry
    
    def refresh_token(self, refresh_func):
        """Refresh token using provided function"""
        new_token = refresh_func()
        self.set_token(new_token)
        return new_token


class AuthenticationManager:
    """Manage authentication with account lockout protection"""
    
    def __init__(self, max_attempts: int = 5, lockout_duration: int = 900):
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration
        self.failed_attempts = {}  # username -> (count, lockout_until)
    
    def is_locked_out(self, username: str) -> bool:
        """Check if account is locked out"""
        if username not in self.failed_attempts:
            return False
        
        count, lockout_until = self.failed_attempts[username]
        if lockout_until and datetime.utcnow() < lockout_until:
            return True
        
        # Clear lockout if expired
        if lockout_until and datetime.utcnow() >= lockout_until:
            del self.failed_attempts[username]
            return False
        
        return False
    
    def record_failed_attempt(self, username: str):
        """Record failed authentication attempt"""
        if username not in self.failed_attempts:
            self.failed_attempts[username] = [1, None]
        else:
            count, _ = self.failed_attempts[username]
            count += 1
            
            if count >= self.max_attempts:
                lockout_until = datetime.utcnow() + timedelta(seconds=self.lockout_duration)
                self.failed_attempts[username] = [count, lockout_until]
                logger.warning(f"Account {username} locked out until {lockout_until}")
            else:
                self.failed_attempts[username] = [count, None]
    
    def clear_failed_attempts(self, username: str):
        """Clear failed attempts for successful authentication"""
        if username in self.failed_attempts:
            del self.failed_attempts[username]


class RBACManager:
    """Role-Based Access Control Manager - V2 Enhancement"""
    
    def __init__(self, api_client=None):
        self.api_client = api_client
        self.user_permissions = {}
        self._load_permissions()
    
    def _load_permissions(self):
        """Load user permissions from Prisma Cloud API or defaults"""
        if self.api_client:
            try:
                response = self.api_client.session.get(
                    f"{self.api_client.api_url}/api/v1/users/me/permissions",
                    headers=self.api_client._get_auth_headers(),
                    timeout=30
                )
                response.raise_for_status()
                self.user_permissions = response.json()
                logger.info("User permissions loaded from API")
            except Exception as e:
                logger.warning(f"Could not load permissions from API: {e}")
                # Default to read-only
                self.user_permissions = {'permissions': ['read']}
        else:
            # Default permissions if no API client
            self.user_permissions = {'permissions': ['read', 'write']}
    
    def check_permission(self, action: str, resource: str) -> bool:
        """Check if user has permission for action on resource"""
        required_perms = {
            'deploy': ['waas:write', 'policy:write', 'write'],
            'export': ['waas:read', 'policy:read', 'read'],
            'delete': ['waas:delete', 'policy:delete', 'delete'],
            'modify': ['waas:write', 'policy:write', 'write'],
            'read': ['waas:read', 'policy:read', 'read']
        }
        
        user_perms = self.user_permissions.get('permissions', [])
        required = required_perms.get(action, [])
        
        # Check if user has any of the required permissions
        return any(perm in user_perms for perm in required) or 'admin' in user_perms
    
    def require_permission(self, action: str, resource: str):
        """Require permission or raise exception"""
        if not self.check_permission(action, resource):
            raise SecurityAwareException(
                f"Insufficient permissions for {action} on {resource}"
            )


class ThreatDetector:
    """Advanced threat detection and anomaly detection - V2 Enhancement"""
    
    def __init__(self, anomaly_threshold: int = 10, time_window: int = 300):
        self.anomaly_threshold = anomaly_threshold
        self.time_window = time_window
        self.request_history = deque(maxlen=1000)
        self.allowed_endpoints = [
            'policy', 'alert/rule', 'compliance', 'cloud',
            'policies/firewall/app/container',
            'policies/firewall/app/host',
            'policies/firewall/app/serverless'
        ]
        self.lock = Lock()
    
    def record_request(self, request_data: dict):
        """Record API request for analysis"""
        with self.lock:
            self.request_history.append({
                'timestamp': datetime.utcnow(),
                'endpoint': request_data.get('endpoint', ''),
                'method': request_data.get('method', 'GET'),
                'source_ip': request_data.get('source_ip', ''),
                'user': request_data.get('user', '')
            })
    
    def detect_anomalies(self, request_data: dict) -> List[str]:
        """Detect anomalous patterns in requests"""
        anomalies = []
        
        with self.lock:
            # Rate limiting check
            cutoff_time = datetime.utcnow() - timedelta(seconds=self.time_window)
            recent_requests = [
                r for r in self.request_history
                if r['timestamp'] > cutoff_time
            ]
            
            if len(recent_requests) > self.anomaly_threshold:
                anomalies.append("RATE_LIMIT_EXCEEDED")
            
            # Unusual endpoint access
            endpoint = request_data.get('endpoint', '')
            if endpoint and not any(allowed in endpoint for allowed in self.allowed_endpoints):
                anomalies.append("UNAUTHORIZED_ENDPOINT_ACCESS")
            
            # Geographic anomaly (if IP geolocation available)
            source_ip = request_data.get('source_ip')
            if source_ip and self._is_geographic_anomaly(source_ip):
                anomalies.append("GEOGRAPHIC_ANOMALY")
        
        return anomalies
    
    def _is_geographic_anomaly(self, ip: str) -> bool:
        """Check for geographic anomalies (placeholder - implement with geolocation service)"""
        # This would integrate with a geolocation service
        # For now, return False
        return False
    
    def log_threat_event(self, event_type: str, details: dict):
        """Log security threat events"""
        logger.warning(
            f"security_threat_detected",
            extra={
                'event_type': event_type,
                'severity': 'HIGH',
                'details': sanitize_log_data(details),
                'timestamp': datetime.utcnow().isoformat()
            }
        )


class SecretsManager:
    """Unified secrets management interface - V2 Enhancement"""
    
    def __init__(self, provider: str = "env"):
        self.provider = provider
        self.client = self._initialize_client()
    
    def _initialize_client(self):
        """Initialize secrets management client"""
        if self.provider == "vault":
            try:
                import hvac
                vault_url = os.getenv('VAULT_ADDR')
                vault_token = os.getenv('VAULT_TOKEN')
                if vault_url and vault_token:
                    return hvac.Client(url=vault_url, token=vault_token)
            except ImportError:
                logger.warning("HashiCorp Vault client not available")
            except Exception as e:
                logger.warning(f"Failed to initialize Vault client: {e}")
        
        elif self.provider == "aws":
            try:
                import boto3
                return boto3.client('secretsmanager')
            except ImportError:
                logger.warning("AWS SDK not available")
            except Exception as e:
                logger.warning(f"Failed to initialize AWS Secrets Manager: {e}")
        
        elif self.provider == "azure":
            try:
                from azure.identity import DefaultAzureCredential
                from azure.keyvault.secrets import SecretClient
                vault_url = os.getenv('AZURE_KEYVAULT_URL')
                if vault_url:
                    credential = DefaultAzureCredential()
                    return SecretClient(vault_url=vault_url, credential=credential)
            except ImportError:
                logger.warning("Azure SDK not available")
            except Exception as e:
                logger.warning(f"Failed to initialize Azure Key Vault: {e}")
        
        return None  # Fallback to environment variables
    
    def get_secret(self, secret_name: str) -> Optional[str]:
        """Get secret from configured provider"""
        if self.provider == "env":
            return os.getenv(secret_name)
        elif self.provider == "vault" and self.client:
            try:
                response = self.client.secrets.kv.v2.read_secret_version(path=secret_name)
                return response['data']['data']['value']
            except Exception as e:
                logger.error(f"Failed to get secret from Vault: {e}")
                return os.getenv(secret_name)  # Fallback
        elif self.provider == "aws" and self.client:
            try:
                response = self.client.get_secret_value(SecretId=secret_name)
                return response['SecretString']
            except Exception as e:
                logger.error(f"Failed to get secret from AWS: {e}")
                return os.getenv(secret_name)  # Fallback
        elif self.provider == "azure" and self.client:
            try:
                secret = self.client.get_secret(secret_name)
                return secret.value
            except Exception as e:
                logger.error(f"Failed to get secret from Azure: {e}")
                return os.getenv(secret_name)  # Fallback
        
        return os.getenv(secret_name)


class RateLimiter:
    """Rate limiter for API requests - V2 Enhancement"""
    
    def __init__(self, max_calls: int = 5, period: float = 1.0):
        self.max_calls = max_calls
        self.period = period
        self.calls = deque()
        self.lock = Lock()
    
    def __enter__(self):
        """Context manager entry"""
        with self.lock:
            now = time.time()
            # Remove old calls outside the time window
            while self.calls and self.calls[0] < now - self.period:
                self.calls.popleft()
            
            # Check if we've exceeded the limit
            if len(self.calls) >= self.max_calls:
                sleep_time = self.period - (now - self.calls[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    # Remove expired calls after sleep
                    while self.calls and self.calls[0] < time.time() - self.period:
                        self.calls.popleft()
            
            self.calls.append(time.time())
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        pass


class CircuitBreaker:
    """Circuit breaker pattern for resilient API calls - V2 Enhancement"""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.circuit_open = False
        self.circuit_open_until = None
        self.last_failure_time = None
        self.lock = Lock()
    
    def call(self, func: Callable, *args, **kwargs):
        """Execute function with circuit breaker protection"""
        with self.lock:
            if self.circuit_open:
                if self.circuit_open_until and datetime.utcnow() < self.circuit_open_until:
                    raise SecurityAwareException("Circuit breaker is open - service unavailable")
                else:
                    # Try to recover
                    self.circuit_open = False
                    self.failure_count = 0
        
        try:
            result = func(*args, **kwargs)
            # Success - reset failure count
            with self.lock:
                self.failure_count = 0
            return result
        except Exception as e:
            with self.lock:
                self.failure_count += 1
                self.last_failure_time = datetime.utcnow()
                
                if self.failure_count >= self.failure_threshold:
                    self.circuit_open = True
                    self.circuit_open_until = datetime.utcnow() + timedelta(seconds=self.recovery_timeout)
                    logger.error(
                        f"Circuit breaker opened after {self.failure_count} failures",
                        extra={'failure_count': self.failure_count}
                    )
            raise


class MetricsCollector:
    """Collect and export security and performance metrics - V2 Enhancement"""
    
    def __init__(self):
        self.metrics = {
            'api_requests_total': 0,
            'api_requests_failed': 0,
            'authentication_attempts': 0,
            'authentication_failures': 0,
            'deployments_total': 0,
            'deployments_failed': 0,
            'security_events': 0,
            'response_time_avg': 0.0,
            'response_time_sum': 0.0
        }
        self.lock = Lock()
    
    def record_api_request(self, success: bool, duration: float):
        """Record API request metrics"""
        with self.lock:
            self.metrics['api_requests_total'] += 1
            if not success:
                self.metrics['api_requests_failed'] += 1
            
            # Update average response time
            total = self.metrics['api_requests_total']
            self.metrics['response_time_sum'] += duration
            self.metrics['response_time_avg'] = self.metrics['response_time_sum'] / total
    
    def record_authentication(self, success: bool):
        """Record authentication attempt"""
        with self.lock:
            self.metrics['authentication_attempts'] += 1
            if not success:
                self.metrics['authentication_failures'] += 1
    
    def record_deployment(self, success: bool):
        """Record deployment attempt"""
        with self.lock:
            self.metrics['deployments_total'] += 1
            if not success:
                self.metrics['deployments_failed'] += 1
    
    def record_security_event(self):
        """Record security event"""
        with self.lock:
            self.metrics['security_events'] += 1
    
    def get_metrics(self) -> Dict:
        """Get current metrics"""
        with self.lock:
            return self.metrics.copy()
    
    def export_metrics(self, format: str = 'prometheus') -> str:
        """Export metrics in specified format"""
        metrics = self.get_metrics()
        
        if format == 'prometheus':
            lines = []
            for key, value in metrics.items():
                lines.append(f"{key} {value}")
            return "\n".join(lines)
        elif format == 'json':
            return json.dumps(metrics, indent=2)
        else:
            return str(metrics)


def get_security_headers(request_id: Optional[str] = None) -> Dict[str, str]:
    """Get security headers for HTTP requests"""
    if request_id is None:
        request_id = str(uuid.uuid4())
    
    return {
        "User-Agent": "PrismaCloudToolkit/1.2",
        "X-Request-ID": request_id,
        "X-API-Version": "v1",
        "X-Client-Version": "1.2"
    }


def safe_error_response(error: Exception) -> str:
    """Return safe error message without sensitive data"""
    if isinstance(error, SecurityAwareException):
        return error.message
    # Generic message for unknown errors
    return "An error occurred. Please check logs for details."
