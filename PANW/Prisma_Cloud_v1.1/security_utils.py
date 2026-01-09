#!/usr/bin/env python3
"""
Security Utilities Module
Provides security functions for OWASP Top 10 and CSA CCM compliance
"""

import ssl
import hashlib
import re
import ipaddress
import uuid
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from urllib.parse import urlparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import logging

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
            'version': '1.0',
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


def get_security_headers(request_id: Optional[str] = None) -> Dict[str, str]:
    """Get security headers for HTTP requests"""
    if request_id is None:
        request_id = str(uuid.uuid4())
    
    return {
        "User-Agent": "PrismaCloudToolkit/2.0",
        "X-Request-ID": request_id,
        "X-API-Version": "v1",
        "X-Client-Version": "2.0"
    }


def safe_error_response(error: Exception) -> str:
    """Return safe error message without sensitive data"""
    if isinstance(error, SecurityAwareException):
        return error.message
    # Generic message for unknown errors
    return "An error occurred. Please check logs for details."


