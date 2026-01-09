#!/usr/bin/env python3
"""
Configuration Management Module v1.2
Centralized configuration management with validation
"""

import yaml
import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, validator
import logging

logger = logging.getLogger(__name__)


class SecurityConfig(BaseModel):
    """Security configuration model"""
    verify_ssl: bool = True
    min_tls_version: str = "1.2"
    enable_audit_logging: bool = True
    encrypt_backups: bool = True
    max_session_duration: int = Field(3600, ge=300, le=86400)
    token_ttl: int = Field(3600, ge=300, le=86400)
    
    @validator('min_tls_version')
    def validate_tls_version(cls, v):
        if v not in ['1.2', '1.3']:
            raise ValueError('TLS version must be 1.2 or 1.3')
        return v


class LoggingConfig(BaseModel):
    """Logging configuration model"""
    level: str = "INFO"
    format: str = "json"
    destination: str = "file"
    file_path: str = "logs/security.log"
    retention_days: int = Field(90, ge=1, le=3650)
    
    @validator('level')
    def validate_level(cls, v):
        if v not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            raise ValueError('Invalid log level')
        return v


class ComplianceConfig(BaseModel):
    """Compliance configuration model"""
    frameworks: list = ["OWASP_API_TOP10_2023", "CSA_CCM_V4", "PCI_DSS_4"]
    auto_report: bool = True
    report_frequency: str = "weekly"
    
    @validator('report_frequency')
    def validate_frequency(cls, v):
        if v not in ['daily', 'weekly', 'monthly']:
            raise ValueError('Report frequency must be daily, weekly, or monthly')
        return v


class PerformanceConfig(BaseModel):
    """Performance configuration model"""
    connection_pool_size: int = Field(10, ge=1, le=100)
    max_workers: int = Field(5, ge=1, le=20)
    timeout: int = Field(30, ge=5, le=300)
    rate_limit: int = Field(5, ge=1, le=100)


class AppConfig(BaseModel):
    """Main application configuration"""
    security: SecurityConfig = SecurityConfig()
    logging: LoggingConfig = LoggingConfig()
    compliance: ComplianceConfig = ComplianceConfig()
    performance: PerformanceConfig = PerformanceConfig()
    
    class Config:
        extra = 'forbid'


class ConfigManager:
    """Configuration manager with validation"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or os.getenv('CONFIG_FILE', 'config.yaml')
        self.config: Optional[AppConfig] = None
        self._load_config()
    
    def _load_config(self):
        """Load configuration from file or environment"""
        config_path = Path(self.config_file)
        
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    if config_path.suffix == '.yaml' or config_path.suffix == '.yml':
                        config_data = yaml.safe_load(f)
                    elif config_path.suffix == '.json':
                        config_data = json.load(f)
                    else:
                        raise ValueError(f"Unsupported config file format: {config_path.suffix}")
                
                self.config = AppConfig(**config_data)
                logger.info(f"Configuration loaded from {config_path}")
            except Exception as e:
                logger.warning(f"Failed to load config file: {e}, using defaults")
                self.config = AppConfig()
        else:
            logger.info("No config file found, using defaults")
            self.config = AppConfig()
        
        # Override with environment variables if present
        self._apply_env_overrides()
    
    def _apply_env_overrides(self):
        """Apply environment variable overrides"""
        if os.getenv('VERIFY_SSL'):
            self.config.security.verify_ssl = os.getenv('VERIFY_SSL').lower() == 'true'
        if os.getenv('LOG_LEVEL'):
            self.config.logging.level = os.getenv('LOG_LEVEL')
        if os.getenv('TIMEOUT'):
            self.config.performance.timeout = int(os.getenv('TIMEOUT'))
    
    def get_config(self) -> AppConfig:
        """Get current configuration"""
        return self.config
    
    def save_config(self, output_file: Optional[str] = None):
        """Save current configuration to file"""
        output_path = Path(output_file or self.config_file)
        config_dict = self.config.dict()
        
        with open(output_path, 'w') as f:
            if output_path.suffix == '.yaml' or output_path.suffix == '.yml':
                yaml.dump(config_dict, f, default_flow_style=False)
            elif output_path.suffix == '.json':
                json.dump(config_dict, f, indent=2)
        
        logger.info(f"Configuration saved to {output_path}")
