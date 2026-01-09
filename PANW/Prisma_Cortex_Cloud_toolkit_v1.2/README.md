# Prisma Cloud Toolkit v1.2

Enhanced security-hardened toolkit for Prisma Cloud operations with comprehensive OWASP Top 10 and CSA CCM v4.0 compliance.

# 🚀 Features

# Core Functionality
- Prisma Cloud to Cortex Cloud Migration: Automated migration of policies, alert rules, and compliance data
- WAAS Policy Deployment: Deploy and manage Web Application and API Security policies
- Compliance Reporting: Advanced compliance analysis with gap detection
- Batch Operations: Parallel processing for improved performance

# Security Enhancements (v1.2)
- ✅ Enhanced RBAC: Role-based access control with permission checks
- ✅ Advanced Threat Detection: Anomaly detection and security event logging
- ✅ Secrets Management: Support for HashiCorp Vault, AWS Secrets Manager, and Azure Key Vault
- ✅ Circuit Breaker Pattern: Resilient API calls with automatic recovery
- ✅ Rate Limiting: Configurable rate limiting for API requests
- ✅ Connection Pooling: Optimized connection management
- ✅ Comprehensive Metrics: Performance and security metrics collection
- ✅ Configuration Management: Centralized configuration with validation

# Security Compliance
- OWASP Top 10 (2021): A01-A10 vulnerabilities addressed
- OWASP API Top 10 (2023): API-specific security controls
- CSA CCM v4.0: Cloud security controls alignment
- PCI DSS 4.0: Payment card industry compliance
- HIPAA: Healthcare data protection
- GDPR: Data privacy compliance

# 📋 Requirements

- Python 3.8+
- Prisma Cloud account with API access
- Required Python packages (see `requirements.txt`)

# 🔧 Installation

1. Clone or download this repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables or use secrets management:
```bash
export PRISMA_ACCESS_KEY="your-access-key"
export PRISMA_SECRET_KEY="your-secret-key"
# OR
export PRISMA_USERNAME="your-username"
export PRISMA_PASSWORD="your-password"
```

# 📖 Usage

# Migration Tool

Migrate policies from Prisma Cloud to Cortex Cloud:

```bash
python PrismaCloud_migrationtool.py \
    --prisma-url https://api.prismacloud.io \
    --output-dir ./migration_output \
    --config config.yaml
```

Options:
- `--prisma-url`: Prisma Cloud API URL (required)
- `--access-key`: Access key (optional, prefer environment variables)
- `--secret-key`: Secret key (optional, prefer environment variables)
- `--output-dir`: Output directory for migration files (default: `./migration_output`)
- `--verify-ssl`: Verify SSL certificates (default: True)
- `--config`: Path to configuration file (YAML or JSON)
- `--export-metrics`: Export performance metrics to file

# WAAS Policy Deployment

Deploy WAAS policies from YAML files:

```bash
python SOC\ SOPs/Prisma_Cortex_Cloud_scripts_v1.2/deploy_waas_script.py \
    https://console.prismacloud.io \
    username \
    password \
    container \
    policy.yaml \
    --config config.yaml
```

Policy Types:
- `container`: For Kubernetes, Docker, ECS containerized applications
- `host`: For VM-based applications (EC2, Azure VMs)
- `serverless`: For serverless functions (Lambda, Azure Functions)
- `app-embedded`: For applications with embedded defenders

Options:
- `--config`: Path to configuration file
- `--export`: Export existing policies instead of deploying
- `--verify-only`: Only verify deployment without deploying
- `--no-verify-ssl`: Disable SSL verification (NOT RECOMMENDED)

# ⚙️ Configuration

Create a `config.yaml` file for centralized configuration:

```yaml
security:
  verify_ssl: true
  min_tls_version: "1.2"
  enable_audit_logging: true
  encrypt_backups: true
  max_session_duration: 3600
  token_ttl: 3600

logging:
  level: "INFO"
  format: "json"
  destination: "file"
  file_path: "logs/security.log"
  retention_days: 90

compliance:
  frameworks:
    - "OWASP_API_TOP10_2023"
    - "CSA_CCM_V4"
    - "PCI_DSS_4"
  auto_report: true
  report_frequency: "weekly"

performance:
  connection_pool_size: 10
  max_workers: 5
  timeout: 30
  rate_limit: 5
```

# 🔐 Secrets Management

# Environment Variables (Default)
```bash
export PRISMA_ACCESS_KEY="your-key"
export PRISMA_SECRET_KEY="your-secret"
```

# HashiCorp Vault
```bash
export SECRETS_PROVIDER="vault"
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="your-vault-token"
```

# AWS Secrets Manager
```bash
export SECRETS_PROVIDER="aws"
# AWS credentials configured via AWS CLI or IAM role
```

# Azure Key Vault
```bash
export SECRETS_PROVIDER="azure"
export AZURE_KEYVAULT_URL="https://your-vault.vault.azure.net"
# Azure credentials via DefaultAzureCredential
```

# 📊 Metrics and Monitoring

The toolkit collects comprehensive metrics:

- API request counts and response times
- Authentication attempts and failures
- Deployment success/failure rates
- Security events and anomalies
- Performance metrics

Metrics can be exported in Prometheus or JSON format:

```python
from PrismaCloud_migrationtool import EnhancedPrismaCloudClient

client = EnhancedPrismaCloudClient(...)
# ... perform operations ...
metrics = client.get_metrics()
print(metrics)
```

# 🧪 Testing

Run the test suite:

```bash
python -m pytest tests/
```

Or run specific tests:

```bash
python tests/test_security_utils.py
```

# 📁 Project Structure

```
Prisma_Cloud_v1.2/
├── PrismaCloud_migrationtool.py    # Main migration tool
├── security_utils.py                # Security utilities
├── config_manager.py               # Configuration management
├── requirements.txt                # Python dependencies
├── README.md                        # This file
├── tests/                           # Test suite
│   └── test_security_utils.py
└── SOC SOPs/
    └── Prisma_Cortex_Cloud_scripts_v1.2/
        └── deploy_waas_script.py     # WAAS deployment script
```

# 🔒 Security Features

# Input Validation
- URL whitelisting (SSRF protection)
- Policy name sanitization
- File path validation
- Input length and character restrictions

# Authentication & Authorization
- Secure token management with expiration
- RBAC permission checks
- Account lockout protection
- Credential encryption support

# Cryptographic Controls
- TLS 1.2+ enforcement
- SSL certificate verification
- Backup encryption
- File integrity checksums

# Logging & Monitoring
- Structured logging with `structlog`
- Sensitive data sanitization
- Security event logging
- Performance metrics collection

# Resilience
- Circuit breaker pattern
- Retry logic with exponential backoff
- Rate limiting
- Connection pooling

# 📝 Compliance Reports

The toolkit generates comprehensive compliance reports:

- OWASP API Top 10 (2023): Coverage analysis for all 10 categories
- CSA CCM v4.0: Control coverage and gap analysis
- PCI DSS 4.0: Payment card industry compliance
- HIPAA: Healthcare compliance
- GDPR: Data privacy compliance

Reports are generated in HTML and JSON formats with:
- Coverage percentages
- Control mapping
- Evidence collection
- Recommendations for improvement

# 🐛 Troubleshooting

# Authentication Failures
- Verify credentials are correct
- Check if account is locked out
- Ensure API access is enabled
- Verify SSL certificate validity

# Permission Errors
- Check RBAC permissions in Prisma Cloud
- Verify user has required roles
- Review API access policies

# Performance Issues
- Adjust `connection_pool_size` in config
- Reduce `max_workers` for parallel operations
- Increase `timeout` values
- Check rate limiting settings

# 📚 Additional Resources

- [Prisma Cloud API Documentation](https://prisma.pan.dev/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CSA CCM v4.0](https://cloudsecurityalliance.org/research/cloud-controls-matrix/)
- [Cortex Cloud Documentation](https://cortex.paloaltonetworks.com/)

# 🤝 Contributing

This toolkit is designed for security teams migrating from Prisma Cloud to Cortex Cloud. When contributing:

1. Follow security best practices
2. Add tests for new features
3. Update documentation
4. Ensure OWASP and CSA CCM compliance

# 📄 License

This toolkit is provided as-is for security operations. Ensure compliance with your organization's policies and applicable regulations.

# 🔄 Version History

# v1.2 (Current)
- Enhanced RBAC implementation
- Advanced threat detection
- Secrets management integration
- Circuit breaker pattern
- Performance optimizations
- Comprehensive metrics collection
- Configuration management system

# v1.1
- Initial security hardening
- Basic RBAC support
- Input validation
- Structured logging
- File integrity checks

# v1.0
- Initial release
- Basic migration functionality
- WAAS deployment support

# ⚠️ Security Notice

This toolkit handles sensitive credentials and security configurations. Always:

- Use secrets management in production
- Enable SSL verification
- Review and audit all operations
- Follow principle of least privilege
- Keep dependencies updated
- Monitor for security events

# 📧 Support

For issues or questions:
1. Review the troubleshooting section
2. Check logs for detailed error messages
3. Verify configuration and credentials
4. Review Prisma Cloud API documentation

---

Version: 1.2  
Last Updated: 2026-01-09  
Security Status: Hardened for OWASP Top 10 and CSA CCM v4.0
