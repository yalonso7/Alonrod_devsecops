# Prisma Cloud Toolkit v1.2 - Comprehensive Tool Usage Guide

# Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Tool 1: PrismaCloud Migration Tool](#tool-1-prismacloud-migration-tool)
5. [Tool 2: WAAS Policy Deployment Script](#tool-2-waas-policy-deployment-script)
6. [Tool 3: Batch Deployment Script](#tool-3-batch-deployment-script)
7. [Configuration Management](#configuration-management)
8. [Secrets Management](#secrets-management)
9. [Troubleshooting](#troubleshooting)
10. [Best Practices](#best-practices)

---

# Overview

The Prisma Cloud Toolkit v1.2 provides three main tools for managing Prisma Cloud operations:

1. PrismaCloud Migration Tool - Migrate policies, alerts, and compliance data from Prisma Cloud to Cortex Cloud
2. WAAS Policy Deployment Script - Deploy individual WAAS (Web Application and API Security) policies
3. Batch Deployment Script - Automate deployment of multiple WAAS policies across environments

All tools are security-hardened with OWASP Top 10 and CSA CCM v4.0 compliance features.

---

# Prerequisites

# System Requirements
- Python 3.8 or higher
- pip (Python package manager)
- Bash shell (for batch deployment script)
- Access to Prisma Cloud console/API
- Network access to Prisma Cloud endpoints

# Required Credentials
- Prisma Cloud API credentials (Access Key + Secret Key) OR
- Prisma Cloud console credentials (Username + Password)

# Optional Requirements
- HashiCorp Vault (for secrets management)
- AWS Secrets Manager (for secrets management)
- Azure Key Vault (for secrets management)
- GitLab CI/CD (for automated deployments)

---

# Installation

# Step 1: Clone or Download the Toolkit

```bash
cd Prisma_Cloud_v1.2
```

# Step 2: Install Python Dependencies

```bash
pip install -r requirements.txt
```

# Step 3: Set Up Environment Variables

Create a `.env` file or export environment variables:

```bash
# For Migration Tool
export PRISMA_ACCESS_KEY="your-access-key"
export PRISMA_SECRET_KEY="your-secret-key"

# For WAAS Deployment
export PRISMA_USERNAME="your-username"
export PRISMA_PASSWORD="your-password"
export PRISMA_CONSOLE_URL="https://console.prismacloud.io"

# Optional: Secrets Management
export SECRETS_PROVIDER="vault"  # or "aws", "azure", "env"
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="your-vault-token"
```

# Step 4: Create Configuration File (Optional)

Create `config.yaml`:

```yaml
security:
  verify_ssl: true
  min_tls_version: "1.2"
  enable_audit_logging: true
  token_ttl: 3600

performance:
  connection_pool_size: 10
  max_workers: 5
  timeout: 30
  rate_limit: 5

compliance:
  frameworks:
    - "OWASP_API_TOP10_2023"
    - "CSA_CCM_V4"
    - "PCI_DSS_4"
```

---

# Tool 1: PrismaCloud Migration Tool

# Purpose
Migrates policies, alert rules, compliance standards, and cloud account configurations from Prisma Cloud to Cortex Cloud format.

# Basic Usage

```bash
python PrismaCloud_migrationtool.py \
    --prisma-url https://api.prismacloud.io \
    --output-dir ./migration_output
```

# Command-Line Options

| Option | Required | Description | Example |
|--------|----------|-------------|---------|
| `--prisma-url` | Yes | Prisma Cloud API URL | `https://api.prismacloud.io` |
| `--access-key` | No* | Access key (prefer env var) | `abc123...` |
| `--secret-key` | No* | Secret key (prefer env var) | `xyz789...` |
| `--output-dir` | No | Output directory | `./migration_output` |
| `--verify-ssl` | No | Verify SSL (default: True) | Flag |
| `--no-verify-ssl` | No | Disable SSL verification | Flag |
| `--config` | No | Path to config file | `config.yaml` |
| `--export-metrics` | No | Export performance metrics | Flag |

*Credentials required via environment variables or secrets management if not provided

# Detailed Examples

# Example 1: Basic Migration

```bash
# Set credentials
export PRISMA_ACCESS_KEY="your-key"
export PRISMA_SECRET_KEY="your-secret"

# Run migration
python PrismaCloud_migrationtool.py \
    --prisma-url https://api.prismacloud.io \
    --output-dir ./migration_output
```

Output:
- `prisma_export_raw.json` - Raw exported data with checksum
- `cortex_import_ready.json` - Transformed data ready for Cortex Cloud
- `migration_report.csv` - Summary report
- `migration_compliance_report.html` - HTML compliance report
- `compliance_analysis.json` - Detailed compliance analysis
- `metrics.json` - Performance metrics (if `--export-metrics` used)

# Example 2: Migration with Configuration File

```bash
python PrismaCloud_migrationtool.py \
    --prisma-url https://api.prismacloud.io \
    --config config.yaml \
    --output-dir ./migration_output \
    --export-metrics
```

# Example 3: Migration with Secrets Management

```bash
# Use HashiCorp Vault
export SECRETS_PROVIDER="vault"
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="your-token"

python PrismaCloud_migrationtool.py \
    --prisma-url https://api.prismacloud.io \
    --output-dir ./migration_output
```

# Understanding the Output

# 1. Raw Export (`prisma_export_raw.json`)
Contains all exported data with metadata:
```json
{
  "data": {
    "policies": [...],
    "alert_rules": [...],
    "compliance_standards": [...],
    "cloud_accounts": [...]
  },
  "metadata": {
    "created": "2026-01-09T12:00:00",
    "version": "1.2",
    "checksum": "sha256:abc123..."
  }
}
```

# 2. Transformed Data (`cortex_import_ready.json`)
Data transformed to Cortex Cloud format with validation applied.

# 3. Compliance Report (`migration_compliance_report.html`)
Interactive HTML report showing:
- Policy severity distribution
- Compliance framework coverage
- OWASP API Top 10 analysis
- CSA CCM v4.0 control mapping
- Gap analysis and recommendations

# 4. Metrics (`metrics.json`)
Performance metrics:
```json
{
  "api_requests_total": 150,
  "api_requests_failed": 2,
  "authentication_attempts": 1,
  "response_time_avg": 0.45,
  "security_events": 0
}
```

# Advanced Features

# Parallel Batch Export
The tool automatically uses parallel processing for multiple endpoints when configured:

```yaml
# config.yaml
performance:
  max_workers: 5  # Number of parallel workers
```

# RBAC Enforcement
The tool checks permissions before operations:
- Read operations require `read` or `waas:read` permission
- Write operations require `write` or `waas:write` permission

# Threat Detection
Anomalies are automatically detected and logged:
- Rate limit violations
- Unauthorized endpoint access
- Geographic anomalies

---

# Tool 2: WAAS Policy Deployment Script

# Purpose
Deploys individual WAAS policies from YAML files to Prisma Cloud console.

# Basic Usage

```bash
python SOC\ SOPs/Prisma_Cortex_Cloud_scripts_v1.2/deploy_waas_script.py \
    <console_url> \
    <username> \
    <password> \
    <policy_type> \
    <yaml_file>
```

# Command-Line Arguments

| Position | Required | Description | Example |
|----------|----------|-------------|---------|
| 1 | Yes | Console URL | `https://console.prismacloud.io` |
| 2 | No* | Username | `admin` |
| 3 | No* | Password | `MyP@ssw0rd` |
| 4 | Yes | Policy type | `container`, `host`, `serverless`, `app-embedded` |
| 5 | Yes | YAML policy file | `policy.yaml` |

*Credentials can be provided via environment variables or secrets management

# Command-Line Options

| Option | Description |
|--------|-------------|
| `--config FILE` | Path to configuration file |
| `--export` | Export existing policies instead of deploying |
| `--verify-only` | Only verify deployment without deploying |
| `--no-verify-ssl` | Disable SSL verification (NOT RECOMMENDED) |

# Policy Types

1. container - For Kubernetes, Docker, ECS containerized applications
2. host - For VM-based applications (EC2, Azure VMs, GCP Compute)
3. serverless - For serverless functions (Lambda, Azure Functions, Cloud Functions)
4. app-embedded - For applications with embedded defenders

# Detailed Examples

# Example 1: Deploy Container Policy

```bash
python SOC\ SOPs/Prisma_Cortex_Cloud_scripts_v1.2/deploy_waas_script.py \
    https://console.prismacloud.io \
    admin \
    MyP@ssw0rd \
    container \
    policies/production-api-policy.yaml
```

# Example 2: Deploy with Environment Variables

```bash
export PRISMA_USERNAME="admin"
export PRISMA_PASSWORD="MyP@ssw0rd"

python SOC\ SOPs/Prisma_Cortex_Cloud_scripts_v1.2/deploy_waas_script.py \
    https://console.prismacloud.io \
    "" \
    "" \
    container \
    policies/production-api-policy.yaml
```

# Example 3: Export Existing Policies

```bash
python SOC\ SOPs/Prisma_Cortex_Cloud_scripts_v1.2/deploy_waas_script.py \
    https://console.prismacloud.io \
    admin \
    MyP@ssw0rd \
    container \
    --export \
    exported-policies.json
```

# Example 4: Deploy with Configuration

```bash
python SOC\ SOPs/Prisma_Cortex_Cloud_scripts_v1.2/deploy_waas_script.py \
    https://console.prismacloud.io \
    admin \
    MyP@ssw0rd \
    container \
    policy.yaml \
    --config config.yaml
```

# Policy YAML Format

See `sample_waas_policy.txt` for a complete example. Basic structure:

```yaml
apiVersion: waas.prismacloud.io/v1
kind: WAASPolicy

metadata:
  name: production-api-protection
  description: Production API protection

spec:
  appScope:
    applications:
      - customer-api
      - payment-api
    environments:
      - production
  
  rulesets:
    - name: production-protection
      httpProtection:
        enabled: true
        sqli: prevent
        xss: prevent
      apiProtection:
        enabled: true
        schemaValidation: prevent
      rateLimiting:
        enabled: true
        perClient:
          limit: 100
          period: 1m
```

# Deployment Process

1. Authentication - Authenticates with Prisma Cloud
2. Policy Loading - Loads and validates YAML policy
3. Conversion - Converts YAML to Prisma Cloud API format
4. Validation - Validates policy name and structure
5. RBAC Check - Verifies user has deployment permissions
6. Threat Detection - Monitors for anomalies
7. Deployment - Deploys or updates policy
8. Verification - Verifies deployment success

# Output

Successful deployment shows:
```
🔐 Authenticating to https://console.prismacloud.io...
✓ Authentication successful
📄 Loading policy from policy.yaml...
✓ YAML loaded successfully
🔄 Converting policy to Prisma Cloud format...
✓ Conversion complete
📤 Deploying container WAAS policy 'production-api-protection'...
  ℹ Creating new rule 'production-api-protection'...
✓ Policy deployed successfully
🔍 Verifying deployment of 'production-api-protection'...
✓ Policy 'production-api-protection' verified successfully

================================================================================
✅ DEPLOYMENT SUCCESSFUL
================================================================================
Policy Name: production-api-protection
Policy Type: container
Collections: [{'name': 'production'}]
Applications: ['customer-api', 'payment-api']
================================================================================
```

---

# Tool 3: Batch Deployment Script

# Purpose
Automates deployment of multiple WAAS policies across different environments and policy types.

# Basic Usage

```bash
./SOC\ SOPs/Prisma_Cortex_Cloud_scripts_v1.2/batch_deploy_script.sh \
    -e production
```

# Command-Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--environment` | `-e` | Environment (dev, staging, production) |
| `--dry-run` | `-d` | Show what would be deployed without deploying |
| `--verbose` | `-v` | Enable verbose output |
| `--backup` | `-b` | Backup existing policies before deployment |
| `--help` | `-h` | Show help message |

# Directory Structure

The script expects the following directory structure:

```
policies/
├── dev/
│   ├── container/
│   │   ├── dev-api-policy.yaml
│   │   └── dev-web-policy.yaml
│   ├── host/
│   │   └── dev-vm-policy.yaml
│   └── serverless/
│       └── dev-lambda-policy.yaml
├── staging/
│   ├── container/
│   └── host/
└── production/
    ├── container/
    │   ├── production-api-policy.yaml
    │   └── production-web-policy.yaml
    ├── host/
    └── serverless/
```

# Environment Variables

```bash
export PRISMA_CONSOLE_URL="https://console.prismacloud.io"
export PRISMA_USERNAME="admin"
export PRISMA_PASSWORD="MyP@ssw0rd"
```

# Detailed Examples

# Example 1: Deploy All Production Policies

```bash
# Set environment variables
export PRISMA_CONSOLE_URL="https://console.prismacloud.io"
export PRISMA_USERNAME="admin"
export PRISMA_PASSWORD="MyP@ssw0rd"

# Deploy
./SOC\ SOPs/Prisma_Cortex_Cloud_scripts_v1.2/batch_deploy_script.sh \
    -e production
```

# Example 2: Dry Run for Staging

```bash
./SOC\ SOPs/Prisma_Cortex_Cloud_scripts_v1.2/batch_deploy_script.sh \
    -e staging \
    --dry-run
```

# Example 3: Deploy with Backup and Verbose Output

```bash
./SOC\ SOPs/Prisma_Cortex_Cloud_scripts_v1.2/batch_deploy_script.sh \
    -e production \
    --backup \
    --verbose
```

# Output

The script creates:
- `logs/deployment_YYYYMMDD_HHMMSS.log` - Detailed deployment log
- `backups/{environment}_{policy_type}_{timestamp}.json` - Policy backups (if `--backup` used)

Example output:
```
╔════════════════════════════════════════════════════════════════════╗
║     Prisma Cloud WAAS Batch Deployment Tool v1.2                 ║
╚════════════════════════════════════════════════════════════════════╝

✓ Checking requirements...
✓ All requirements met
✓ Processing container policies...
✓ Deploying production-api-policy (container)...
✓ Successfully deployed: production-api-policy
✓ Processing host policies...
✓ Processing serverless policies...

═══════════════════════════════════════════════════════════
                    Deployment Summary                      
═══════════════════════════════════════════════════════════

Environment:        production
Timestamp:          2026-01-09 12:00:00
Dry Run:            false
Backup:             true

Total Success:      5
Total Failures:     0

Log File:           logs/deployment_20260109_120000.log
Backup Location:    backups/
═══════════════════════════════════════════════════════════
```

# Process Flow

1. Validation - Checks requirements and environment variables
2. Backup - Backs up existing policies (if `--backup` used)
3. Deployment - Deploys policies by type (container, host, serverless, app-embedded)
4. Verification - Verifies each deployment
5. Summary - Generates deployment summary

---

# Configuration Management

# Configuration File Format

Create `config.yaml`:

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

# Using Configuration

```bash
# Migration tool
python PrismaCloud_migrationtool.py \
    --prisma-url https://api.prismacloud.io \
    --config config.yaml

# WAAS deployment
python deploy_waas_script.py \
    ... \
    --config config.yaml
```

---

# Secrets Management

# Environment Variables (Default)

```bash
export PRISMA_ACCESS_KEY="your-key"
export PRISMA_SECRET_KEY="your-secret"
```

# HashiCorp Vault

```bash
export SECRETS_PROVIDER="vault"
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="your-token"

# Secrets stored in Vault at:
# secret/prisma/access_key
# secret/prisma/secret_key
```

# AWS Secrets Manager

```bash
export SECRETS_PROVIDER="aws"
# AWS credentials via AWS CLI or IAM role

# Secrets stored in AWS Secrets Manager:
# prisma-access-key
# prisma-secret-key
```

# Azure Key Vault

```bash
export SECRETS_PROVIDER="azure"
export AZURE_KEYVAULT_URL="https://your-vault.vault.azure.net"
# Azure credentials via DefaultAzureCredential

# Secrets stored in Azure Key Vault:
# PrismaAccessKey
# PrismaSecretKey
```

---

# Troubleshooting

# Common Issues

# 1. Authentication Failures

Error: `Authentication failed`

Solutions:
- Verify credentials are correct
- Check if account is locked out
- Ensure API access is enabled
- Verify SSL certificate validity

# 2. Permission Errors

Error: `Insufficient permissions for deploy`

Solutions:
- Check RBAC permissions in Prisma Cloud
- Verify user has required roles
- Review API access policies

# 3. SSL Verification Errors

Error: `SSL verification failed`

Solutions:
- Verify certificate is valid
- Check system time is correct
- Use `--no-verify-ssl` only for testing (NOT RECOMMENDED)

# 4. Rate Limiting

Error: `Rate limit exceeded`

Solutions:
- Reduce `rate_limit` in config
- Increase delays between requests
- Use batch operations

# 5. File Not Found

Error: `Policy file not found`

Solutions:
- Verify file path is correct
- Check file permissions
- Ensure file exists

# Debug Mode

Enable verbose logging:

```bash
# Python scripts
export PYTHONUNBUFFERED=1
python script.py --verbose

# Bash script
./batch_deploy_script.sh -v
```

# Log Files

- Migration tool: Console output + structured logs
- WAAS deployment: Console output
- Batch deployment: `logs/deployment_*.log`

---

# Best Practices

# Security

1. Never commit credentials - Use environment variables or secrets management
2. Enable SSL verification - Always verify SSL certificates
3. Use RBAC - Implement role-based access control
4. Audit logs - Enable comprehensive audit logging
5. Rotate credentials - Regularly rotate API keys and passwords

# Performance

1. Connection pooling - Use appropriate pool sizes
2. Parallel processing - Use batch operations when possible
3. Rate limiting - Configure appropriate rate limits
4. Caching - Cache authentication tokens

# Operations

1. Test in non-production - Always test in dev/staging first
2. Backup before changes - Always backup before deployments
3. Version control - Keep policies in version control
4. Documentation - Document all custom policies
5. Monitoring - Monitor metrics and logs

# Compliance

1. Regular audits - Run compliance reports regularly
2. Gap analysis - Review and address compliance gaps
3. Evidence collection - Maintain audit trails
4. Framework updates - Keep compliance frameworks updated

---

# Additional Resources

- [Prisma Cloud API Documentation](https://prisma.pan.dev/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CSA CCM v4.0](https://cloudsecurityalliance.org/research/cloud-controls-matrix/)
- [Cortex Cloud Documentation](https://cortex.paloaltonetworks.com/)

---

Version: 1.2  
Last Updated: 2026-01-09  
Support: Review troubleshooting section or check logs for detailed error messages
