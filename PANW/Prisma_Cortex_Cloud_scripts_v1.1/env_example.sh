# Prisma Cloud WAAS Deployment - Environment Variables Template
# Copy this file to .env and fill in your actual values
# WARNING: Never commit .env file to version control!

# ============================================================================
# PRISMA CLOUD CONFIGURATION
# ============================================================================

# Prisma Cloud Console URL
# Examples:
#   SaaS: https://api.prismacloud.io
#   Self-hosted: https://your-console.company.com
PRISMA_CONSOLE_URL=https://api.prismacloud.io

# Development Environment Credentials
PRISMA_USERNAME_DEV=your-dev-username
PRISMA_PASSWORD_DEV=your-dev-password

# Staging Environment Credentials
PRISMA_USERNAME_STAGING=your-staging-username
PRISMA_PASSWORD_STAGING=your-staging-password

# Production Environment Credentials
PRISMA_USERNAME_PROD=your-prod-username
PRISMA_PASSWORD_PROD=your-prod-password

# ============================================================================
# DEPLOYMENT CONFIGURATION
# ============================================================================

# Target environment (dev, staging, production)
ENVIRONMENT=development

# Policy deployment mode (alert, prevent)
DEPLOYMENT_MODE=alert

# Enable dry run mode (true/false)
DRY_RUN=false

# Enable automatic backup before deployment (true/false)
AUTO_BACKUP=true

# ============================================================================
# NOTIFICATION SETTINGS
# ============================================================================

# Slack webhook URL for notifications
# Get from: https://api.slack.com/messaging/webhooks
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Slack channel for notifications
SLACK_CHANNEL=#security-alerts

# Email addresses for notifications (comma-separated)
NOTIFICATION_EMAIL=security-team@company.com,devops@company.com

# PagerDuty integration key (for critical alerts)
PAGERDUTY_INTEGRATION_KEY=your-pagerduty-key

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

# Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
LOG_LEVEL=INFO

# Log retention period (in days)
LOG_RETENTION_DAYS=90

# Enable detailed logging (true/false)
VERBOSE_LOGGING=false

# ============================================================================
# BACKUP CONFIGURATION
# ============================================================================

# Backup directory
BACKUP_DIR=./backups

# Backup retention period (in days)
BACKUP_RETENTION_DAYS=365

# Compress backups (true/false)
COMPRESS_BACKUPS=true

# ============================================================================
# DOCKER CONFIGURATION (if using Docker deployment)
# ============================================================================

# Docker registry URL
DOCKER_REGISTRY=docker.io

# Docker image name
DOCKER_IMAGE_NAME=prisma-waas-deployer

# Docker image tag
DOCKER_IMAGE_TAG=latest

# ============================================================================
# CI/CD INTEGRATION
# ============================================================================

# GitHub token (for GitHub Actions)
# GITHUB_TOKEN=your-github-token

# GitLab token (for GitLab CI)
# GITLAB_TOKEN=your-gitlab-token

# Jenkins API token
# JENKINS_TOKEN=your-jenkins-token

# Azure DevOps Personal Access Token
# AZURE_DEVOPS_PAT=your-azure-pat

# ============================================================================
# ADVANCED SETTINGS
# ============================================================================

# API request timeout (in seconds)
API_TIMEOUT=30

# API retry attempts on failure
API_RETRY_ATTEMPTS=3

# API retry delay (in seconds)
API_RETRY_DELAY=5

# Maximum concurrent deployments
MAX_CONCURRENT_DEPLOYMENTS=5

# Enable SSL verification (true/false)
# Set to false only for self-signed certificates in non-production
VERIFY_SSL=true

# ============================================================================
# FEATURE FLAGS
# ============================================================================

# Enable experimental features (true/false)
ENABLE_EXPERIMENTAL=false

# Enable automatic rollback on failure (true/false)
AUTO_ROLLBACK=false

# Enable policy validation before deployment (true/false)
VALIDATE_BEFORE_DEPLOY=true

# Enable post-deployment verification (true/false)
POST_DEPLOY_VERIFICATION=true

# ============================================================================
# COMPLIANCE & AUDIT
# ============================================================================

# Enable compliance reporting (true/false)
ENABLE_COMPLIANCE_REPORTING=true

# Compliance frameworks (comma-separated)
# Options: owasp_api_top10, pci_dss, hipaa, gdpr, csa_ccm
COMPLIANCE_FRAMEWORKS=owasp_api_top10,csa_ccm

# Audit log destination
# Options: local, syslog, s3, cloudwatch
AUDIT_LOG_DESTINATION=local

# S3 bucket for audit logs (if using S3)
# AUDIT_LOG_S3_BUCKET=s3://your-bucket/audit-logs/

# Syslog server (if using syslog)
# SYSLOG_SERVER=syslog.company.com:514

# ============================================================================
# PERFORMANCE TUNING
# ============================================================================

# Request rate limit (requests per second)
RATE_LIMIT_RPS=5

# Batch size for bulk operations
BATCH_SIZE=10

# Connection pool size
CONNECTION_POOL_SIZE=10

# ============================================================================
# PROXY CONFIGURATION (if needed)
# ============================================================================

# HTTP proxy
# HTTP_PROXY=http://proxy.company.com:8080

# HTTPS proxy
# HTTPS_PROXY=https://proxy.company.com:8443

# No proxy (comma-separated domains)
# NO_PROXY=localhost,127.0.0.1,.company.com

# ============================================================================
# CLOUD PROVIDER SPECIFIC (optional)
# ============================================================================

# AWS Configuration
# AWS_REGION=us-east-1
# AWS_ACCESS_KEY_ID=your-access-key
# AWS_SECRET_ACCESS_KEY=your-secret-key

# Azure Configuration
# AZURE_SUBSCRIPTION_ID=your-subscription-id
# AZURE_TENANT_ID=your-tenant-id
# AZURE_CLIENT_ID=your-client-id
# AZURE_CLIENT_SECRET=your-client-secret

# GCP Configuration
# GCP_PROJECT_ID=your-project-id
# GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# ============================================================================
# NOTES
# ============================================================================
# 1. Never commit this file with actual credentials
# 2. Use secrets management tools (HashiCorp Vault, AWS Secrets Manager, etc.)
# 3. Rotate credentials regularly (every 90 days minimum)
# 4. Use different credentials for each environment
# 5. Enable MFA for admin accounts
# 6. Follow principle of least privilege
# 7. Monitor for credential exposure in logs
# 8. Use environment-specific .env files (.env.dev, .env.staging, .env.prod)
