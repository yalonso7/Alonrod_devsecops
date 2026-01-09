# Prisma Cloud WAAS Policy Deployment Toolkit

Complete toolkit for deploying and managing Prisma Cloud Web Application and API Security (WAAS) policies using Infrastructure as Code principles.

# 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Policy Configuration](#policy-configuration)
- [Deployment Methods](#deployment-methods)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)
- [Security Considerations](#security-considerations)

# 🎯 Overview

This toolkit provides:

- Declarative YAML Configuration: Define WAAS policies in human-readable YAML
- Automated Deployment: Deploy policies via Python script or CI/CD pipelines
- Version Control: Track policy changes in Git
- Multi-Environment Support: Separate policies for dev, staging, production
- OWASP Alignment: Pre-configured protection for OWASP API Top 10
- CSA CCM Compliance: Controls mapped to Cloud Security Alliance framework

# ✅ Prerequisites

# Required

- Python 3.7 or higher
- Prisma Cloud Compute (formerly Twistlock) account
- Admin or Security Admin role in Prisma Cloud
- Network access to Prisma Cloud Console

# Optional

- Git for version control
- Docker for containerized deployment
- CI/CD platform (GitHub Actions, GitLab CI, Jenkins)

# 📦 Installation

# Method 1: Basic Installation

```bash
# Clone or download this repository
git clone https://github.com/your-org/prisma-waas-toolkit.git
cd prisma-waas-toolkit

# Install Python dependencies
pip install -r requirements.txt

# Verify installation
python deploy_waas_policy.py --help
```

# Method 2: Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

# Method 3: Docker

```bash
# Build Docker image
docker build -t prisma-waas-deployer .

# Run deployment
docker run -v $(pwd):/workspace prisma-waas-deployer \
  https://console.prismacloud.io \
  admin \
  password \
  container \
  sample-waas-policy.yaml
```

# 🚀 Quick Start

# Step 1: Configure Your Policy

Copy the sample policy and customize it:

```bash
cp sample-waas-policy.yaml my-production-policy.yaml
```

Edit `my-production-policy.yaml` and update:
- Application names in `spec.appScope.applications`
- Rate limits in `spec.rulesets[0].rateLimiting`
- Alert channels in `spec.alerting.channels`
- Security headers
- Custom rules

# Step 2: Test Connection

```bash
# Test authentication
python deploy_waas_policy.py \
  https://your-console.prismacloud.io \
  your-username \
  your-password \
  container \
  --export
```

# Step 3: Deploy Policy

```bash
# Deploy to production
python deploy_waas_policy.py \
  https://your-console.prismacloud.io \
  your-username \
  your-password \
  container \
  my-production-policy.yaml
```

# Step 4: Verify

Check the Prisma Cloud Console:
1. Navigate to Defend → WAAS → Container
2. Verify your policy appears in the list
3. Check the rule configuration matches your YAML

# 📝 Policy Configuration

# Basic Structure

```yaml
apiVersion: waas.prismacloud.io/v1
kind: WAASPolicy

metadata:
  name: my-policy
  description: Policy description

spec:
  appScope:
    applications: ["app1", "app2"]
    environments: ["production"]
  
  rulesets:
    - name: main-ruleset
      httpProtection:
        sqli: prevent
        xss: prevent
      apiProtection:
        enabled: true
      rateLimiting:
        enabled: true
```

# Configuration Sections

| Section | Description | Required |
|---------|-------------|----------|
| `metadata` | Policy name and description | Yes |
| `appScope` | Which apps this policy applies to | Yes |
| `httpProtection` | OWASP Top 10 protections | Recommended |
| `apiProtection` | API-specific security controls | Recommended |
| `rateLimiting` | DoS and rate limit settings | Recommended |
| `botProtection` | Bot detection and mitigation | Optional |
| `customRules` | Organization-specific rules | Optional |
| `accessControl` | IP/geo restrictions | Optional |

# Policy Examples

# Minimal Policy (Alert Only)

```yaml
metadata:
  name: minimal-alert-policy

spec:
  appScope:
    applications: ["*"]
  
  rulesets:
    - name: basic-protection
      httpProtection:
        enabled: true
        sqli: alert
        xss: alert
```

# Production-Ready Policy

See `sample-waas-policy.yaml` for a comprehensive example with:
- All OWASP protections enabled
- Rate limiting configured
- Bot protection active
- Custom rules defined
- Alert channels configured

# API-Focused Policy

```yaml
metadata:
  name: api-security-strict

spec:
  appScope:
    applications: ["api-*"]
  
  rulesets:
    - name: api-protection
      apiProtection:
        enabled: true
        schemaValidation: prevent
        bola: prevent
        bfla: prevent
      
      rateLimiting:
        enabled: true
        perAPIKey:
          limit: 1000
          period: 1m
      
      authentication:
        jwt:
          enabled: true
          strictValidation: true
```

# 🔧 Deployment Methods

# Method 1: Command Line (Manual)

```bash
# Deploy container policy
python deploy_waas_policy.py \
  https://console.prismacloud.io \
  admin \
  $PASSWORD \
  container \
  production-policy.yaml

# Deploy serverless policy
python deploy_waas_policy.py \
  https://console.prismacloud.io \
  admin \
  $PASSWORD \
  serverless \
  lambda-policy.yaml
```

# Method 2: Environment Variables

```bash
# Create .env file
cat > .env << EOF
PRISMA_CONSOLE_URL=https://console.prismacloud.io
PRISMA_USERNAME=admin
PRISMA_PASSWORD=your-secure-password
EOF

# Use in script
export $(cat .env | xargs)
python deploy_waas_policy.py \
  $PRISMA_CONSOLE_URL \
  $PRISMA_USERNAME \
  $PRISMA_PASSWORD \
  container \
  production-policy.yaml
```

# Method 3: CI/CD Pipeline

# GitHub Actions

```yaml
# .github/workflows/deploy-waas.yml
name: Deploy WAAS Policies

on:
  push:
    branches: [main]
    paths: ['policies/']

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Deploy policies
        env:
          PRISMA_URL: ${{ secrets.PRISMA_CONSOLE_URL }}
          PRISMA_USER: ${{ secrets.PRISMA_USERNAME }}
          PRISMA_PASS: ${{ secrets.PRISMA_PASSWORD }}
        run: |
          python deploy_waas_policy.py \
            $PRISMA_URL \
            $PRISMA_USER \
            $PRISMA_PASS \
            container \
            policies/production.yaml
```

# GitLab CI

```yaml
# .gitlab-ci.yml
deploy-waas:
  stage: deploy
  image: python:3.9
  script:
    - pip install -r requirements.txt
    - python deploy_waas_policy.py
        $PRISMA_CONSOLE_URL
        $PRISMA_USERNAME
        $PRISMA_PASSWORD
        container
        policies/production.yaml
  only:
    - main
```

# Method 4: Terraform

```hcl
# waas-deployment.tf
resource "null_resource" "deploy_waas_policy" {
  triggers = {
    policy_hash = filemd5("${path.module}/production-policy.yaml")
  }

  provisioner "local-exec" {
    command = <<EOT
      python deploy_waas_policy.py \
        ${var.prisma_console_url} \
        ${var.prisma_username} \
        ${var.prisma_password} \
        container \
        ${path.module}/production-policy.yaml
    EOT
  }
}
```

# 💡 Examples

# Example 1: Progressive Deployment

```bash
# Week 1: Deploy in alert mode
python deploy_waas_policy.py ... policies/week1-alert.yaml

# Week 2: Enable blocking for critical threats
python deploy_waas_policy.py ... policies/week2-partial-block.yaml

# Week 3: Full enforcement
python deploy_waas_policy.py ... policies/week3-full-enforcement.yaml
```

# Example 2: Multi-Environment

```bash
# Development environment
python deploy_waas_policy.py ... policies/dev-policy.yaml

# Staging environment
python deploy_waas_policy.py ... policies/staging-policy.yaml

# Production environment
python deploy_waas_policy.py ... policies/production-policy.yaml
```

# Example 3: Export and Backup

```bash
# Export existing policies before changes
python deploy_waas_policy.py \
  https://console.prismacloud.io \
  admin \
  $PASSWORD \
  container \
  --export backup-$(date +%Y%m%d).json

# Deploy new policy
python deploy_waas_policy.py ... new-policy.yaml

# If issues, restore from backup using Prisma Cloud UI
```

# 🔍 Troubleshooting

# Common Issues

# Authentication Failures

```
❌ Error: Authentication failed: 401 Client Error
```

Solutions:
- Verify username and password are correct
- Check if account has proper permissions (Admin or Security Admin role)
- Ensure console URL is correct and accessible
- Check if API access is enabled for your account

# YAML Parsing Errors

```
❌ Error: YAML parse error at line 45
```

Solutions:
- Validate YAML syntax using online validator
- Check indentation (use spaces, not tabs)
- Ensure all quotes are properly closed
- Verify list items start with `-`

# Policy Not Applying

```
✓ Policy deployed successfully
✗ Policy 'my-policy' not found after deployment
```

Solutions:
- Check application/collection names match existing resources
- Verify scope configuration in `appScope`
- Check Prisma Cloud Console for error messages
- Review defender logs for connection issues

# Rate Limit Errors

```
❌ Error: 429 Too Many Requests
```

Solutions:
- Wait 60 seconds and retry
- Reduce number of concurrent deployments
- Implement exponential backoff in scripts

# Debug Mode

Enable verbose output:

```bash
# Add debug flag (if implemented)
python deploy_waas_policy.py --debug ...

# Or use Python debugging
python -m pdb deploy_waas_policy.py ...
```

# Getting Help

1. Check Prisma Cloud documentation: https://docs.paloaltonetworks.com/
2. Review API reference: https://pan.dev/prisma-cloud/api/
3. Contact Palo Alto Networks support
4. Check GitHub issues (if open source)

# ✨ Best Practices

# 1. Version Control

```bash
# Initialize Git repository
git init
git add policies/ deploy_waas_policy.py
git commit -m "Initial WAAS policies"

# Create branches for changes
git checkout -b feature/add-rate-limiting
# Make changes
git commit -am "Add rate limiting to production API"
git push origin feature/add-rate-limiting
```

# 2. Testing Strategy

```bash
# Always test in non-production first
python deploy_waas_policy.py ... dev policies/test-policy.yaml

# Monitor for 24-48 hours
# Check false positive rate
# Adjust thresholds

# Then promote to production
python deploy_waas_policy.py ... prod policies/prod-policy.yaml
```

# 3. Gradual Rollout

Start with `alert` mode, gradually move to `prevent`:

```yaml
# Phase 1: Alert only (Week 1-2)
httpProtection:
  sqli: alert
  xss: alert

# Phase 2: Block critical (Week 3-4)
httpProtection:
  sqli: prevent
  xss: alert

# Phase 3: Full enforcement (Week 5+)
httpProtection:
  sqli: prevent
  xss: prevent
```

# 4. Monitoring

```bash
# Set up monitoring for:
# - False positive rate (<5% target)
# - Blocked request volume
# - Policy performance impact
# - Alert fatigue indicators

# Regular reviews
# - Weekly: Review critical alerts
# - Monthly: Policy effectiveness analysis
# - Quarterly: Full policy audit
```

# 5. Documentation

Maintain documentation for:
- Policy change history
- Exception justifications
- Custom rule purposes
- Rate limit rationales
- Alert response procedures

# 🔒 Security Considerations

# Credential Management

❌ Never commit credentials to Git:

```bash
# Add to .gitignore
echo ".env" >> .gitignore
echo "*.password" >> .gitignore
echo "secrets/" >> .gitignore
```

✅ Use secure credential storage:

```bash
# Use environment variables
export PRISMA_PASSWORD=$(security find-generic-password -w -s prisma)

# Use secret managers
export PRISMA_PASSWORD=$(aws secretsmanager get-secret-value --secret-id prisma/password --query SecretString --output text)

# Use CI/CD secrets
# GitHub Secrets, GitLab CI Variables, Azure Key Vault, etc.
```

# Policy Validation

Before deploying:

```bash
# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('policy.yaml'))"

# Test in isolated environment
# Review changes in pull request
# Get security team approval
```

# Audit Trail

```bash
# Keep detailed logs
python deploy_waas_policy.py ... 2>&1 | tee deployment-$(date +%Y%m%d-%H%M%S).log

# Store deployment records
git tag -a v1.2.3 -m "Production deployment 2026-01-08"
git push origin v1.2.3
```

# Least Privilege

- Create dedicated service account for deployments
- Grant minimum required permissions
- Rotate credentials regularly (every 90 days)
- Use access keys instead of passwords when possible
- Enable MFA on admin accounts

# 📚 Additional Resources

- [Prisma Cloud Documentation](https://docs.paloaltonetworks.com/prisma/prisma-cloud)
- [WAAS Configuration Guide](https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin-compute/waas)
- [API Reference](https://pan.dev/prisma-cloud/api/cwpp/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [CSA Cloud Controls Matrix](https://cloudsecurityalliance.org/research/cloud-controls-matrix/)

# 📄 License

[Your License Here]

# 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

# 📞 Support

- Email: security-team@company.com
- Slack: #prisma-cloud-support
- Jira: Create ticket in SEC project
