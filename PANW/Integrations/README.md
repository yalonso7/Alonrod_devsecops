# SOC Integrations Directory

This directory contains integration code snippets, configurations, and documentation for connecting Palo Alto Networks security products (Cortex XDR, XSOAR, Prisma Cloud) with third-party SOC tools and platforms.

# Contents

- SOC_Integrations_SOP.md - Comprehensive Standard Operating Procedure with code snippets for all integrations
- integrations_config.yaml - Configuration template for all integrations
- QUICK_REFERENCE.md - Quick reference guide for common integration patterns

# Supported Integrations

# Palo Alto Networks Products
- ✅ Cortex XDR
- ✅ Cortex XSOAR
- ✅ Prisma Cloud

# Security Scanning Tools
- ✅ SonarQube
- ✅ Snyk

# SIEM and Logging
- ✅ Splunk (HEC and Search API)
- ⚠️ Elasticsearch (template provided)
- ⚠️ QRadar (template provided)

# ITSM and Ticketing
- ✅ ServiceNow
- ✅ Jira

# Communication and Collaboration
- ✅ Slack
- ⚠️ Microsoft Teams (template provided)
- ✅ PagerDuty

# Additional Integrations
- ⚠️ Salesforce (template provided)
- ⚠️ GitHub (template provided)
- ⚠️ Azure DevOps (template provided)

# Quick Start

1. Review the SOP: Read `SOC_Integrations_SOP.md` for detailed integration code
2. Configure: Copy `integrations_config.yaml` and fill in your values
3. Set Environment Variables: Export required credentials
4. Use Quick Reference: Refer to `QUICK_REFERENCE.md` for common patterns

# Usage Example

```python
from integrations import CortexXDRClient, XSOARClient, SlackClient

# Initialize clients
xdr = CortexXDRClient(
    api_key=os.getenv("XDR_API_KEY"),
    api_key_id=os.getenv("XDR_API_KEY_ID")
)

xsoar = XSOARClient(
    base_url=os.getenv("XSOAR_URL"),
    api_key=os.getenv("XSOAR_API_KEY")
)

slack = SlackClient(webhook_url=os.getenv("SLACK_WEBHOOK_URL"))

# Get XDR incidents
incidents = xdr.get_incidents(limit=10)

# Create XSOAR incident
for incident in incidents:
    xsoar_incident = xsoar.create_incident(
        name=f"XDR: {incident['incident_id']}",
        severity=3
    )
    
    # Notify Slack
    slack.send_message(
        channel="#security-alerts",
        text=f"New XDR incident: {incident['incident_id']}"
    )
```

# Integration Patterns

# Pattern 1: Alert → Incident Creation
- Source: Prisma Cloud / XDR
- Destination: XSOAR / ServiceNow / Jira
- Trigger: New alert/incident

# Pattern 2: Event → SIEM Logging
- Source: Any security event
- Destination: Splunk / Elasticsearch
- Trigger: Real-time events

# Pattern 3: Critical Alert → Notification
- Source: High-severity alerts
- Destination: Slack / PagerDuty
- Trigger: Critical severity threshold

# Pattern 4: Vulnerability → Ticketing
- Source: SonarQube / Snyk
- Destination: Jira / ServiceNow
- Trigger: New vulnerability

# Configuration

All integrations use environment variables for credentials. See `integrations_config.yaml` for the complete configuration template.

Required environment variables:
- `XDR_API_KEY`, `XDR_API_KEY_ID`
- `XSOAR_URL`, `XSOAR_API_KEY`
- `PRISMA_API_URL`, `PRISMA_ACCESS_KEY`, `PRISMA_SECRET_KEY`
- `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN`
- `SNOW_INSTANCE_URL`, `SNOW_USERNAME`, `SNOW_PASSWORD`
- `JIRA_URL`, `JIRA_USERNAME`, `JIRA_API_TOKEN`
- `SLACK_WEBHOOK_URL`
- `PAGERDUTY_API_KEY`

# Testing

Use the integration test framework provided in the SOP to validate your integrations:

```python
from integrations import IntegrationTestSuite
import unittest

unittest.main()
```

# Security Considerations

1. Never commit credentials - Use environment variables or secrets management
2. Use HTTPS - Always use encrypted connections
3. Validate inputs - Sanitize all inputs to prevent injection
4. Rate limiting - Implement rate limiting to prevent abuse
5. Error handling - Don't expose sensitive information in error messages
6. Audit logging - Log all integration activities

# Support

For issues or questions:
1. Review the troubleshooting section in the SOP
2. Check the quick reference guide
3. Review API documentation for specific tools
4. Contact SOC team for assistance

---

Version: 1.0  
Last Updated: 2026-01-09
