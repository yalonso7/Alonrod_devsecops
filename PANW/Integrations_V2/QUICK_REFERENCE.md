# SOC Integrations Quick Reference Guide

# Quick Start

# 1. Set Environment Variables

```bash
# Palo Alto Networks
export XDR_API_KEY="your-xdr-api-key"
export XDR_API_KEY_ID="your-xdr-key-id"
export XSOAR_URL="https://xsoar.example.com"
export XSOAR_API_KEY="your-xsoar-api-key"
export PRISMA_API_URL="https://api.prismacloud.io"
export PRISMA_ACCESS_KEY="your-prisma-access-key"
export PRISMA_SECRET_KEY="your-prisma-secret-key"

# SIEM
export SPLUNK_HEC_URL="https://splunk.example.com:8088/services/collector"
export SPLUNK_HEC_TOKEN="your-hec-token"

# ITSM
export SNOW_INSTANCE_URL="https://yourinstance.service-now.com"
export SNOW_USERNAME="your-username"
export SNOW_PASSWORD="your-password"
export JIRA_URL="https://yourcompany.atlassian.net"
export JIRA_USERNAME="your-username"
export JIRA_API_TOKEN="your-api-token"

# Communication
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
export PAGERDUTY_API_KEY="your-pagerduty-api-key"
```

# 2. Install Dependencies

```bash
pip install requests flask python-dotenv pyyaml
```

# 3. Use Integration Classes

```python
from integrations import CortexXDRClient, XSOARClient, PrismaCloudClient

# Initialize clients
xdr = CortexXDRClient(api_key=os.getenv("XDR_API_KEY"), api_key_id=os.getenv("XDR_API_KEY_ID"))
xsoar = XSOARClient(base_url=os.getenv("XSOAR_URL"), api_key=os.getenv("XSOAR_API_KEY"))
prisma = PrismaCloudClient(api_url=os.getenv("PRISMA_API_URL"), 
                          access_key=os.getenv("PRISMA_ACCESS_KEY"),
                          secret_key=os.getenv("PRISMA_SECRET_KEY"))

# Use integrations
incidents = xdr.get_incidents(limit=10)
xsoar_incident = xsoar.create_incident(name="Security Alert", severity=3)
alerts = prisma.get_alerts()
```

# Common Integration Patterns

# Pattern 1: XDR Incident → XSOAR + ServiceNow

```python
# Get XDR incident
xdr_incident = xdr.get_incident(incident_id)

# Create XSOAR incident
xsoar_incident = xsoar.create_incident(
    name=f"XDR: {xdr_incident['incident_id']}",
    severity=map_severity(xdr_incident['severity'])
)

# Create ServiceNow incident
snow_incident = servicenow.create_incident(
    short_description=f"XDR Incident: {xdr_incident['incident_id']}",
    description=format_incident_description(xdr_incident),
    urgency=map_severity_to_urgency(xdr_incident['severity'])
)
```

# Pattern 2: Prisma Alert → Splunk + Slack

```python
# Get Prisma alert
prisma_alert = prisma.get_alerts()[0]

# Send to Splunk
splunk.send_event(
    event=prisma_alert,
    source="prisma_cloud",
    sourcetype="prisma:alert"
)

# Notify Slack
slack.send_message(
    channel="#security-alerts",
    text=f"Prisma Alert: {prisma_alert['policy']['name']}",
    blocks=create_alert_blocks(prisma_alert)
)
```

# Pattern 3: SonarQube Issue → Jira

```python
# Get SonarQube issues
sonar_issues = sonarqube.get_project_issues(
    project_key="MYPROJECT",
    severities=["CRITICAL", "BLOCKER"]
)

# Create Jira issues
for issue in sonar_issues:
    jira.create_issue(
        project_key="SEC",
        summary=f"SonarQube: {issue['message']}",
        description=format_sonar_issue(issue),
        priority=map_sonar_severity(issue['severity']),
        labels=["sonarqube", "security"]
    )
```

# API Endpoints Quick Reference

# Cortex XDR
- Base URL: `https://api.xdr.us.paloaltonetworks.com`
- Auth: API Key + API Key ID
- Key Endpoints:
  - `POST /public_api/v1/incidents/get_incidents`
  - `POST /public_api/v1/alerts/get_alerts`
  - `POST /public_api/v1/endpoints/isolate`

# XSOAR
- Base URL: Your XSOAR instance URL
- Auth: Bearer token
- Key Endpoints:
  - `POST /incident` - Create incident
  - `POST /command` - Execute command
  - `GET /incident/{id}` - Get incident

# Prisma Cloud
- Base URL: `https://api.prismacloud.io`
- Auth: Username/Password (gets token)
- Key Endpoints:
  - `POST /v2/alert` - Get alerts
  - `GET /compliance` - Get compliance status
  - `POST /v2/vulnerability/container` - Get vulnerabilities

# Splunk HEC
- Base URL: `https://splunk.example.com:8088`
- Auth: HEC Token
- Endpoint: `POST /services/collector/event`

# ServiceNow
- Base URL: `https://instance.service-now.com`
- Auth: Basic Auth
- Key Endpoints:
  - `POST /api/now/table/incident`
  - `PATCH /api/now/table/incident/{sys_id}`

# Jira
- Base URL: `https://company.atlassian.net`
- Auth: Basic Auth (username + API token)
- Key Endpoints:
  - `POST /rest/api/3/issue`
  - `POST /rest/api/3/issue/{key}/comment`

# Severity Mapping

| Source | Critical | High | Medium | Low |
|--------|----------|------|--------|-----|
| XDR | critical | high | medium | low |
| Prisma Cloud | critical | high | medium | low |
| SonarQube | BLOCKER | CRITICAL | MAJOR | MINOR |
| XSOAR | 4 | 3 | 2 | 1 |
| ServiceNow | 1 | 2 | 3 | 4 |
| Jira | Highest | High | Medium | Low |

# Error Handling

# Retry Logic

```python
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def api_call_with_retry():
    # Your API call
    pass
```

# Error Logging

```python
import logging

logger = logging.getLogger(__name__)

try:
    result = api_call()
except requests.exceptions.HTTPError as e:
    logger.error(f"API call failed: {e.response.status_code} - {e.response.text}")
    raise
except Exception as e:
    logger.exception(f"Unexpected error: {e}")
    raise
```

# Testing Integrations

# Test Connection

```python
def test_integration_connection(client):
    """Test if integration is accessible"""
    try:
        # Simple API call to test connection
        result = client.get_status()  # Example method
        return True
    except Exception as e:
        print(f"Connection test failed: {e}")
        return False
```

# Test End-to-End Flow

```python
def test_e2e_flow():
    """Test complete integration flow"""
    # 1. Create test event
    test_event = create_test_event()
    
    # 2. Send to source
    source_result = source_client.create_event(test_event)
    
    # 3. Verify in destination
    destination_result = destination_client.get_event(source_result['id'])
    
    # 4. Validate
    assert destination_result is not None
    assert destination_result['status'] == 'created'
```

# Best Practices

1. Use Environment Variables: Never hardcode credentials
2. Implement Retry Logic: Handle transient failures
3. Log Everything: Comprehensive logging for troubleshooting
4. Validate Input: Sanitize and validate all inputs
5. Rate Limiting: Respect API rate limits
6. Error Handling: Graceful error handling and recovery
7. Testing: Test integrations before production use
8. Monitoring: Monitor integration health and performance

# Troubleshooting Checklist

- [ ] Verify credentials are correct
- [ ] Check network connectivity
- [ ] Verify API endpoints are accessible
- [ ] Check SSL certificates
- [ ] Review API rate limits
- [ ] Check logs for errors
- [ ] Validate request/response formats
- [ ] Test with minimal example first

# Support Resources

- Cortex XDR API Docs: https://docs.paloaltonetworks.com/cortex/cortex-xdr
- XSOAR API Docs: https://xsoar.pan.dev/docs
- Prisma Cloud API Docs: https://prisma.pan.dev/
- Splunk HEC Docs: https://docs.splunk.com/Documentation/Splunk/latest/Data/HECExamples
- ServiceNow API Docs: https://developer.servicenow.com/
- Jira API Docs: https://developer.atlassian.com/cloud/jira/platform/rest/v3/

---

Last Updated: 2026-01-09
