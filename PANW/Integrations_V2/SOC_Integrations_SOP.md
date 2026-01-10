# SOC Integrations Standard Operating Procedure (SOP)

# Table of Contents

1. [Overview](#overview)
2. [Palo Alto Networks Product Integrations](#palo-alto-networks-product-integrations)
3. [Security Scanning Integrations](#security-scanning-integrations)
4. [SIEM and Logging Integrations](#siem-and-logging-integrations)
5. [ITSM and Ticketing Integrations](#itsm-and-ticketing-integrations)
6. [Communication and Collaboration](#communication-and-collaboration)
7. [Additional SOC Integrations](#additional-soc-integrations)
8. [Integration Testing and Validation](#integration-testing-and-validation)
9. [Troubleshooting](#troubleshooting)

---

# Overview

This SOP provides comprehensive integration code snippets and configuration examples for connecting Palo Alto Networks security products (Cortex XDR, XSOAR, Prisma Cloud) with third-party SOC tools and platforms.

# Integration Categories

- Palo Alto Networks Products: Cortex XDR, XSOAR, Prisma Cloud
- Security Scanning: SonarQube, Snyk
- SIEM/Logging: Splunk, ELK Stack, QRadar
- ITSM/Ticketing: ServiceNow, Jira
- Communication: Slack, Microsoft Teams, PagerDuty
- Additional: Salesforce, GitHub, Azure DevOps

---

# Palo Alto Networks Product Integrations

# 1. Cortex XDR Integration

# 1.1 XDR API Integration (Python)

```python
#!/usr/bin/env python3
"""
Cortex XDR API Integration
Purpose: Query incidents, manage endpoints, and automate responses
"""

import requests
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import os

class CortexXDRClient:
    """Cortex XDR API Client"""
    
    def __init__(self, api_key: str, api_key_id: str, base_url: str = "https://api.xdr.us.paloaltonetworks.com"):
        self.api_key = api_key
        self.api_key_id = api_key_id
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "x-xdr-auth-id": str(api_key_id),
            "Authorization": api_key,
            "Content-Type": "application/json"
        })
    
    def get_incidents(self, 
                     from_date: Optional[str] = None,
                     to_date: Optional[str] = None,
                     limit: int = 100) -> Dict:
        """Get XDR incidents"""
        url = f"{self.base_url}/public_api/v1/incidents/get_incidents"
        
        payload = {
            "request_data": {
                "filters": [],
                "search_from": 0,
                "search_to": limit,
                "sort": {
                    "field": "creation_time",
                    "keyword": "desc"
                }
            }
        }
        
        if from_date:
            payload["request_data"]["filters"].append({
                "field": "creation_time",
                "operator": "gte",
                "value": from_date
            })
        
        if to_date:
            payload["request_data"]["filters"].append({
                "field": "creation_time",
                "operator": "lte",
                "value": to_date
            })
        
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()
    
    def get_endpoint_details(self, endpoint_id: str) -> Dict:
        """Get endpoint details"""
        url = f"{self.base_url}/public_api/v1/endpoints/get_endpoint"
        payload = {
            "request_data": {
                "endpoint_id": endpoint_id
            }
        }
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()
    
    def isolate_endpoint(self, endpoint_id: str, isolation_type: str = "full") -> Dict:
        """Isolate an endpoint"""
        url = f"{self.base_url}/public_api/v1/endpoints/isolate"
        payload = {
            "request_data": {
                "endpoint_id_list": [endpoint_id],
                "isolation_type": isolation_type  # full, selective
            }
        }
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()
    
    def get_alerts(self, severity: Optional[str] = None, limit: int = 100) -> Dict:
        """Get XDR alerts"""
        url = f"{self.base_url}/public_api/v1/alerts/get_alerts"
        
        filters = []
        if severity:
            filters.append({
                "field": "severity",
                "operator": "eq",
                "value": severity
            })
        
        payload = {
            "request_data": {
                "filters": filters,
                "search_from": 0,
                "search_to": limit
            }
        }
        
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()
    
    def add_incident_comment(self, incident_id: str, comment: str) -> Dict:
        """Add comment to incident"""
        url = f"{self.base_url}/public_api/v1/incidents/add_comment"
        payload = {
            "request_data": {
                "incident_id": incident_id,
                "comment": comment
            }
        }
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()

# Usage Example
if __name__ == "__main__":
    # Initialize client
    client = CortexXDRClient(
        api_key=os.getenv("XDR_API_KEY"),
        api_key_id=os.getenv("XDR_API_KEY_ID")
    )
    
    # Get recent incidents
    incidents = client.get_incidents(
        from_date=(datetime.now() - timedelta(days=7)).isoformat()
    )
    
    print(f"Found {len(incidents.get('reply', {}).get('incidents', []))} incidents")
    
    # Get critical alerts
    alerts = client.get_alerts(severity="critical", limit=50)
    print(f"Found {len(alerts.get('reply', {}).get('alerts', []))} critical alerts")
```

# 1.2 XDR Webhook Integration (Flask)

```python
#!/usr/bin/env python3
"""
Cortex XDR Webhook Receiver
Purpose: Receive XDR webhooks and trigger automated responses
"""

from flask import Flask, request, jsonify
import requests
import json
import os

app = Flask(__name__)

@app.route('/xdr/webhook', methods=['POST'])
def xdr_webhook():
    """Receive XDR webhook notifications"""
    try:
        data = request.json
        
        # Validate webhook signature
        if not validate_webhook_signature(request):
            return jsonify({"error": "Invalid signature"}), 401
        
        event_type = data.get('event_type')
        incident_id = data.get('incident_id')
        
        # Route to appropriate handler
        if event_type == 'incident_created':
            handle_new_incident(data)
        elif event_type == 'alert_created':
            handle_new_alert(data)
        elif event_type == 'endpoint_isolated':
            handle_endpoint_isolation(data)
        
        return jsonify({"status": "success"}), 200
    
    except Exception as e:
        print(f"Webhook error: {e}")
        return jsonify({"error": str(e)}), 500

def handle_new_incident(incident_data: dict):
    """Handle new incident creation"""
    incident_id = incident_data.get('incident_id')
    severity = incident_data.get('severity')
    
    # Send to ServiceNow
    create_servicenow_incident(incident_data)
    
    # Send to Slack
    send_slack_notification(
        channel="#security-alerts",
        message=f"New XDR Incident: {incident_id} (Severity: {severity})"
    )
    
    # If critical, page on-call
    if severity == "critical":
        trigger_pagerduty_alert(incident_data)

def validate_webhook_signature(request) -> bool:
    """Validate webhook signature"""
    # Implement signature validation logic
    return True

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')
```

# 1.3 XDR to Prisma Cloud Integration

```python
#!/usr/bin/env python3
"""
XDR to Prisma Cloud Integration
Purpose: Correlate XDR incidents with Prisma Cloud alerts
"""

import requests
from datetime import datetime, timedelta

class XDRPrismaCloudCorrelation:
    """Correlate XDR and Prisma Cloud events"""
    
    def __init__(self, xdr_client, prisma_client):
        self.xdr = xdr_client
        self.prisma = prisma_client
    
    def correlate_incident(self, xdr_incident_id: str):
        """Correlate XDR incident with Prisma Cloud alerts"""
        # Get XDR incident details
        xdr_incident = self.xdr.get_incident(xdr_incident_id)
        
        # Extract relevant fields
        endpoint_id = xdr_incident.get('endpoint_id')
        timestamp = xdr_incident.get('creation_time')
        
        # Query Prisma Cloud for related alerts
        prisma_alerts = self.prisma.get_alerts(
            resource_id=endpoint_id,
            from_time=timestamp
        )
        
        # Create correlation report
        correlation = {
            "xdr_incident_id": xdr_incident_id,
            "prisma_alerts": prisma_alerts,
            "correlation_score": self.calculate_correlation_score(
                xdr_incident, prisma_alerts
            )
        }
        
        return correlation
    
    def calculate_correlation_score(self, xdr_incident, prisma_alerts) -> float:
        """Calculate correlation score between XDR and Prisma events"""
        # Implementation of correlation logic
        return 0.85
```

---

# 2. Cortex XSOAR Integration

# 2.1 XSOAR API Integration (Python)

```python
#!/usr/bin/env python3
"""
Cortex XSOAR API Integration
Purpose: Create incidents, execute playbooks, and manage integrations
"""

import requests
import json
from typing import Dict, List, Optional
import os

class XSOARClient:
    """Cortex XSOAR API Client"""
    
    def __init__(self, base_url: str, api_key: str, verify_ssl: bool = True):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        })
    
    def create_incident(self, 
                       name: str,
                       severity: int = 1,
                       type: str = "Unclassified",
                       labels: Optional[List[Dict]] = None,
                       custom_fields: Optional[Dict] = None) -> Dict:
        """Create a new incident in XSOAR"""
        url = f"{self.base_url}/incident"
        
        payload = {
            "name": name,
            "type": type,
            "severity": severity,
            "labels": labels or [],
            "customFields": custom_fields or {}
        }
        
        response = self.session.post(url, json=payload, verify=self.verify_ssl)
        response.raise_for_status()
        return response.json()
    
    def execute_command(self, command: str, arguments: Dict) -> Dict:
        """Execute a command in XSOAR"""
        url = f"{self.base_url}/command"
        
        payload = {
            "command": command,
            "arguments": arguments
        }
        
        response = self.session.post(url, json=payload, verify=self.verify_ssl)
        response.raise_for_status()
        return response.json()
    
    def get_incident(self, incident_id: str) -> Dict:
        """Get incident details"""
        url = f"{self.base_url}/incident/{incident_id}"
        response = self.session.get(url, verify=self.verify_ssl)
        response.raise_for_status()
        return response.json()
    
    def update_incident(self, incident_id: str, updates: Dict) -> Dict:
        """Update incident"""
        url = f"{self.base_url}/incident/{incident_id}"
        response = self.session.put(url, json=updates, verify=self.verify_ssl)
        response.raise_for_status()
        return response.json()
    
    def add_incident_entry(self, incident_id: str, entry: str, entry_type: str = "note") -> Dict:
        """Add entry to incident"""
        url = f"{self.base_url}/incident/{incident_id}/entry"
        
        payload = {
            "entry": entry,
            "type": entry_type  # note, comment, warRoomEntry
        }
        
        response = self.session.post(url, json=payload, verify=self.verify_ssl)
        response.raise_for_status()
        return response.json()
    
    def search_incidents(self, query: str, limit: int = 100) -> List[Dict]:
        """Search incidents"""
        url = f"{self.base_url}/incident/search"
        
        payload = {
            "query": query,
            "size": limit
        }
        
        response = self.session.post(url, json=payload, verify=self.verify_ssl)
        response.raise_for_status()
        return response.json().get('data', [])

# Usage Example
if __name__ == "__main__":
    client = XSOARClient(
        base_url=os.getenv("XSOAR_URL", "https://xsoar.example.com"),
        api_key=os.getenv("XSOAR_API_KEY")
    )
    
    # Create incident from Prisma Cloud alert
    incident = client.create_incident(
        name="Prisma Cloud: Critical Vulnerability Detected",
        severity=3,  # High
        type="Vulnerability",
        labels=[
            {"type": "source", "value": "Prisma Cloud"},
            {"type": "severity", "value": "critical"}
        ],
        custom_fields={
            "prisma_alert_id": "alert-12345",
            "resource_id": "resource-abc"
        }
    )
    
    print(f"Created incident: {incident.get('id')}")
```

# 2.2 XSOAR Playbook Integration

```python
#!/usr/bin/env python3
"""
XSOAR Playbook Automation
Purpose: Trigger and monitor playbook execution
"""

class XSOARPlaybookManager:
    """Manage XSOAR playbook execution"""
    
    def __init__(self, xsoar_client):
        self.client = xsoar_client
    
    def trigger_playbook(self, 
                        playbook_name: str,
                        incident_id: str,
                        inputs: Optional[Dict] = None) -> Dict:
        """Trigger a playbook on an incident"""
        command = "executePlaybook"
        arguments = {
            "incidentId": incident_id,
            "playbookName": playbook_name,
            "inputs": inputs or {}
        }
        
        return self.client.execute_command(command, arguments)
    
    def get_playbook_status(self, playbook_instance_id: str) -> Dict:
        """Get playbook execution status"""
        command = "getPlaybookStatus"
        arguments = {
            "playbookInstanceId": playbook_instance_id
        }
        
        return self.client.execute_command(command, arguments)
    
    def stop_playbook(self, playbook_instance_id: str) -> Dict:
        """Stop a running playbook"""
        command = "stopPlaybook"
        arguments = {
            "playbookInstanceId": playbook_instance_id
        }
        
        return self.client.execute_command(command, arguments)

# Example: Automated Incident Response
def automated_incident_response(xsoar_client, incident_id: str):
    """Automated response workflow"""
    playbook_manager = XSOARPlaybookManager(xsoar_client)
    
    # Trigger investigation playbook
    investigation = playbook_manager.trigger_playbook(
        playbook_name="Investigate Security Incident",
        incident_id=incident_id
    )
    
    # Wait for investigation to complete
    # Then trigger remediation if needed
    remediation = playbook_manager.trigger_playbook(
        playbook_name="Remediate Security Threat",
        incident_id=incident_id,
        inputs={"auto_remediate": True}
    )
    
    return {"investigation": investigation, "remediation": remediation}
```

# 2.3 XSOAR Webhook Integration

```python
#!/usr/bin/env python3
"""
XSOAR Webhook Integration
Purpose: Receive XSOAR webhooks and integrate with other systems
"""

from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/xsoar/webhook', methods=['POST'])
def xsoar_webhook():
    """Receive XSOAR webhook notifications"""
    try:
        data = request.json
        event_type = data.get('eventType')
        
        if event_type == 'incidentCreated':
            handle_incident_created(data)
        elif event_type == 'incidentUpdated':
            handle_incident_updated(data)
        elif event_type == 'playbookCompleted':
            handle_playbook_completed(data)
        
        return jsonify({"status": "success"}), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def handle_incident_created(data: dict):
    """Handle new incident creation"""
    incident = data.get('incident', {})
    
    # Sync to ServiceNow
    sync_to_servicenow(incident)
    
    # Notify Slack
    notify_slack(incident)

def sync_to_servicenow(incident: dict):
    """Sync incident to ServiceNow"""
    # Implementation
    pass

def notify_slack(incident: dict):
    """Notify Slack channel"""
    # Implementation
    pass
```

---

# 3. Prisma Cloud Integration

# 3.1 Prisma Cloud API Integration

```python
#!/usr/bin/env python3
"""
Prisma Cloud API Integration
Purpose: Query alerts, policies, and compliance data
"""

import requests
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import os

class PrismaCloudClient:
    """Prisma Cloud API Client"""
    
    def __init__(self, api_url: str, access_key: str, secret_key: str):
        self.api_url = api_url.rstrip('/')
        self.access_key = access_key
        self.secret_key = secret_key
        self.token = None
        self.token_expiry = None
        self._authenticate()
    
    def _authenticate(self):
        """Authenticate and get access token"""
        url = f"{self.api_url}/login"
        payload = {
            "username": self.access_key,
            "password": self.secret_key
        }
        
        response = requests.post(url, json=payload)
        response.raise_for_status()
        data = response.json()
        self.token = data.get('token')
        self.token_expiry = datetime.now() + timedelta(hours=1)
    
    def _get_headers(self) -> Dict:
        """Get request headers with auth token"""
        if not self.token or datetime.now() >= self.token_expiry:
            self._authenticate()
        
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
    
    def get_alerts(self, 
                  time_range: Optional[Dict] = None,
                  filters: Optional[List[Dict]] = None,
                  limit: int = 100) -> List[Dict]:
        """Get Prisma Cloud alerts"""
        url = f"{self.api_url}/v2/alert"
        
        payload = {
            "timeRange": time_range or {
                "type": "relative",
                "value": {"unit": "hour", "amount": 24}
            },
            "filters": filters or [],
            "limit": limit
        }
        
        response = requests.post(
            url,
            json=payload,
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()
    
    def get_compliance_status(self, compliance_standard: str) -> Dict:
        """Get compliance status for a standard"""
        url = f"{self.api_url}/compliance"
        
        params = {
            "complianceStandard": compliance_standard
        }
        
        response = requests.get(
            url,
            params=params,
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()
    
    def get_vulnerabilities(self, 
                           resource_id: Optional[str] = None,
                           severity: Optional[str] = None) -> List[Dict]:
        """Get vulnerability data"""
        url = f"{self.api_url}/v2/vulnerability/container"
        
        filters = []
        if resource_id:
            filters.append({
                "name": "resource.id",
                "operator": "=",
                "value": resource_id
            })
        if severity:
            filters.append({
                "name": "severity",
                "operator": "=",
                "value": severity
            })
        
        payload = {"filters": filters}
        
        response = requests.post(
            url,
            json=payload,
            headers=self._get_headers()
        )
        response.raise_for_status()
        return response.json()

# Usage Example
if __name__ == "__main__":
    client = PrismaCloudClient(
        api_url=os.getenv("PRISMA_API_URL", "https://api.prismacloud.io"),
        access_key=os.getenv("PRISMA_ACCESS_KEY"),
        secret_key=os.getenv("PRISMA_SECRET_KEY")
    )
    
    # Get critical alerts
    alerts = client.get_alerts(
        filters=[{
            "name": "alert.status",
            "operator": "=",
            "value": "open"
        }, {
            "name": "policy.severity",
            "operator": "=",
            "value": "critical"
        }]
    )
    
    print(f"Found {len(alerts)} critical alerts")
```

# 3.2 Prisma Cloud Webhook Integration

```python
#!/usr/bin/env python3
"""
Prisma Cloud Webhook Receiver
Purpose: Receive Prisma Cloud webhooks and trigger responses
"""

from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route('/prisma/webhook', methods=['POST'])
def prisma_webhook():
    """Receive Prisma Cloud webhook notifications"""
    try:
        data = request.json
        alert_type = data.get('alertType')
        
        if alert_type == 'NEW_ALERT':
            handle_new_alert(data)
        elif alert_type == 'ALERT_CLOSED':
            handle_alert_closed(data)
        elif alert_type == 'COMPLIANCE_VIOLATION':
            handle_compliance_violation(data)
        
        return jsonify({"status": "success"}), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def handle_new_alert(alert_data: dict):
    """Handle new Prisma Cloud alert"""
    alert_id = alert_data.get('alertId')
    severity = alert_data.get('severity')
    
    # Create XSOAR incident
    create_xsoar_incident(alert_data)
    
    # Send to Splunk
    send_to_splunk(alert_data)
    
    # Notify SOC team
    if severity in ['critical', 'high']:
        notify_soc_team(alert_data)

def create_xsoar_incident(alert_data: dict):
    """Create XSOAR incident from Prisma alert"""
    # Implementation using XSOARClient
    pass

def send_to_splunk(alert_data: dict):
    """Send alert to Splunk"""
    # Implementation
    pass

def notify_soc_team(alert_data: dict):
    """Notify SOC team"""
    # Implementation
    pass
```

---

# Security Scanning Integrations

# 4. SonarQube Integration

# 4.1 SonarQube API Integration

```python
#!/usr/bin/env python3
"""
SonarQube API Integration
Purpose: Query code quality issues and security vulnerabilities
"""

import requests
from typing import Dict, List, Optional
import os

class SonarQubeClient:
    """SonarQube API Client"""
    
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.session = requests.Session()
        self.session.auth = (token, '')
    
    def get_project_issues(self, 
                          project_key: str,
                          severities: Optional[List[str]] = None,
                          types: Optional[List[str]] = None) -> List[Dict]:
        """Get project issues"""
        url = f"{self.base_url}/api/issues/search"
        
        params = {
            "componentKeys": project_key,
            "resolved": "false"
        }
        
        if severities:
            params["severities"] = ",".join(severities)
        if types:
            params["types"] = ",".join(types)
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json().get('issues', [])
    
    def get_security_hotspots(self, project_key: str) -> List[Dict]:
        """Get security hotspots"""
        url = f"{self.base_url}/api/hotspots/search"
        
        params = {
            "projectKey": project_key
        }
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json().get('hotspots', [])
    
    def get_project_measures(self, 
                            project_key: str,
                            metrics: List[str]) -> Dict:
        """Get project measures/metrics"""
        url = f"{self.base_url}/api/measures/component"
        
        params = {
            "component": project_key,
            "metricKeys": ",".join(metrics)
        }
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()
    
    def create_issue_comment(self, issue_key: str, comment: str) -> Dict:
        """Add comment to issue"""
        url = f"{self.base_url}/api/issues/add_comment"
        
        params = {
            "issue": issue_key,
            "text": comment
        }
        
        response = self.session.post(url, params=params)
        response.raise_for_status()
        return response.json()

# Integration with XSOAR
def sync_sonarqube_to_xsoar(sonar_client, xsoar_client, project_key: str):
    """Sync SonarQube issues to XSOAR incidents"""
    # Get critical security issues
    issues = sonar_client.get_project_issues(
        project_key=project_key,
        severities=['CRITICAL', 'BLOCKER'],
        types=['VULNERABILITY', 'SECURITY_HOTSPOT']
    )
    
    for issue in issues:
        # Create XSOAR incident
        incident = xsoar_client.create_incident(
            name=f"SonarQube: {issue.get('message')}",
            severity=map_sonar_severity(issue.get('severity')),
            type="Vulnerability",
            labels=[
                {"type": "source", "value": "SonarQube"},
                {"type": "project", "value": project_key}
            ],
            custom_fields={
                "sonar_issue_key": issue.get('key'),
                "rule": issue.get('rule'),
                "component": issue.get('component')
            }
        )
        
        print(f"Created XSOAR incident: {incident.get('id')}")

def map_sonar_severity(severity: str) -> int:
    """Map SonarQube severity to XSOAR severity"""
    mapping = {
        'BLOCKER': 4,  # Critical
        'CRITICAL': 3,  # High
        'MAJOR': 2,     # Medium
        'MINOR': 1,     # Low
        'INFO': 0       # Info
    }
    return mapping.get(severity, 1)
```

---

# 5. Snyk Integration

# 5.1 Snyk API Integration

```python
#!/usr/bin/env python3
"""
Snyk API Integration
Purpose: Query vulnerabilities and license issues
"""

import requests
from typing import Dict, List, Optional
import os

class SnykClient:
    """Snyk API Client"""
    
    def __init__(self, api_token: str, org_id: str):
        self.api_token = api_token
        self.org_id = org_id
        self.base_url = "https://api.snyk.io/v1"
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {api_token}",
            "Content-Type": "application/json"
        })
    
    def get_projects(self) -> List[Dict]:
        """Get all projects"""
        url = f"{self.base_url}/org/{self.org_id}/projects"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json().get('projects', [])
    
    def get_project_issues(self, project_id: str) -> Dict:
        """Get project issues/vulnerabilities"""
        url = f"{self.base_url}/org/{self.org_id}/project/{project_id}/issues"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()
    
    def get_vulnerabilities(self, 
                          project_id: str,
                          severity: Optional[str] = None) -> List[Dict]:
        """Get vulnerabilities for a project"""
        issues = self.get_project_issues(project_id)
        vulnerabilities = issues.get('issues', {}).get('vulnerabilities', [])
        
        if severity:
            vulnerabilities = [
                v for v in vulnerabilities 
                if v.get('severity') == severity
            ]
        
        return vulnerabilities
    
    def ignore_issue(self, 
                    project_id: str,
                    issue_id: str,
                    reason: str,
                    expires: Optional[str] = None) -> Dict:
        """Ignore an issue"""
        url = f"{self.base_url}/org/{self.org_id}/project/{project_id}/ignore"
        
        payload = {
            "reason": reason,
            "disregardIfFixable": False
        }
        
        if expires:
            payload["expires"] = expires
        
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()

# Integration with Prisma Cloud
def sync_snyk_to_prisma(snyk_client, prisma_client):
    """Sync Snyk vulnerabilities to Prisma Cloud"""
    projects = snyk_client.get_projects()
    
    for project in projects:
        project_id = project.get('id')
        vulnerabilities = snyk_client.get_vulnerabilities(
            project_id=project_id,
            severity='high'
        )
        
        for vuln in vulnerabilities:
            # Create Prisma Cloud alert or sync data
            # Implementation depends on Prisma Cloud API
            pass
```

---

# SIEM and Logging Integrations

# 6. Splunk Integration

# 6.1 Splunk HEC (HTTP Event Collector) Integration

```python
#!/usr/bin/env python3
"""
Splunk HEC Integration
Purpose: Send security events to Splunk
"""

import requests
import json
from datetime import datetime
from typing import Dict, List, Optional
import os

class SplunkHECClient:
    """Splunk HTTP Event Collector Client"""
    
    def __init__(self, hec_url: str, hec_token: str, index: str = "main"):
        self.hec_url = hec_url.rstrip('/')
        self.hec_token = hec_token
        self.index = index
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Splunk {hec_token}",
            "Content-Type": "application/json"
        })
    
    def send_event(self, 
                  event: Dict,
                  source: Optional[str] = None,
                  sourcetype: Optional[str] = None,
                  host: Optional[str] = None) -> requests.Response:
        """Send a single event to Splunk"""
        url = f"{self.hec_url}/services/collector/event"
        
        payload = {
            "time": int(datetime.now().timestamp()),
            "event": event,
            "index": self.index
        }
        
        if source:
            payload["source"] = source
        if sourcetype:
            payload["sourcetype"] = sourcetype
        if host:
            payload["host"] = host
        
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response
    
    def send_events_batch(self, events: List[Dict]) -> requests.Response:
        """Send multiple events in batch"""
        url = f"{self.hec_url}/services/collector/event"
        
        payloads = []
        for event in events:
            payload = {
                "time": int(datetime.now().timestamp()),
                "event": event,
                "index": self.index
            }
            payloads.append(payload)
        
        # Splunk HEC accepts multiple events in one request
        response = self.session.post(url, json=payloads)
        response.raise_for_status()
        return response

# Integration Examples
def send_xdr_incident_to_splunk(xdr_incident: dict, splunk_client: SplunkHECClient):
    """Send XDR incident to Splunk"""
    event = {
        "incident_id": xdr_incident.get('incident_id'),
        "severity": xdr_incident.get('severity'),
        "status": xdr_incident.get('status'),
        "alert_count": xdr_incident.get('alert_count'),
        "creation_time": xdr_incident.get('creation_time'),
        "source": "Cortex XDR"
    }
    
    splunk_client.send_event(
        event=event,
        source="xdr",
        sourcetype="xdr:incident",
        host=xdr_incident.get('endpoint_id')
    )

def send_prisma_alert_to_splunk(prisma_alert: dict, splunk_client: SplunkHECClient):
    """Send Prisma Cloud alert to Splunk"""
    event = {
        "alert_id": prisma_alert.get('alertId'),
        "policy_name": prisma_alert.get('policy', {}).get('name'),
        "severity": prisma_alert.get('severity'),
        "resource_id": prisma_alert.get('resource', {}).get('id'),
        "source": "Prisma Cloud"
    }
    
    splunk_client.send_event(
        event=event,
        source="prisma_cloud",
        sourcetype="prisma:alert",
        host=prisma_alert.get('resource', {}).get('cloudType')
    )
```

# 6.2 Splunk Search API Integration

```python
#!/usr/bin/env python3
"""
Splunk Search API Integration
Purpose: Query Splunk for security events
"""

import requests
import time
from typing import Dict, List, Optional

class SplunkSearchClient:
    """Splunk Search API Client"""
    
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.auth = (username, password)
    
    def create_search_job(self, query: str, kwargs) -> str:
        """Create a search job"""
        url = f"{self.base_url}/services/search/jobs"
        
        params = {
            "search": query,
            kwargs
        }
        
        response = self.session.post(url, params=params)
        response.raise_for_status()
        return response.text.split('<sid>')[1].split('</sid>')[0]
    
    def get_search_results(self, 
                          search_id: str,
                          output_mode: str = "json",
                          count: int = 100) -> Dict:
        """Get search results"""
        url = f"{self.base_url}/services/search/jobs/{search_id}/results"
        
        params = {
            "output_mode": output_mode,
            "count": count
        }
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()
    
    def wait_for_search_completion(self, search_id: str, timeout: int = 300) -> bool:
        """Wait for search to complete"""
        url = f"{self.base_url}/services/search/jobs/{search_id}"
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            response = self.session.get(url)
            response.raise_for_status()
            
            # Parse XML response to check status
            if 'DONE' in response.text:
                return True
            
            time.sleep(2)
        
        return False
    
    def search(self, query: str, kwargs) -> List[Dict]:
        """Execute a search and return results"""
        search_id = self.create_search_job(query, kwargs)
        
        if self.wait_for_search_completion(search_id):
            results = self.get_search_results(search_id)
            return results.get('results', [])
        
        return []
```

---

# ITSM and Ticketing Integrations

# 7. ServiceNow Integration

# 7.1 ServiceNow API Integration

```python
#!/usr/bin/env python3
"""
ServiceNow API Integration
Purpose: Create and manage incidents, change requests, and CMDB records
"""

import requests
from typing import Dict, List, Optional
import base64
import os

class ServiceNowClient:
    """ServiceNow REST API Client"""
    
    def __init__(self, instance_url: str, username: str, password: str):
        self.instance_url = instance_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        
        # Basic authentication
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.session.headers.update({
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        })
    
    def create_incident(self, 
                       short_description: str,
                       description: str,
                       urgency: str = "3",
                       impact: str = "3",
                       category: str = "Security",
                       assignment_group: Optional[str] = None,
                       kwargs) -> Dict:
        """Create a ServiceNow incident"""
        url = f"{self.instance_url}/api/now/table/incident"
        
        payload = {
            "short_description": short_description,
            "description": description,
            "urgency": urgency,
            "impact": impact,
            "category": category,
            kwargs
        }
        
        if assignment_group:
            payload["assignment_group"] = assignment_group
        
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json().get('result', {})
    
    def update_incident(self, sys_id: str, updates: Dict) -> Dict:
        """Update an incident"""
        url = f"{self.instance_url}/api/now/table/incident/{sys_id}"
        
        response = self.session.patch(url, json=updates)
        response.raise_for_status()
        return response.json().get('result', {})
    
    def get_incident(self, sys_id: str) -> Dict:
        """Get incident details"""
        url = f"{self.instance_url}/api/now/table/incident/{sys_id}"
        
        response = self.session.get(url)
        response.raise_for_status()
        return response.json().get('result', {})
    
    def add_incident_comment(self, sys_id: str, comment: str) -> Dict:
        """Add comment to incident"""
        url = f"{self.instance_url}/api/now/table/incident/{sys_id}"
        
        payload = {
            "comments": comment
        }
        
        response = self.session.patch(url, json=payload)
        response.raise_for_status()
        return response.json().get('result', {})
    
    def create_change_request(self,
                             short_description: str,
                             description: str,
                             risk: str = "medium",
                             kwargs) -> Dict:
        """Create a change request"""
        url = f"{self.instance_url}/api/now/table/change_request"
        
        payload = {
            "short_description": short_description,
            "description": description,
            "risk": risk,
            kwargs
        }
        
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json().get('result', {})
    
    def query_table(self, table_name: str, query: str = "", limit: int = 100) -> List[Dict]:
        """Query any ServiceNow table"""
        url = f"{self.instance_url}/api/now/table/{table_name}"
        
        params = {
            "sysparm_query": query,
            "sysparm_limit": limit
        }
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json().get('result', [])

# Integration Examples
def create_servicenow_incident_from_xdr(xdr_incident: dict, servicenow_client: ServiceNowClient):
    """Create ServiceNow incident from XDR incident"""
    incident = servicenow_client.create_incident(
        short_description=f"XDR Incident: {xdr_incident.get('incident_id')}",
        description=f"""
        Cortex XDR Incident Details:
        - Incident ID: {xdr_incident.get('incident_id')}
        - Severity: {xdr_incident.get('severity')}
        - Status: {xdr_incident.get('status')}
        - Alert Count: {xdr_incident.get('alert_count')}
        - Creation Time: {xdr_incident.get('creation_time')}
        """,
        urgency=map_xdr_severity_to_urgency(xdr_incident.get('severity')),
        impact="2",  # Medium
        category="Security",
        assignment_group="Security Operations",
        u_source="Cortex XDR"
    )
    
    return incident

def map_xdr_severity_to_urgency(severity: str) -> str:
    """Map XDR severity to ServiceNow urgency"""
    mapping = {
        "critical": "1",  # Critical
        "high": "2",      # High
        "medium": "3",    # Medium
        "low": "4"        # Low
    }
    return mapping.get(severity.lower(), "3")
```

---

# 8. Jira Integration

# 8.1 Jira API Integration

```python
#!/usr/bin/env python3
"""
Jira API Integration
Purpose: Create and manage Jira issues/tickets
"""

import requests
from typing import Dict, List, Optional
import base64
import os

class JiraClient:
    """Jira REST API Client"""
    
    def __init__(self, base_url: str, username: str, api_token: str):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.api_token = api_token
        self.session = requests.Session()
        
        # Basic authentication
        credentials = base64.b64encode(f"{username}:{api_token}".encode()).decode()
        self.session.headers.update({
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json"
        })
    
    def create_issue(self,
                   project_key: str,
                   summary: str,
                   description: str,
                   issue_type: str = "Bug",
                   priority: Optional[str] = None,
                   labels: Optional[List[str]] = None,
                   kwargs) -> Dict:
        """Create a Jira issue"""
        url = f"{self.base_url}/rest/api/3/issue"
        
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{
                            "type": "text",
                            "text": description
                        }]
                    }]
                },
                "issuetype": {"name": issue_type},
                kwargs
            }
        }
        
        if priority:
            payload["fields"]["priority"] = {"name": priority}
        
        if labels:
            payload["fields"]["labels"] = labels
        
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()
    
    def update_issue(self, issue_key: str, updates: Dict) -> Dict:
        """Update a Jira issue"""
        url = f"{self.base_url}/rest/api/3/issue/{issue_key}"
        
        response = self.session.put(url, json=updates)
        response.raise_for_status()
        return response.json()
    
    def add_comment(self, issue_key: str, comment: str) -> Dict:
        """Add comment to issue"""
        url = f"{self.base_url}/rest/api/3/issue/{issue_key}/comment"
        
        payload = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{
                        "type": "text",
                        "text": comment
                    }]
                }]
            }
        }
        
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()
    
    def transition_issue(self, issue_key: str, transition_id: str) -> Dict:
        """Transition issue to a new status"""
        url = f"{self.base_url}/rest/api/3/issue/{issue_key}/transitions"
        
        payload = {
            "transition": {"id": transition_id}
        }
        
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()
    
    def search_issues(self, jql: str, max_results: int = 100) -> List[Dict]:
        """Search issues using JQL"""
        url = f"{self.base_url}/rest/api/3/search"
        
        params = {
            "jql": jql,
            "maxResults": max_results
        }
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json().get('issues', [])

# Integration Example
def create_jira_issue_from_prisma_alert(prisma_alert: dict, jira_client: JiraClient):
    """Create Jira issue from Prisma Cloud alert"""
    issue = jira_client.create_issue(
        project_key="SEC",
        summary=f"Prisma Cloud Alert: {prisma_alert.get('policy', {}).get('name')}",
        description=f"""
        Prisma Cloud Security Alert
        
        Alert ID: {prisma_alert.get('alertId')}
        Policy: {prisma_alert.get('policy', {}).get('name')}
        Severity: {prisma_alert.get('severity')}
        Resource: {prisma_alert.get('resource', {}).get('id')}
        Cloud Type: {prisma_alert.get('resource', {}).get('cloudType')}
        """,
        issue_type="Security Issue",
        priority=map_prisma_severity_to_jira(prisma_alert.get('severity')),
        labels=["prisma-cloud", "security", prisma_alert.get('severity', '').lower()]
    )
    
    return issue

def map_prisma_severity_to_jira(severity: str) -> str:
    """Map Prisma Cloud severity to Jira priority"""
    mapping = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low"
    }
    return mapping.get(severity.lower(), "Medium")
```

---

# Communication and Collaboration

# 9. Slack Integration

# 9.1 Slack Webhook Integration

```python
#!/usr/bin/env python3
"""
Slack Integration
Purpose: Send notifications and alerts to Slack channels
"""

import requests
import json
from typing import Dict, List, Optional
import os

class SlackClient:
    """Slack Webhook/API Client"""
    
    def __init__(self, webhook_url: Optional[str] = None, bot_token: Optional[str] = None):
        self.webhook_url = webhook_url
        self.bot_token = bot_token
        self.api_base = "https://slack.com/api"
    
    def send_message(self,
                    channel: str,
                    text: str,
                    blocks: Optional[List[Dict]] = None,
                    attachments: Optional[List[Dict]] = None) -> requests.Response:
        """Send message to Slack channel"""
        if self.webhook_url:
            return self._send_via_webhook(channel, text, blocks, attachments)
        elif self.bot_token:
            return self._send_via_api(channel, text, blocks, attachments)
        else:
            raise ValueError("Either webhook_url or bot_token must be provided")
    
    def _send_via_webhook(self, channel: str, text: str, blocks: List[Dict], attachments: List[Dict]):
        """Send via webhook"""
        payload = {
            "channel": channel,
            "text": text
        }
        
        if blocks:
            payload["blocks"] = blocks
        if attachments:
            payload["attachments"] = attachments
        
        response = requests.post(self.webhook_url, json=payload)
        response.raise_for_status()
        return response
    
    def _send_via_api(self, channel: str, text: str, blocks: List[Dict], attachments: List[Dict]):
        """Send via API"""
        url = f"{self.api_base}/chat.postMessage"
        
        headers = {
            "Authorization": f"Bearer {self.bot_token}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "channel": channel,
            "text": text
        }
        
        if blocks:
            payload["blocks"] = blocks
        if attachments:
            payload["attachments"] = attachments
        
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        return response
    
    def create_alert_block(self,
                          title: str,
                          severity: str,
                          description: str,
                          fields: Optional[List[Dict]] = None,
                          actions: Optional[List[Dict]] = None) -> List[Dict]:
        """Create formatted alert block for Slack"""
        color_map = {
            "critical": "#FF0000",
            "high": "#FF6B00",
            "medium": "#FFA500",
            "low": "#FFFF00",
            "info": "#00FF00"
        }
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": title
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": description
                }
            }
        ]
        
        if fields:
            blocks.append({
                "type": "section",
                "fields": fields
            })
        
        if actions:
            blocks.append({
                "type": "actions",
                "elements": actions
            })
        
        return blocks

# Integration Examples
def send_xdr_incident_to_slack(xdr_incident: dict, slack_client: SlackClient):
    """Send XDR incident notification to Slack"""
    blocks = slack_client.create_alert_block(
        title=f"🚨 XDR Incident: {xdr_incident.get('incident_id')}",
        severity=xdr_incident.get('severity', 'medium'),
        description=f"New Cortex XDR incident detected",
        fields=[
            {
                "type": "mrkdwn",
                "text": f"*Severity:*\n{xdr_incident.get('severity')}"
            },
            {
                "type": "mrkdwn",
                "text": f"*Status:*\n{xdr_incident.get('status')}"
            },
            {
                "type": "mrkdwn",
                "text": f"*Alert Count:*\n{xdr_incident.get('alert_count')}"
            },
            {
                "type": "mrkdwn",
                "text": f"*Created:*\n{xdr_incident.get('creation_time')}"
            }
        ],
        actions=[
            {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "View in XDR"
                },
                "url": f"https://xdr.paloaltonetworks.com/incidents/{xdr_incident.get('incident_id')}"
            }
        ]
    )
    
    slack_client.send_message(
        channel="#security-alerts",
        text=f"XDR Incident: {xdr_incident.get('incident_id')}",
        blocks=blocks
    )
```

---

# Additional SOC Integrations

# 10. Salesforce Integration

```python
#!/usr/bin/env python3
"""
Salesforce Integration
Purpose: Create cases and sync security events
"""

import requests
from typing import Dict, Optional
import os

class SalesforceClient:
    """Salesforce REST API Client"""
    
    def __init__(self, instance_url: str, access_token: str):
        self.instance_url = instance_url.rstrip('/')
        self.access_token = access_token
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        })
    
    def create_case(self,
                   subject: str,
                   description: str,
                   priority: str = "Medium",
                   origin: str = "API",
                   kwargs) -> Dict:
        """Create a Salesforce case"""
        url = f"{self.instance_url}/services/data/v57.0/sobjects/Case"
        
        payload = {
            "Subject": subject,
            "Description": description,
            "Priority": priority,
            "Origin": origin,
            kwargs
        }
        
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()
```

# 11. PagerDuty Integration

```python
#!/usr/bin/env python3
"""
PagerDuty Integration
Purpose: Trigger and manage incidents
"""

import requests
from typing import Dict, Optional

class PagerDutyClient:
    """PagerDuty API Client"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.pagerduty.com"
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Token token={api_key}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.pagerduty+json;version=2"
        })
    
    def create_incident(self,
                      service_id: str,
                      summary: str,
                      severity: str = "error",
                      source: str = "Prisma Cloud",
                      kwargs) -> Dict:
        """Create a PagerDuty incident"""
        url = f"{self.base_url}/incidents"
        
        payload = {
            "incident": {
                "type": "incident",
                "title": summary,
                "service": {
                    "id": service_id,
                    "type": "service_reference"
                },
                "priority": {
                    "id": self._get_priority_id(severity)
                },
                "body": {
                    "type": "incident_body",
                    "details": kwargs.get("details", "")
                },
                "incident_key": kwargs.get("incident_key")
            }
        }
        
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()
    
    def _get_priority_id(self, severity: str) -> str:
        """Get priority ID based on severity"""
        # Implementation to fetch priority IDs
        return "P1"  # Placeholder
```

# 12. GitHub Integration

```python
#!/usr/bin/env python3
"""
GitHub Integration
Purpose: Create security issues and manage repositories
"""

import requests
from typing import Dict, Optional
import os

class GitHubClient:
    """GitHub API Client"""
    
    def __init__(self, token: str):
        self.token = token
        self.base_url = "https://api.github.com"
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        })
    
    def create_issue(self,
                    owner: str,
                    repo: str,
                    title: str,
                    body: str,
                    labels: Optional[List[str]] = None) -> Dict:
        """Create a GitHub issue"""
        url = f"{self.base_url}/repos/{owner}/{repo}/issues"
        
        payload = {
            "title": title,
            "body": body
        }
        
        if labels:
            payload["labels"] = labels
        
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()
```

---

# Integration Testing and Validation

# 13. Integration Test Framework

```python
#!/usr/bin/env python3
"""
Integration Test Framework
Purpose: Test and validate integrations
"""

import unittest
from typing import Dict, List

class IntegrationTestSuite(unittest.TestCase):
    """Test suite for integrations"""
    
    def test_xdr_connection(self):
        """Test XDR API connection"""
        client = CortexXDRClient(
            api_key=os.getenv("XDR_API_KEY"),
            api_key_id=os.getenv("XDR_API_KEY_ID")
        )
        incidents = client.get_incidents(limit=1)
        self.assertIsNotNone(incidents)
    
    def test_xsoar_incident_creation(self):
        """Test XSOAR incident creation"""
        client = XSOARClient(
            base_url=os.getenv("XSOAR_URL"),
            api_key=os.getenv("XSOAR_API_KEY")
        )
        incident = client.create_incident(
            name="Test Incident",
            severity=1
        )
        self.assertIsNotNone(incident.get('id'))
    
    def test_splunk_hec_send(self):
        """Test Splunk HEC event sending"""
        client = SplunkHECClient(
            hec_url=os.getenv("SPLUNK_HEC_URL"),
            hec_token=os.getenv("SPLUNK_HEC_TOKEN")
        )
        response = client.send_event(
            event={"test": "data"},
            source="test"
        )
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()
```

---

# Troubleshooting

# Common Issues and Solutions

# 1. Authentication Failures

Problem: API authentication fails

Solutions:
- Verify credentials are correct
- Check token expiration
- Ensure API keys have proper permissions
- Verify SSL certificates

# 2. Rate Limiting

Problem: API rate limits exceeded

Solutions:
- Implement exponential backoff
- Use connection pooling
- Batch requests when possible
- Cache responses

# 3. Webhook Delivery Failures

Problem: Webhooks not being received

Solutions:
- Verify webhook URL is accessible
- Check firewall rules
- Validate webhook signatures
- Implement retry logic

---

# Configuration Files

# Integration Configuration Template

```yaml
# integrations_config.yaml
integrations:
  cortex_xdr:
    api_key: "${XDR_API_KEY}"
    api_key_id: "${XDR_API_KEY_ID}"
    base_url: "https://api.xdr.us.paloaltonetworks.com"
  
  xsoar:
    base_url: "${XSOAR_URL}"
    api_key: "${XSOAR_API_KEY}"
    verify_ssl: true
  
  prisma_cloud:
    api_url: "${PRISMA_API_URL}"
    access_key: "${PRISMA_ACCESS_KEY}"
    secret_key: "${PRISMA_SECRET_KEY}"
  
  splunk:
    hec_url: "${SPLUNK_HEC_URL}"
    hec_token: "${SPLUNK_HEC_TOKEN}"
    index: "security"
  
  servicenow:
    instance_url: "${SNOW_INSTANCE_URL}"
    username: "${SNOW_USERNAME}"
    password: "${SNOW_PASSWORD}"
  
  jira:
    base_url: "${JIRA_URL}"
    username: "${JIRA_USERNAME}"
    api_token: "${JIRA_API_TOKEN}"
  
  slack:
    webhook_url: "${SLACK_WEBHOOK_URL}"
    default_channel: "#security-alerts"
```

---

Version: 1.0  
Last Updated: 2026-01-09  
Maintained By: SOC Team
