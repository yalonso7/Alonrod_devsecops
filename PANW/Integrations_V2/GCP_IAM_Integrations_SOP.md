# GCP IAM Integrations Standard Operating Procedure (SOP)

# Table of Contents

1. [Overview](#overview)
2. [GCP IAM API Integration Basics](#gcp-iam-api-integration-basics)
3. [GCP IAM to Cortex XDR Integration](#gcp-iam-to-cortex-xdr-integration)
4. [GCP IAM to XSOAR Integration](#gcp-iam-to-xsoar-integration)
5. [Cloud Audit Logs Monitoring](#cloud-audit-logs-monitoring)
6. [Webhook Integrations](#webhook-integrations)
7. [Use Cases and Workflows](#use-cases-and-workflows)
8. [Configuration and Setup](#configuration-and-setup)
9. [Troubleshooting](#troubleshooting)

---

# Overview

This SOP provides comprehensive integration code snippets and configuration examples for connecting Google Cloud Platform (GCP) IAM (Identity and Access Management) with Palo Alto Networks security products (Cortex XDR, XSOAR). These integrations enable automated identity-based security operations, incident response, and compliance monitoring for GCP cloud environments.

# Integration Use Cases

- IAM Threat Detection: Monitor GCP IAM events for suspicious access patterns and privilege escalations
- Automated Incident Response: Create security incidents in XDR/XSOAR based on GCP IAM security events
- Access Governance: Track IAM user and service account access changes, policy modifications
- Compliance Monitoring: Monitor IAM compliance violations and policy changes
- Automated Remediation: Respond to IAM-based threats automatically (disable service accounts, revoke keys)
- Cloud Audit Logs Integration: Monitor Cloud Audit Logs for IAM-related security events

---

# GCP IAM API Integration Basics

# 1. GCP IAM Client (Python with Google Cloud libraries)

```python
#!/usr/bin/env python3
"""
GCP IAM API Integration Client
Purpose: Authenticate and interact with GCP IAM API using Google Cloud libraries
"""

from google.cloud import iam
from google.cloud import asset
from google.cloud import logging_v2
from google.oauth2 import service_account
import json
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import os

class GCPIAMClient:
    """GCP IAM API Client using Google Cloud libraries"""
    
    def __init__(self, 
                 project_id: str,
                 credentials_path: Optional[str] = None,
                 credentials_json: Optional[Dict] = None):
        """
        Initialize GCP IAM client
        
        Args:
            project_id: GCP project ID
            credentials_path: Path to service account JSON key file
            credentials_json: Service account credentials as dictionary
        """
        self.project_id = project_id
        
        # Set up credentials
        if credentials_path:
            credentials = service_account.Credentials.from_service_account_file(
                credentials_path
            )
        elif credentials_json:
            credentials = service_account.Credentials.from_service_account_info(
                credentials_json
            )
        else:
            # Use default credentials (Application Default Credentials)
            credentials = None
        
        # Initialize clients
        self.iam_client = iam.IAMCredentialsClient(credentials=credentials)
        self.asset_client = asset.AssetServiceClient(credentials=credentials)
        self.logging_client = logging_v2.LoggingServiceV2Client(credentials=credentials)
        
        # For IAM policy operations, we'll use the Resource Manager API
        from google.cloud import resourcemanager_v3
        self.resource_manager = resourcemanager_v3.ProjectsClient(credentials=credentials)
    
    def get_service_account(self, service_account_email: str) -> Dict:
        """Get service account details"""
        from google.cloud import iam_v1
        iam_service = iam_v1.IAMClient(credentials=self.iam_client._credentials)
        
        name = f"projects/{self.project_id}/serviceAccounts/{service_account_email}"
        try:
            service_account_obj = iam_service.get_service_account(name=name)
            return {
                'email': service_account_obj.email,
                'name': service_account_obj.name,
                'display_name': service_account_obj.display_name,
                'disabled': service_account_obj.disabled,
                'description': service_account_obj.description
            }
        except Exception as e:
            print(f"Error getting service account: {e}")
            return {}
    
    def list_service_accounts(self) -> List[Dict]:
        """List all service accounts in the project"""
        from google.cloud import iam_v1
        iam_service = iam_v1.IAMClient(credentials=self.iam_client._credentials)
        
        parent = f"projects/{self.project_id}"
        service_accounts = []
        
        try:
            for account in iam_service.list_service_accounts(name=parent):
                service_accounts.append({
                    'email': account.email,
                    'name': account.name,
                    'display_name': account.display_name,
                    'disabled': account.disabled,
                    'description': account.description
                })
        except Exception as e:
            print(f"Error listing service accounts: {e}")
        
        return service_accounts
    
    def get_service_account_keys(self, service_account_email: str) -> List[Dict]:
        """Get service account keys"""
        from google.cloud import iam_v1
        iam_service = iam_v1.IAMClient(credentials=self.iam_client._credentials)
        
        name = f"projects/{self.project_id}/serviceAccounts/{service_account_email}"
        keys = []
        
        try:
            for key in iam_service.list_service_account_keys(name=name):
                keys.append({
                    'name': key.name,
                    'key_type': str(key.key_type),
                    'valid_after_time': key.valid_after_time.isoformat() if key.valid_after_time else None,
                    'valid_before_time': key.valid_before_time.isoformat() if key.valid_before_time else None,
                    'key_algorithm': str(key.key_algorithm)
                })
        except Exception as e:
            print(f"Error getting service account keys: {e}")
        
        return keys
    
    def get_iam_policy(self, resource: str) -> Dict:
        """Get IAM policy for a resource"""
        from google.cloud import iam_v1
        iam_service = iam_v1.IAMClient(credentials=self.iam_client._credentials)
        
        try:
            policy = iam_service.get_iam_policy(request={"resource": resource})
            return {
                'version': policy.version,
                'bindings': [
                    {
                        'role': binding.role,
                        'members': list(binding.members),
                        'condition': binding.condition.SerializeToString() if binding.condition else None
                    }
                    for binding in policy.bindings
                ],
                'etag': policy.etag.hex() if policy.etag else None
            }
        except Exception as e:
            print(f"Error getting IAM policy: {e}")
            return {}
    
    def get_project_iam_policy(self) -> Dict:
        """Get IAM policy for the project"""
        resource = f"projects/{self.project_id}"
        return self.get_iam_policy(resource)
    
    def get_service_account_iam_policy(self, service_account_email: str) -> Dict:
        """Get IAM policy for a service account"""
        resource = f"projects/{self.project_id}/serviceAccounts/{service_account_email}"
        return self.get_iam_policy(resource)
    
    def disable_service_account(self, service_account_email: str) -> Dict:
        """Disable a service account"""
        from google.cloud import iam_v1
        iam_service = iam_v1.IAMClient(credentials=self.iam_client._credentials)
        
        name = f"projects/{self.project_id}/serviceAccounts/{service_account_email}"
        
        try:
            iam_service.disable_service_account(name=name)
            return {"status": "success", "message": f"Service account {service_account_email} disabled"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def enable_service_account(self, service_account_email: str) -> Dict:
        """Enable a service account"""
        from google.cloud import iam_v1
        iam_service = iam_v1.IAMClient(credentials=self.iam_client._credentials)
        
        name = f"projects/{self.project_id}/serviceAccounts/{service_account_email}"
        
        try:
            iam_service.enable_service_account(name=name)
            return {"status": "success", "message": f"Service account {service_account_email} enabled"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def delete_service_account_key(self, service_account_email: str, key_name: str) -> Dict:
        """Delete a service account key"""
        from google.cloud import iam_v1
        iam_service = iam_v1.IAMClient(credentials=self.iam_client._credentials)
        
        try:
            iam_service.delete_service_account_key(name=key_name)
            return {"status": "success", "message": f"Key {key_name} deleted"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def get_audit_logs(self,
                      start_time: Optional[datetime] = None,
                      end_time: Optional[datetime] = None,
                      filter_str: Optional[str] = None,
                      page_size: int = 100) -> List[Dict]:
        """
        Get Cloud Audit Logs for IAM events
        
        Args:
            start_time: Start time for log query
            end_time: End time for log query
            filter_str: Additional filter expression
            page_size: Maximum number of logs per page
        """
        if not start_time:
            start_time = datetime.now() - timedelta(hours=1)
        if not end_time:
            end_time = datetime.now()
        
        # Build filter
        log_filter = f"""
        resource.type="service_account" OR
        resource.type="project" OR
        protoPayload.serviceName="iam.googleapis.com"
        """
        
        if filter_str:
            log_filter += f" AND {filter_str}"
        
        # Add time filter
        log_filter += f"""
        AND timestamp >= "{start_time.isoformat()}Z"
        AND timestamp <= "{end_time.isoformat()}Z"
        """
        
        logs = []
        parent = f"projects/{self.project_id}"
        
        try:
            entries = self.logging_client.list_log_entries(
                resource_names=[parent],
                filter_=log_filter,
                page_size=page_size
            )
            
            for entry in entries:
                log_data = {
                    'log_name': entry.log_name,
                    'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
                    'severity': str(entry.severity),
                    'resource': {
                        'type': entry.resource.type,
                        'labels': dict(entry.resource.labels)
                    },
                    'json_payload': None,
                    'proto_payload': None
                }
                
                if entry.json_payload:
                    log_data['json_payload'] = json.loads(entry.json_payload)
                
                if entry.proto_payload:
                    # Convert proto payload to dict
                    log_data['proto_payload'] = {
                        'service_name': entry.proto_payload.service_name if hasattr(entry.proto_payload, 'service_name') else None,
                        'method_name': entry.proto_payload.method_name if hasattr(entry.proto_payload, 'method_name') else None,
                        'authentication_info': str(entry.proto_payload.authentication_info) if hasattr(entry.proto_payload, 'authentication_info') else None
                    }
                
                logs.append(log_data)
        except Exception as e:
            print(f"Error getting audit logs: {e}")
        
        return logs
    
    def get_security_events(self,
                           start_time: Optional[datetime] = None,
                           limit: int = 100) -> List[Dict]:
        """Get security-related IAM events from Cloud Audit Logs"""
        security_methods = [
            'google.iam.admin.v1.IAM.CreateServiceAccount',
            'google.iam.admin.v1.IAM.DeleteServiceAccount',
            'google.iam.admin.v1.IAM.SetIamPolicy',
            'google.iam.admin.v1.IAM.CreateServiceAccountKey',
            'google.iam.admin.v1.IAM.DeleteServiceAccountKey',
            'google.iam.admin.v1.IAM.DisableServiceAccount',
            'google.iam.admin.v1.IAM.EnableServiceAccount'
        ]
        
        filter_str = " OR ".join([f'protoPayload.methodName="{method}"' for method in security_methods])
        
        return self.get_audit_logs(start_time=start_time, filter_str=filter_str, page_size=limit)
    
    def search_all_iam_policies(self) -> List[Dict]:
        """Search all IAM policies in the project using Cloud Asset Inventory"""
        parent = f"projects/{self.project_id}"
        asset_type = "iam.googleapis.com/ServiceAccount"
        
        policies = []
        
        try:
            # Search for service accounts
            response = self.asset_client.search_all_resources(
                scope=parent,
                asset_types=[asset_type]
            )
            
            for resource in response:
                policies.append({
                    'name': resource.name,
                    'asset_type': resource.asset_type,
                    'project': resource.project,
                    'iam_policy': self.get_iam_policy(resource.name) if resource.name else {}
                })
        except Exception as e:
            print(f"Error searching IAM policies: {e}")
        
        return policies

# Usage Example
if __name__ == "__main__":
    client = GCPIAMClient(
        project_id=os.getenv("GCP_PROJECT_ID"),
        credentials_path=os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    )
    
    # Get recent security events
    events = client.get_security_events(
        start_time=datetime.now() - timedelta(hours=24)
    )
    print(f"Found {len(events)} security events")
    
    # List service accounts
    service_accounts = client.list_service_accounts()
    print(f"Found {len(service_accounts)} service accounts")
    
    # Get project IAM policy
    policy = client.get_project_iam_policy()
    print(f"Project has {len(policy.get('bindings', []))} IAM bindings")
```

---

# GCP IAM to Cortex XDR Integration

# 2.1 GCP IAM Events to XDR Incidents

```python
#!/usr/bin/env python3
"""
GCP IAM to Cortex XDR Integration
Purpose: Create XDR incidents from GCP IAM security events
"""

from datetime import datetime, timedelta
from typing import Dict, List
import os
import time
import json

class GCPIAMXDRIntegration:
    """Integrate GCP IAM with Cortex XDR"""
    
    def __init__(self, gcp_iam_client, xdr_client):
        self.gcp_iam = gcp_iam_client
        self.xdr = xdr_client
    
    def monitor_iam_events(self, check_interval_minutes: int = 15):
        """Continuously monitor GCP IAM events and create XDR incidents"""
        last_check = datetime.now() - timedelta(minutes=check_interval_minutes)
        
        while True:
            try:
                # Get security events since last check
                events = self.gcp_iam.get_security_events(start_time=last_check)
                
                # Process events
                for event in events:
                    self.process_iam_event(event)
                
                last_check = datetime.now()
                time.sleep(check_interval_minutes * 60)
                
            except Exception as e:
                print(f"Error monitoring IAM events: {e}")
                time.sleep(60)
    
    def process_iam_event(self, event: Dict):
        """Process a single IAM event and create XDR incident if needed"""
        proto_payload = event.get('proto_payload', {})
        method_name = proto_payload.get('method_name', '')
        severity = self.determine_severity(method_name)
        
        # Only create incidents for high-severity events
        if severity in ['high', 'critical']:
            incident_data = self.create_xdr_incident_from_event(event)
            self.xdr.create_incident(incident_data)
    
    def determine_severity(self, method_name: str) -> str:
        """Determine severity based on method name"""
        critical_methods = [
            'google.iam.admin.v1.IAM.DeleteServiceAccount',
            'google.iam.admin.v1.IAM.SetIamPolicy',
            'google.iam.admin.v1.IAM.CreateServiceAccountKey'
        ]
        
        high_methods = [
            'google.iam.admin.v1.IAM.CreateServiceAccount',
            'google.iam.admin.v1.IAM.DisableServiceAccount',
            'google.iam.admin.v1.IAM.DeleteServiceAccountKey'
        ]
        
        if any(method in method_name for method in critical_methods):
            return 'critical'
        elif any(method in method_name for method in high_methods):
            return 'high'
        else:
            return 'medium'
    
    def create_xdr_incident_from_event(self, event: Dict) -> Dict:
        """Create XDR incident payload from GCP IAM event"""
        log_name = event.get('log_name', '')
        timestamp = event.get('timestamp', datetime.now().isoformat())
        proto_payload = event.get('proto_payload', {})
        method_name = proto_payload.get('method_name', 'Unknown')
        resource = event.get('resource', {})
        resource_type = resource.get('type', 'Unknown')
        
        # Extract service account email if available
        service_account_email = resource.get('labels', {}).get('email_id', 'Unknown')
        
        # Build incident description
        description = f"""
        GCP IAM Security Event Detected
        
        Method: {method_name}
        Log Name: {log_name}
        Timestamp: {timestamp}
        Resource Type: {resource_type}
        Service Account: {service_account_email}
        Severity: {event.get('severity', 'UNKNOWN')}
        
        Event Details:
        {json.dumps(event, indent=2)}
        """
        
        return {
            "incident_name": f"GCP IAM: {method_name} - {service_account_email}",
            "severity": self.determine_severity(method_name),
            "description": description,
            "labels": [
                {"key": "source", "value": "GCP IAM"},
                {"key": "method_name", "value": method_name},
                {"key": "service_account", "value": service_account_email},
                {"key": "resource_type", "value": resource_type}
            ],
            "custom_fields": {
                "gcp_log_name": log_name,
                "gcp_method_name": method_name,
                "gcp_service_account": service_account_email,
                "gcp_resource_type": resource_type,
                "gcp_timestamp": timestamp,
                "gcp_project_id": self.gcp_iam.project_id
            }
        }
    
    def sync_suspicious_access_to_xdr(self, service_account_email: str, event: Dict):
        """Create XDR incident for suspicious IAM access"""
        service_account = self.gcp_iam.get_service_account(service_account_email)
        iam_policy = self.gcp_iam.get_service_account_iam_policy(service_account_email)
        keys = self.gcp_iam.get_service_account_keys(service_account_email)
        
        # Check for suspicious patterns
        is_suspicious = self.detect_suspicious_pattern(event, service_account, iam_policy, keys)
        
        if is_suspicious:
            incident = {
                "incident_name": f"GCP IAM: Suspicious Access - {service_account_email}",
                "severity": "high",
                "description": f"""
                Suspicious IAM access detected for service account: {service_account_email}
                
                Service Account Details:
                - Email: {service_account.get('email', 'Unknown')}
                - Display Name: {service_account.get('display_name', 'Unknown')}
                - Disabled: {service_account.get('disabled', False)}
                - Keys: {len(keys)}
                
                Event Details:
                - Method: {event.get('proto_payload', {}).get('method_name', 'Unknown')}
                - Timestamp: {event.get('timestamp', '')}
                
                Risk Indicators:
                - Unusual policy changes
                - Access from unknown source
                - Privilege escalation attempt
                - Multiple active keys
                """,
                "labels": [
                    {"key": "source", "value": "GCP IAM"},
                    {"key": "event_type", "value": "suspicious_access"},
                    {"key": "threat_type", "value": "privilege_escalation"}
                ]
            }
            
            xdr_incident = self.xdr.create_incident(incident)
            
            # Add comment with remediation steps
            self.xdr.add_incident_comment(
                xdr_incident.get('incident_id'),
                "Recommended Actions:\n1. Review service account permissions\n2. Check for unauthorized policy changes\n3. Consider disabling service account\n4. Review recent service account activity"
            )
            
            return xdr_incident
    
    def detect_suspicious_pattern(self, event: Dict, service_account: Dict, iam_policy: Dict, keys: List[Dict]) -> bool:
        """Detect suspicious IAM access patterns"""
        proto_payload = event.get('proto_payload', {})
        method_name = proto_payload.get('method_name', '')
        
        # Check for privilege escalation
        if 'SetIamPolicy' in method_name:
            # Check if policy grants admin permissions
            bindings = iam_policy.get('bindings', [])
            for binding in bindings:
                role = binding.get('role', '')
                if 'roles/owner' in role or 'roles/editor' in role or 'roles/iam.admin' in role:
                    return True
        
        # Check for multiple keys
        if len(keys) > 3:
            return True
        
        # Check for disabled service account being enabled
        if 'EnableServiceAccount' in method_name and service_account.get('disabled'):
            return True
        
        return False
    
    def create_incident_for_unused_key(self, service_account_email: str, key: Dict):
        """Create XDR incident for unused or old service account key"""
        key_name = key.get('name', '')
        valid_after = key.get('valid_after_time')
        
        # Check if key is old (90+ days) and potentially unused
        if valid_after:
            valid_after_dt = datetime.fromisoformat(valid_after.replace('Z', '+00:00'))
            age_days = (datetime.now(valid_after_dt.tzinfo) - valid_after_dt).days
            
            if age_days > 90:
                incident = {
                    "incident_name": f"GCP IAM: Old Service Account Key - {service_account_email}",
                    "severity": "medium",
                    "description": f"""
                    Old service account key detected: {service_account_email}
                    
                    Key: {key_name}
                    Valid After: {valid_after}
                    Age: {age_days} days
                    
                    Recommendation: Rotate or delete this key as it may be a security risk.
                    """,
                    "labels": [
                        {"key": "source", "value": "GCP IAM"},
                        {"key": "event_type", "value": "unused_key"},
                        {"key": "compliance", "value": "key_rotation"}
                    ]
                }
                
                return self.xdr.create_incident(incident)
        
        return None

# Usage Example
if __name__ == "__main__":
    from gcp_iam_client import GCPIAMClient
    from cortex_xdr_client import CortexXDRClient
    
    # Initialize clients
    gcp_iam = GCPIAMClient(
        project_id=os.getenv("GCP_PROJECT_ID"),
        credentials_path=os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    )
    
    xdr = CortexXDRClient(
        api_key=os.getenv("XDR_API_KEY"),
        api_key_id=os.getenv("XDR_API_KEY_ID")
    )
    
    # Create integration
    integration = GCPIAMXDRIntegration(gcp_iam, xdr)
    
    # Monitor events
    integration.monitor_iam_events(check_interval_minutes=15)
```

# 2.2 Automated Response to XDR Incidents

```python
#!/usr/bin/env python3
"""
Automated Response: XDR Incident → GCP IAM Actions
Purpose: Automatically respond to XDR incidents by taking GCP IAM actions
"""

class XDRGCPIAMResponse:
    """Automated response to XDR incidents using GCP IAM"""
    
    def __init__(self, xdr_client, gcp_iam_client):
        self.xdr = xdr_client
        self.gcp_iam = gcp_iam_client
    
    def handle_xdr_incident(self, incident_id: str):
        """Handle XDR incident and take GCP IAM actions"""
        incident = self.xdr.get_incident(incident_id)
        
        # Check if incident is related to GCP IAM
        if self.is_iam_related(incident):
            service_account_email = self.extract_service_account_email(incident)
            key_name = self.extract_key_name(incident)
            
            if service_account_email:
                # Determine response action
                action = self.determine_response_action(incident)
                
                if action == 'disable_service_account':
                    result = self.gcp_iam.disable_service_account(service_account_email)
                    self.xdr.add_incident_comment(
                        incident_id,
                        f"Automated Response: {result.get('message', 'Action completed')}"
                    )
                elif action == 'delete_key' and key_name:
                    result = self.gcp_iam.delete_service_account_key(service_account_email, key_name)
                    self.xdr.add_incident_comment(
                        incident_id,
                        f"Automated Response: {result.get('message', 'Action completed')}"
                    )
    
    def is_iam_related(self, incident: Dict) -> bool:
        """Check if incident is GCP IAM-related"""
        labels = incident.get('labels', [])
        for label in labels:
            if label.get('key') == 'source' and label.get('value') == 'GCP IAM':
                return True
            if label.get('key') == 'threat_type') and 'privilege' in label.get('value', '').lower():
                return True
        return False
    
    def extract_service_account_email(self, incident: Dict) -> Optional[str]:
        """Extract service account email from incident"""
        custom_fields = incident.get('custom_fields', {})
        return custom_fields.get('gcp_service_account')
    
    def extract_key_name(self, incident: Dict) -> Optional[str]:
        """Extract key name from incident"""
        custom_fields = incident.get('custom_fields', {})
        return custom_fields.get('gcp_key_name')
    
    def determine_response_action(self, incident: Dict) -> str:
        """Determine appropriate response action"""
        severity = incident.get('severity', 'medium')
        method_name = incident.get('custom_fields', {}).get('gcp_method_name', '')
        
        if severity == 'critical':
            if 'ServiceAccountKey' in method_name:
                return 'delete_key'
            else:
                return 'disable_service_account'
        elif severity == 'high':
            if 'ServiceAccountKey' in method_name:
                return 'delete_key'
        
        return 'monitor'
```

---

# GCP IAM to XSOAR Integration

# 3.1 GCP IAM Events to XSOAR Incidents

```python
#!/usr/bin/env python3
"""
GCP IAM to XSOAR Integration
Purpose: Create XSOAR incidents from GCP IAM security events and automate playbooks
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
import os
import json

class GCPIAMXSOARIntegration:
    """Integrate GCP IAM with Cortex XSOAR"""
    
    def __init__(self, gcp_iam_client, xsoar_client):
        self.gcp_iam = gcp_iam_client
        self.xsoar = xsoar_client
    
    def create_xsoar_incident_from_event(self, event: Dict) -> Dict:
        """Create XSOAR incident from GCP IAM event"""
        log_name = event.get('log_name', '')
        proto_payload = event.get('proto_payload', {})
        method_name = proto_payload.get('method_name', 'Unknown')
        resource = event.get('resource', {})
        service_account_email = resource.get('labels', {}).get('email_id', 'Unknown')
        
        # Determine incident type and severity
        incident_type, severity = self.map_method_to_incident_type(method_name)
        
        # Create incident
        incident = self.xsoar.create_incident(
            name=f"GCP IAM: {method_name} - {service_account_email}",
            severity=severity,
            type=incident_type,
            labels=[
                {"type": "source", "value": "GCP IAM"},
                {"type": "method_name", "value": method_name},
                {"type": "service_account", "value": service_account_email},
                {"type": "project_id", "value": self.gcp_iam.project_id}
            ],
            custom_fields={
                "gcp_log_name": log_name,
                "gcp_method_name": method_name,
                "gcp_service_account": service_account_email,
                "gcp_resource_type": resource.get('type', 'Unknown'),
                "gcp_timestamp": event.get('timestamp', ''),
                "gcp_project_id": self.gcp_iam.project_id
            }
        )
        
        # Add detailed description
        description = self.build_incident_description(event, service_account_email, proto_payload)
        self.xsoar.add_incident_entry(
            incident.get('id'),
            description,
            entry_type="note"
        )
        
        return incident
    
    def map_method_to_incident_type(self, method_name: str) -> tuple:
        """Map GCP IAM method name to XSOAR incident type and severity"""
        mapping = {
            'google.iam.admin.v1.IAM.DeleteServiceAccount': ('Identity Access Management', 4),  # Critical
            'google.iam.admin.v1.IAM.SetIamPolicy': ('Access', 4),
            'google.iam.admin.v1.IAM.CreateServiceAccount': ('Identity Access Management', 3),  # High
            'google.iam.admin.v1.IAM.DisableServiceAccount': ('Identity Access Management', 3),
            'google.iam.admin.v1.IAM.CreateServiceAccountKey': ('Authentication', 3),
            'google.iam.admin.v1.IAM.DeleteServiceAccountKey': ('Authentication', 2),  # Medium
            'google.iam.admin.v1.IAM.EnableServiceAccount': ('Identity Access Management', 2)
        }
        
        # Try to match partial method name
        for key, value in mapping.items():
            if key in method_name:
                return value
        
        return ('Unclassified', 1)
    
    def build_incident_description(self, event: Dict, service_account_email: str, proto_payload: Dict) -> str:
        """Build detailed incident description"""
        return f"""
# GCP IAM Security Event

# Event Information
- Method: {proto_payload.get('method_name', 'Unknown')}
- Log Name: {event.get('log_name', 'Unknown')}
- Timestamp: {event.get('timestamp', '')}
- Severity: {event.get('severity', 'UNKNOWN')}
- Project ID: {self.gcp_iam.project_id}

# Service Account Information
- Email: {service_account_email}

# Resource Information
- Type: {event.get('resource', {}).get('type', 'Unknown')}

# Event Details
```json
{json.dumps(event, indent=2)}
```

# Recommended Actions
1. Verify service account identity and authorization
2. Review recent IAM activity for this service account
3. Check for related security events
4. Review service account permissions and IAM bindings
5. Consider additional access controls
        """
    
    def trigger_playbook_for_event(self, event: Dict):
        """Trigger XSOAR playbook based on event type"""
        proto_payload = event.get('proto_payload', {})
        method_name = proto_payload.get('method_name', '')
        
        # Create incident first
        incident = self.create_xsoar_incident_from_event(event)
        
        # Trigger appropriate playbook
        if 'DeleteServiceAccount' in method_name:
            playbook_name = "Investigate GCP Service Account Deletion"
        elif 'SetIamPolicy' in method_name:
            playbook_name = "Investigate GCP IAM Policy Change"
        elif 'CreateServiceAccountKey' in method_name:
            playbook_name = "Investigate Service Account Key Creation"
        elif 'DisableServiceAccount' in method_name:
            playbook_name = "Investigate Service Account Disable"
        else:
            playbook_name = "Generic GCP IAM Investigation"
        
        # Execute playbook
        self.xsoar.execute_command(
            command="executePlaybook",
            arguments={
                "incidentId": incident.get('id'),
                "playbookName": playbook_name
            }
        )
    
    def sync_iam_service_accounts_to_xsoar(self):
        """Sync GCP IAM service account data to XSOAR for reference"""
        service_accounts = self.gcp_iam.list_service_accounts()
        
        for account in service_accounts[:100]:  # Limit to first 100
            account_data = {
                "name": f"GCP Service Account: {account.get('email')}",
                "type": "Identity",
                "rawJSON": json.dumps(account),
                "labels": [
                    {"type": "source", "value": "GCP IAM"},
                    {"type": "service_account", "value": account.get('email')},
                    {"type": "project_id", "value": self.gcp_iam.project_id}
                ]
            }
            
            # Create or update indicator in XSOAR
            self.xsoar.execute_command(
                command="createIndicator",
                arguments=account_data
            )

# Usage Example
if __name__ == "__main__":
    from gcp_iam_client import GCPIAMClient
    from xsoar_client import XSOARClient
    
    gcp_iam = GCPIAMClient(
        project_id=os.getenv("GCP_PROJECT_ID"),
        credentials_path=os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    )
    
    xsoar = XSOARClient(
        base_url=os.getenv("XSOAR_URL"),
        api_key=os.getenv("XSOAR_API_KEY")
    )
    
    integration = GCPIAMXSOARIntegration(gcp_iam, xsoar)
    
    # Get recent security events
    events = gcp_iam.get_security_events(
        start_time=datetime.now() - timedelta(hours=1)
    )
    
    # Create incidents for high-severity events
    for event in events:
        proto_payload = event.get('proto_payload', {})
        method_name = proto_payload.get('method_name', '')
        if 'DeleteServiceAccount' in method_name or 'SetIamPolicy' in method_name:
            integration.trigger_playbook_for_event(event)
```

# 3.2 XSOAR Playbook Integration with GCP IAM

```python
#!/usr/bin/env python3
"""
XSOAR Playbook: GCP IAM Service Account Investigation
Purpose: Automated playbook for investigating GCP IAM service account events
"""

class GCPIAMInvestigationPlaybook:
    """XSOAR playbook for GCP IAM investigations"""
    
    def __init__(self, xsoar_client, gcp_iam_client):
        self.xsoar = xsoar_client
        self.gcp_iam = gcp_iam_client
    
    def execute_investigation(self, incident_id: str):
        """Execute full investigation playbook"""
        incident = self.xsoar.get_incident(incident_id)
        
        # Step 1: Extract service account information
        service_account_email = incident.get('customFields', {}).get('gcp_service_account')
        if not service_account_email:
            self.xsoar.add_incident_entry(
                incident_id,
                "Error: Could not extract service account email from incident",
                entry_type="note"
            )
            return
        
        # Step 2: Gather service account details
        account_info = self.gather_service_account_information(service_account_email)
        self.xsoar.add_incident_entry(
            incident_id,
            f"Service Account Information:\n{json.dumps(account_info, indent=2)}",
            entry_type="note"
        )
        
        # Step 3: Check IAM policy and keys
        iam_policy = self.gcp_iam.get_service_account_iam_policy(service_account_email)
        keys = self.gcp_iam.get_service_account_keys(service_account_email)
        
        self.xsoar.add_incident_entry(
            incident_id,
            f"IAM Bindings: {len(iam_policy.get('bindings', []))}\nActive Keys: {len(keys)}",
            entry_type="note"
        )
        
        # Step 4: Get recent activity
        recent_events = self.gcp_iam.get_audit_logs(
            filter_str=f'resource.labels.email_id="{service_account_email}"',
            start_time=datetime.now() - timedelta(days=7)
        )
        
        self.xsoar.add_incident_entry(
            incident_id,
            f"Recent Activity: {len(recent_events)} events found",
            entry_type="note"
        )
        
        # Step 5: Risk assessment
        risk_score = self.assess_risk(account_info, iam_policy, keys, recent_events)
        
        # Step 6: Recommend actions
        recommendations = self.generate_recommendations(risk_score, incident)
        self.xsoar.add_incident_entry(
            incident_id,
            f"Risk Assessment: {risk_score}/10\n\nRecommendations:\n{recommendations}",
            entry_type="note"
        )
        
        # Step 7: Update incident severity if needed
        if risk_score >= 8:
            self.xsoar.update_incident(incident_id, {"severity": 4})
    
    def gather_service_account_information(self, service_account_email: str) -> Dict:
        """Gather comprehensive service account information"""
        account = self.gcp_iam.get_service_account(service_account_email)
        iam_policy = self.gcp_iam.get_service_account_iam_policy(service_account_email)
        keys = self.gcp_iam.get_service_account_keys(service_account_email)
        
        return {
            "service_account": {
                "email": account.get('email'),
                "name": account.get('name'),
                "display_name": account.get('display_name'),
                "disabled": account.get('disabled', False),
                "description": account.get('description')
            },
            "iam_bindings": len(iam_policy.get('bindings', [])),
            "active_keys": len(keys)
        }
    
    def assess_risk(self, account_info: Dict, iam_policy: Dict, keys: List, events: List) -> int:
        """Assess risk score (0-10)"""
        risk = 0
        
        # Check for many IAM bindings
        if len(iam_policy.get('bindings', [])) > 5:
            risk += 2
        
        # Check for admin roles
        bindings = iam_policy.get('bindings', [])
        admin_roles = ['roles/owner', 'roles/editor', 'roles/iam.admin']
        for binding in bindings:
            if any(role in binding.get('role', '') for role in admin_roles):
                risk += 3
        
        # Check for multiple keys
        if len(keys) > 3:
            risk += 2
        
        # Check for recent policy changes
        policy_events = [e for e in events if 'SetIamPolicy' in str(e)]
        if len(policy_events) > 3:
            risk += 3
        
        return min(risk, 10)
    
    def generate_recommendations(self, risk_score: int, incident: Dict) -> str:
        """Generate recommendations based on risk score"""
        recommendations = []
        
        if risk_score >= 8:
            recommendations.append("1. IMMEDIATE: Review all service account permissions")
            recommendations.append("2. Disable unused service account keys")
            recommendations.append("3. Review recent IAM policy changes")
            recommendations.append("4. Consider disabling service account if compromised")
            recommendations.append("5. Notify security team")
        elif risk_score >= 5:
            recommendations.append("1. Review service account IAM bindings")
            recommendations.append("2. Check for unused keys")
            recommendations.append("3. Implement least privilege principles")
            recommendations.append("4. Monitor service account activity")
        else:
            recommendations.append("1. Monitor service account activity")
            recommendations.append("2. Review access patterns")
        
        return "\n".join(recommendations)
```

---

# Cloud Audit Logs Monitoring

# 4.1 Real-time Cloud Audit Logs Processing

```python
#!/usr/bin/env python3
"""
Real-time Cloud Audit Logs Processing
Purpose: Process Cloud Audit Logs in real-time for IAM monitoring
"""

from datetime import datetime
from typing import Dict, List
import json

class CloudAuditLogsProcessor:
    """Process Cloud Audit Logs for IAM monitoring"""
    
    def __init__(self, gcp_iam_client, xdr_client, xsoar_client):
        self.gcp_iam = gcp_iam_client
        self.xdr = xdr_client
        self.xsoar = xsoar_client
    
    def process_audit_log(self, log_entry: Dict):
        """Process a single Cloud Audit Log entry"""
        proto_payload = log_entry.get('proto_payload', {})
        method_name = proto_payload.get('method_name', '')
        
        # Only process IAM events
        if 'iam.googleapis.com' not in str(log_entry) and 'iam.admin' not in method_name:
            return
        
        # Check if this is a security-relevant event
        if self.is_security_event(method_name):
            # Create incidents in both XDR and XSOAR
            self.create_incidents_from_log(log_entry)
    
    def is_security_event(self, method_name: str) -> bool:
        """Check if method is security-relevant"""
        security_methods = [
            'CreateServiceAccount',
            'DeleteServiceAccount',
            'SetIamPolicy',
            'CreateServiceAccountKey',
            'DeleteServiceAccountKey',
            'DisableServiceAccount',
            'EnableServiceAccount'
        ]
        return any(method in method_name for method in security_methods)
    
    def create_incidents_from_log(self, log_entry: Dict):
        """Create incidents in XDR and XSOAR from Cloud Audit Log"""
        # Create XDR incident
        xdr_integration = GCPIAMXDRIntegration(self.gcp_iam, self.xdr)
        xdr_integration.process_iam_event(log_entry)
        
        # Create XSOAR incident
        xsoar_integration = GCPIAMXSOARIntegration(self.gcp_iam, self.xsoar)
        xsoar_integration.create_xsoar_incident_from_event(log_entry)

# Usage with Cloud Pub/Sub
"""
This processor can be used with Cloud Pub/Sub to process Cloud Audit Logs in real-time.
Configure Cloud Logging export to Pub/Sub and subscribe to process logs.
"""
```

---

# Webhook Integrations

# 5.1 Cloud Pub/Sub to XDR/XSOAR Webhook

```python
#!/usr/bin/env python3
"""
Cloud Pub/Sub Webhook Integration
Purpose: Receive Cloud Pub/Sub messages and route to XDR/XSOAR
"""

from flask import Flask, request, jsonify
import os
import json
import base64

app = Flask(__name__)

# Initialize clients (would be done in production setup)
# gcp_iam_client = GCPIAMClient(...)
# xdr_client = CortexXDRClient(...)
# xsoar_client = XSOARClient(...)

@app.route('/gcp/pubsub', methods=['POST'])
def pubsub_webhook():
    """Receive Cloud Pub/Sub webhook"""
    try:
        # Verify webhook (implement Pub/Sub verification)
        if not verify_pubsub_message(request):
            return jsonify({"error": "Invalid message"}), 401
        
        data = request.json
        message = data.get('message', {})
        
        # Decode base64 message data
        message_data = base64.b64decode(message.get('data', '')).decode('utf-8')
        log_entry = json.loads(message_data)
        
        # Extract method name
        proto_payload = log_entry.get('protoPayload', {})
        method_name = proto_payload.get('methodName', '')
        
        # Only process IAM events
        if 'iam.googleapis.com' in str(log_entry) or 'iam.admin' in method_name:
            handle_iam_event(log_entry)
        
        return jsonify({"status": "success"}), 200
    
    except Exception as e:
        print(f"Webhook error: {e}")
        return jsonify({"error": str(e)}), 500

def verify_pubsub_message(request) -> bool:
    """Verify Pub/Sub message"""
    # Implementation would verify the message signature
    # using Pub/Sub's message verification method
    return True

def handle_iam_event(log_entry: dict):
    """Handle IAM-related events"""
    proto_payload = log_entry.get('protoPayload', {})
    method_name = proto_payload.get('methodName', '')
    
    # Route to appropriate handler
    if 'DeleteServiceAccount' in method_name:
        handle_service_account_deletion(log_entry)
    elif 'CreateServiceAccountKey' in method_name or 'DeleteServiceAccountKey' in method_name:
        handle_key_event(log_entry)
    elif 'SetIamPolicy' in method_name:
        handle_policy_event(log_entry)
    elif 'DisableServiceAccount' in method_name or 'EnableServiceAccount' in method_name:
        handle_service_account_lifecycle(log_entry)

def handle_service_account_deletion(log_entry: dict):
    """Handle service account deletion events"""
    # Send to XDR
    xdr_integration = GCPIAMXDRIntegration(gcp_iam_client, xdr_client)
    xdr_integration.process_iam_event(log_entry)
    
    # Send to XSOAR
    xsoar_integration = GCPIAMXSOARIntegration(gcp_iam_client, xsoar_client)
    xsoar_integration.create_xsoar_incident_from_event(log_entry)

def handle_key_event(log_entry: dict):
    """Handle service account key events"""
    # Send to XDR
    xdr_integration = GCPIAMXDRIntegration(gcp_iam_client, xdr_client)
    xdr_integration.process_iam_event(log_entry)
    
    # Send to XSOAR
    xsoar_integration = GCPIAMXSOARIntegration(gcp_iam_client, xsoar_client)
    xsoar_integration.create_xsoar_incident_from_event(log_entry)
    
    # Trigger playbook for key creation
    proto_payload = log_entry.get('protoPayload', {})
    if 'CreateServiceAccountKey' in proto_payload.get('methodName', ''):
        xsoar_integration.trigger_playbook_for_event(log_entry)

def handle_policy_event(log_entry: dict):
    """Handle IAM policy events"""
    # Send to XDR
    xdr_integration = GCPIAMXDRIntegration(gcp_iam_client, xdr_client)
    xdr_integration.process_iam_event(log_entry)
    
    # Send to XSOAR
    xsoar_integration = GCPIAMXSOARIntegration(gcp_iam_client, xsoar_client)
    xsoar_integration.trigger_playbook_for_event(log_entry)

def handle_service_account_lifecycle(log_entry: dict):
    """Handle service account lifecycle events"""
    # Send to XDR
    xdr_integration = GCPIAMXDRIntegration(gcp_iam_client, xdr_client)
    xdr_integration.process_iam_event(log_entry)
    
    # Send to XSOAR
    xsoar_integration = GCPIAMXSOARIntegration(gcp_iam_client, xsoar_client)
    xsoar_integration.create_xsoar_incident_from_event(log_entry)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')
```

---

# Use Cases and Workflows

# 6.1 Complete Workflow: Privilege Escalation Detection

```python
#!/usr/bin/env python3
"""
Complete Workflow: Privilege Escalation Detection and Response
Purpose: End-to-end workflow from detection to remediation
"""

class PrivilegeEscalationWorkflow:
    """Complete workflow for privilege escalation handling"""
    
    def __init__(self, gcp_iam_client, xdr_client, xsoar_client):
        self.gcp_iam = gcp_iam_client
        self.xdr = xdr_client
        self.xsoar = xsoar_client
    
    def execute_workflow(self, event: Dict):
        """Execute complete privilege escalation workflow"""
        
        # Step 1: Detect privilege escalation
        if not self.is_privilege_escalation(event):
            return
        
        proto_payload = event.get('proto_payload', {})
        resource = event.get('resource', {})
        service_account_email = resource.get('labels', {}).get('email_id', 'Unknown')
        
        # Step 2: Gather intelligence
        intelligence = self.gather_intelligence(service_account_email, event)
        
        # Step 3: Create incidents in all platforms
        xdr_incident = self.create_xdr_incident(event, intelligence)
        xsoar_incident = self.create_xsoar_incident(event, intelligence)
        
        # Step 4: Automated response
        response_action = self.determine_response(intelligence)
        self.execute_response(service_account_email, response_action, xdr_incident.get('incident_id'))
        
        # Step 5: Notify stakeholders
        self.notify_stakeholders(event, intelligence, response_action)
        
        return {
            "xdr_incident": xdr_incident,
            "xsoar_incident": xsoar_incident,
            "response_action": response_action
        }
    
    def is_privilege_escalation(self, event: Dict) -> bool:
        """Determine if event indicates privilege escalation"""
        proto_payload = event.get('proto_payload', {})
        method_name = proto_payload.get('method_name', '')
        
        # Check for policy changes that grant admin access
        if 'SetIamPolicy' in method_name:
            # Get the IAM policy to check for admin roles
            resource = event.get('resource', {})
            service_account_email = resource.get('labels', {}).get('email_id')
            if service_account_email:
                iam_policy = self.gcp_iam.get_service_account_iam_policy(service_account_email)
                bindings = iam_policy.get('bindings', [])
                for binding in bindings:
                    role = binding.get('role', '')
                    if 'roles/owner' in role or 'roles/editor' in role or 'roles/iam.admin' in role:
                        return True
        
        return False
    
    def gather_intelligence(self, service_account_email: str, event: Dict) -> Dict:
        """Gather intelligence about the service account and event"""
        account = self.gcp_iam.get_service_account(service_account_email)
        iam_policy = self.gcp_iam.get_service_account_iam_policy(service_account_email)
        keys = self.gcp_iam.get_service_account_keys(service_account_email)
        recent_events = self.gcp_iam.get_audit_logs(
            filter_str=f'resource.labels.email_id="{service_account_email}"',
            start_time=datetime.now() - timedelta(days=7)
        )
        
        return {
            "service_account": account,
            "iam_policy": iam_policy,
            "keys": keys,
            "recent_events": recent_events,
            "risk_score": self.calculate_risk_score(account, iam_policy, recent_events)
        }
    
    def calculate_risk_score(self, account: Dict, iam_policy: Dict, events: List) -> int:
        """Calculate risk score"""
        score = 0
        
        # Admin roles
        bindings = iam_policy.get('bindings', [])
        admin_roles = ['roles/owner', 'roles/editor', 'roles/iam.admin']
        for binding in bindings:
            if any(role in binding.get('role', '') for role in admin_roles):
                score += 3
        
        # Recent policy changes
        policy_events = [e for e in events if 'SetIamPolicy' in str(e)]
        score += min(len(policy_events), 3)
        
        return min(score, 10)
    
    def determine_response(self, intelligence: Dict) -> str:
        """Determine response action"""
        risk_score = intelligence.get('risk_score', 0)
        
        if risk_score >= 8:
            return 'disable_service_account'
        elif risk_score >= 5:
            return 'delete_keys'
        else:
            return 'monitor'
    
    def execute_response(self, service_account_email: str, action: str, incident_id: str):
        """Execute response action"""
        if action == 'disable_service_account':
            result = self.gcp_iam.disable_service_account(service_account_email)
            self.xdr.add_incident_comment(
                incident_id,
                f"Automated Response: {result.get('message', 'Action completed')}"
            )
        elif action == 'delete_keys':
            keys = self.gcp_iam.get_service_account_keys(service_account_email)
            for key in keys:
                result = self.gcp_iam.delete_service_account_key(service_account_email, key.get('name'))
                self.xdr.add_incident_comment(
                    incident_id,
                    f"Automated Response: {result.get('message', 'Action completed')}"
                )
    
    def create_xdr_incident(self, event: Dict, intelligence: Dict) -> Dict:
        """Create XDR incident"""
        xdr_integration = GCPIAMXDRIntegration(self.gcp_iam, self.xdr)
        return xdr_integration.create_xdr_incident_from_event(event)
    
    def create_xsoar_incident(self, event: Dict, intelligence: Dict) -> Dict:
        """Create XSOAR incident"""
        xsoar_integration = GCPIAMXSOARIntegration(self.gcp_iam, self.xsoar)
        return xsoar_integration.create_xsoar_incident_from_event(event)
    
    def notify_stakeholders(self, event: Dict, intelligence: Dict, action: str):
        """Notify security team and stakeholders"""
        # Implementation would send notifications via Slack, email, etc.
        pass
```

---

# Configuration and Setup

# 7.1 Environment Variables

```bash
# GCP Configuration
export GCP_PROJECT_ID="your-gcp-project-id"
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"

# Alternative: Use service account JSON as environment variable
export GCP_CREDENTIALS_JSON='{"type":"service_account","project_id":"..."}'

# Cortex XDR Configuration
export XDR_API_KEY="your-xdr-api-key"
export XDR_API_KEY_ID="your-xdr-key-id"
export XDR_BASE_URL="https://api.xdr.us.paloaltonetworks.com"

# XSOAR Configuration
export XSOAR_URL="https://xsoar.example.com"
export XSOAR_API_KEY="your-xsoar-api-key"
```

# 7.2 Configuration File

```yaml
# gcp_iam_integrations_config.yaml
gcp:
  project_id: "${GCP_PROJECT_ID}"
  credentials_path: "${GOOGLE_APPLICATION_CREDENTIALS}"
  
integrations:
  cortex_xdr:
    enabled: true
    api_key: "${XDR_API_KEY}"
    api_key_id: "${XDR_API_KEY_ID}"
    base_url: "${XDR_BASE_URL}"
    auto_create_incidents: true
    severity_threshold: "medium"
    
  xsoar:
    enabled: true
    base_url: "${XSOAR_URL}"
    api_key: "${XSOAR_API_KEY}"
    auto_create_incidents: true
    trigger_playbooks: true

event_routing:
  DeleteServiceAccount:
    - cortex_xdr
    - xsoar
  SetIamPolicy:
    - cortex_xdr
    - xsoar
  CreateServiceAccountKey:
    - cortex_xdr
    - xsoar
  DisableServiceAccount:
    - xsoar  # Only if suspicious

automated_responses:
  enabled: true
  actions:
    disable_service_account:
      trigger_severity: "critical"
      require_approval: true
    delete_key:
      trigger_severity: "high"
      require_approval: false
```

# 7.3 GCP IAM Permissions Required

```json
{
  "bindings": [
    {
      "role": "roles/iam.serviceAccountViewer",
      "members": ["serviceAccount:integration@project.iam.gserviceaccount.com"]
    },
    {
      "role": "roles/iam.serviceAccountKeyAdmin",
      "members": ["serviceAccount:integration@project.iam.gserviceaccount.com"]
    },
    {
      "role": "roles/logging.viewer",
      "members": ["serviceAccount:integration@project.iam.gserviceaccount.com"]
    },
    {
      "role": "roles/cloudasset.viewer",
      "members": ["serviceAccount:integration@project.iam.gserviceaccount.com"]
    }
  ]
}
```

---

# Troubleshooting

# Common Issues and Solutions

# 1. Authentication Failures

Problem: GCP API authentication fails

Solutions:
- Verify service account key file path is correct
- Check service account has required IAM permissions
- Ensure GOOGLE_APPLICATION_CREDENTIALS environment variable is set
- Verify service account key is not expired
- Check project ID is correct

# 2. Cloud Audit Logs Not Available

Problem: Cannot retrieve Cloud Audit Logs

Solutions:
- Verify Cloud Audit Logs API is enabled
- Check IAM permissions include logging.viewer role
- Ensure audit logs are being generated for IAM operations
- Verify log filter syntax is correct
- Check project has Cloud Logging enabled

# 3. Rate Limiting

Problem: GCP API rate limits exceeded

Solutions:
- Implement exponential backoff
- Use pagination for large result sets
- Cache frequently accessed data
- Batch requests when possible
- Respect GCP API rate limits

# 4. Service Account Not Found

Problem: Cannot find service account

Solutions:
- Verify service account email format is correct
- Check service account exists in the project
- Ensure service account hasn't been deleted
- Verify project ID is correct
- Check IAM permissions to view service accounts

# 5. IAM Policy Access Denied

Problem: Cannot read or modify IAM policies

Solutions:
- Verify service account has iam.serviceAccountViewer role
- Check for organization policies that restrict IAM access
- Ensure service account has project-level permissions
- Verify resource hierarchy permissions
- Check for resource manager constraints

# 6. Cloud Asset Inventory Issues

Problem: Cannot search IAM resources

Solutions:
- Verify Cloud Asset API is enabled
- Check cloudasset.viewer role is granted
- Ensure asset inventory is enabled for the project
- Verify resource types are correct
- Check for organization policy restrictions

---

# Best Practices

1. Service Account Security: Use dedicated service accounts for integrations with minimal required permissions
2. Least Privilege: Grant only minimum required IAM roles
3. Error Handling: Implement comprehensive error handling and logging
4. Rate Limiting: Respect GCP API rate limits and implement backoff
5. Event Deduplication: Implement logic to prevent processing duplicate events
6. Monitoring: Monitor integration health and API usage
7. Testing: Test integrations in non-production GCP projects first
8. Documentation: Document custom mappings and configurations
9. Audit Logging: Log all actions taken via integrations
10. Cloud Audit Logs: Ensure Cloud Audit Logs are enabled and properly configured
11. Encryption: Use encrypted connections for all API calls
12. Key Rotation: Regularly rotate service account keys

---

# API Reference

# GCP IAM API Methods Used

- `iam.projects.serviceAccounts.get()` - Get service account details
- `iam.projects.serviceAccounts.list()` - List service accounts
- `iam.projects.serviceAccounts.getIamPolicy()` - Get IAM policy
- `iam.projects.serviceAccounts.setIamPolicy()` - Set IAM policy
- `iam.projects.serviceAccounts.keys.list()` - List service account keys
- `iam.projects.serviceAccounts.keys.delete()` - Delete service account key
- `iam.projects.serviceAccounts.disable()` - Disable service account
- `iam.projects.serviceAccounts.enable()` - Enable service account

# Cloud Logging API Methods Used

- `logging.entries.list()` - List log entries

# Cloud Asset Inventory API Methods Used

- `cloudasset.assets.searchAllResources()` - Search all resources

# Required GCP IAM Roles

- `roles/iam.serviceAccountViewer` - View service accounts
- `roles/iam.serviceAccountKeyAdmin` - Manage service account keys (for remediation)
- `roles/logging.viewer` - View Cloud Audit Logs
- `roles/cloudasset.viewer` - View Cloud Asset Inventory

---

Version: 1.0  
Last Updated: 2026-01-09  
Maintained By: SOC Team
