# Azure IAM Integrations Standard Operating Procedure (SOP)

# Table of Contents

1. [Overview](#overview)
2. [Azure IAM API Integration Basics](#azure-iam-api-integration-basics)
3. [Azure IAM to Cortex XDR Integration](#azure-iam-to-cortex-xdr-integration)
4. [Azure IAM to XSOAR Integration](#azure-iam-to-xsoar-integration)
5. [Azure IAM to Prisma Cloud Integration](#azure-iam-to-prisma-cloud-integration)
6. [Azure Monitor Activity Logs](#azure-monitor-activity-logs)
7. [Webhook Integrations](#webhook-integrations)
8. [Use Cases and Workflows](#use-cases-and-workflows)
9. [Configuration and Setup](#configuration-and-setup)
10. [Troubleshooting](#troubleshooting)

---

# Overview

This SOP provides comprehensive integration code snippets and configuration examples for connecting Microsoft Azure IAM (Identity and Access Management) with Palo Alto Networks security products (Cortex XDR, XSOAR, Prisma Cloud). These integrations enable automated identity-based security operations, incident response, compliance monitoring, and CIEM (Cloud Infrastructure Entitlement Management) for Azure cloud environments.

# Integration Use Cases

- IAM Threat Detection: Monitor Azure IAM events for suspicious access patterns and privilege escalations
- Automated Incident Response: Create security incidents in XDR/XSOAR based on Azure IAM security events
- Access Governance: Track IAM user, service principal, and role assignment changes
- Compliance Monitoring: Monitor IAM compliance violations and policy changes
- Automated Remediation: Respond to IAM-based threats automatically (disable service principals, revoke credentials)
- Azure Monitor Integration: Monitor Activity Logs for IAM-related security events
- CIEM Integration: Sync Azure IAM identity data to Prisma Cloud for identity governance and least privilege analysis

---

# Azure IAM API Integration Basics

# 1. Azure IAM Client (Python with Azure SDK)

```python
#!/usr/bin/env python3
"""
Azure IAM API Integration Client
Purpose: Authenticate and interact with Azure IAM API using Azure SDK
"""

from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.graph import GraphRbacManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.graphrbac import GraphRbacManagementClient as GraphClient
import json
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import os

class AzureIAMClient:
    """Azure IAM API Client using Azure SDK"""
    
    def __init__(self, 
                 tenant_id: str,
                 subscription_id: str,
                 client_id: Optional[str] = None,
                 client_secret: Optional[str] = None):
        """
        Initialize Azure IAM client
        
        Args:
            tenant_id: Azure AD tenant ID
            subscription_id: Azure subscription ID
            client_id: Service principal client ID (optional, uses DefaultAzureCredential if not provided)
            client_secret: Service principal client secret (optional)
        """
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        
        # Set up credentials
        if client_id and client_secret:
            self.credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
        else:
            # Use DefaultAzureCredential (supports multiple authentication methods)
            self.credential = DefaultAzureCredential()
        
        # Initialize clients
        self.authorization_client = AuthorizationManagementClient(
            self.credential,
            subscription_id
        )
        
        # Graph API client for Azure AD operations
        self.graph_client = GraphClient(
            credentials=self.credential,
            tenant_id=tenant_id
        )
        
        # Monitor client for Activity Logs
        self.monitor_client = MonitorManagementClient(
            self.credential,
            subscription_id
        )
    
    def get_user(self, user_object_id: str) -> Dict:
        """Get Azure AD user details"""
        try:
            user = self.graph_client.users.get(user_object_id)
            return {
                'object_id': user.object_id,
                'user_principal_name': user.user_principal_name,
                'display_name': user.display_name,
                'mail': user.mail,
                'account_enabled': user.account_enabled
            }
        except Exception as e:
            print(f"Error getting user: {e}")
            return {}
    
    def list_users(self) -> List[Dict]:
        """List all Azure AD users"""
        users = []
        try:
            for user in self.graph_client.users.list():
                users.append({
                    'object_id': user.object_id,
                    'user_principal_name': user.user_principal_name,
                    'display_name': user.display_name,
                    'mail': user.mail,
                    'account_enabled': user.account_enabled
                })
        except Exception as e:
            print(f"Error listing users: {e}")
        
        return users
    
    def get_service_principal(self, service_principal_id: str) -> Dict:
        """Get service principal details"""
        try:
            sp = self.graph_client.service_principals.get(service_principal_id)
            return {
                'object_id': sp.object_id,
                'app_id': sp.app_id,
                'display_name': sp.display_name,
                'service_principal_type': sp.service_principal_type,
                'account_enabled': sp.account_enabled
            }
        except Exception as e:
            print(f"Error getting service principal: {e}")
            return {}
    
    def list_service_principals(self) -> List[Dict]:
        """List all service principals"""
        service_principals = []
        try:
            for sp in self.graph_client.service_principals.list():
                service_principals.append({
                    'object_id': sp.object_id,
                    'app_id': sp.app_id,
                    'display_name': sp.display_name,
                    'service_principal_type': sp.service_principal_type,
                    'account_enabled': sp.account_enabled
                })
        except Exception as e:
            print(f"Error listing service principals: {e}")
        
        return service_principals
    
    def get_role_assignments(self, scope: Optional[str] = None) -> List[Dict]:
        """Get role assignments for a scope (subscription, resource group, or resource)"""
        if not scope:
            scope = f"/subscriptions/{self.subscription_id}"
        
        role_assignments = []
        try:
            for assignment in self.authorization_client.role_assignments.list_for_scope(scope):
                role_definition = self.authorization_client.role_definitions.get_by_id(
                    assignment.role_definition_id
                )
                role_assignments.append({
                    'id': assignment.id,
                    'name': assignment.name,
                    'principal_id': assignment.principal_id,
                    'principal_type': assignment.principal_type,
                    'role_definition_id': assignment.role_definition_id,
                    'role_name': role_definition.role_name if role_definition else 'Unknown',
                    'scope': assignment.scope
                })
        except Exception as e:
            print(f"Error getting role assignments: {e}")
        
        return role_assignments
    
    def get_user_role_assignments(self, user_object_id: str) -> List[Dict]:
        """Get role assignments for a specific user"""
        all_assignments = self.get_role_assignments()
        return [a for a in all_assignments if a.get('principal_id') == user_object_id]
    
    def get_service_principal_role_assignments(self, service_principal_id: str) -> List[Dict]:
        """Get role assignments for a specific service principal"""
        all_assignments = self.get_role_assignments()
        return [a for a in all_assignments if a.get('principal_id') == service_principal_id]
    
    def disable_user(self, user_object_id: str) -> Dict:
        """Disable a user account"""
        try:
            user = self.graph_client.users.get(user_object_id)
            user.account_enabled = False
            self.graph_client.users.create(user)
            return {"status": "success", "message": f"User {user_object_id} disabled"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def enable_user(self, user_object_id: str) -> Dict:
        """Enable a user account"""
        try:
            user = self.graph_client.users.get(user_object_id)
            user.account_enabled = True
            self.graph_client.users.create(user)
            return {"status": "success", "message": f"User {user_object_id} enabled"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def disable_service_principal(self, service_principal_id: str) -> Dict:
        """Disable a service principal"""
        try:
            sp = self.graph_client.service_principals.get(service_principal_id)
            sp.account_enabled = False
            self.graph_client.service_principals.create(sp)
            return {"status": "success", "message": f"Service principal {service_principal_id} disabled"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def get_activity_logs(self,
                          start_time: Optional[datetime] = None,
                          end_time: Optional[datetime] = None,
                          filter_str: Optional[str] = None) -> List[Dict]:
        """
        Get Azure Activity Logs for IAM events
        
        Args:
            start_time: Start time for log query
            end_time: End time for log query
            filter_str: Additional filter expression
        """
        if not start_time:
            start_time = datetime.now() - timedelta(hours=1)
        if not end_time:
            end_time = datetime.now()
        
        # Build filter
        log_filter = f"""
        eventTimestamp ge '{start_time.isoformat()}' and
        eventTimestamp le '{end_time.isoformat()}' and
        (resourceProvider eq 'Microsoft.Authorization' or
         resourceProvider eq 'Microsoft.Graph' or
         category eq 'Administrative')
        """
        
        if filter_str:
            log_filter += f" and {filter_str}"
        
        logs = []
        try:
            activity_logs = self.monitor_client.activity_logs.list(
                filter=log_filter
            )
            
            for log in activity_logs:
                log_data = {
                    'id': log.id,
                    'event_timestamp': log.event_timestamp.isoformat() if log.event_timestamp else None,
                    'resource_id': log.resource_id,
                    'resource_group_name': log.resource_group_name,
                    'resource_provider_name': log.resource_provider_name.value if log.resource_provider_name else None,
                    'operation_name': log.operation_name.value if log.operation_name else None,
                    'status': log.status.value if log.status else None,
                    'caller': log.caller,
                    'correlation_id': log.correlation_id,
                    'properties': log.properties
                }
                logs.append(log_data)
        except Exception as e:
            print(f"Error getting activity logs: {e}")
        
        return logs
    
    def get_security_events(self,
                           start_time: Optional[datetime] = None,
                           limit: int = 100) -> List[Dict]:
        """Get security-related IAM events from Activity Logs"""
        security_operations = [
            'Microsoft.Authorization/roleAssignments/write',
            'Microsoft.Authorization/roleAssignments/delete',
            'Microsoft.Graph/servicePrincipals/write',
            'Microsoft.Graph/servicePrincipals/delete',
            'Microsoft.Graph/users/write',
            'Microsoft.Graph/users/delete',
            'Microsoft.Graph/applications/write',
            'Microsoft.Graph/applications/delete'
        ]
        
        filter_str = " or ".join([f"operationName.value eq '{op}'" for op in security_operations])
        
        events = self.get_activity_logs(start_time=start_time, filter_str=filter_str)
        return events[:limit]
    
    def get_sign_in_logs(self,
                        start_time: Optional[datetime] = None,
                        end_time: Optional[datetime] = None,
                        user_id: Optional[str] = None) -> List[Dict]:
        """Get Azure AD sign-in logs"""
        # Note: This requires Microsoft Graph API with appropriate permissions
        # Using Azure SDK's Microsoft Graph client
        from azure.identity import ClientSecretCredential
        from msal import ConfidentialClientApplication
        
        # This is a simplified example - full implementation would use Microsoft Graph API
        # For now, we'll return activity logs filtered for sign-in events
        filter_str = "category eq 'SignInLogs'"
        if user_id:
            filter_str += f" and user_id eq '{user_id}'"
        
        return self.get_activity_logs(start_time=start_time, end_time=end_time, filter_str=filter_str)

# Usage Example
if __name__ == "__main__":
    client = AzureIAMClient(
        tenant_id=os.getenv("AZURE_TENANT_ID"),
        subscription_id=os.getenv("AZURE_SUBSCRIPTION_ID"),
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_secret=os.getenv("AZURE_CLIENT_SECRET")
    )
    
    # Get recent security events
    events = client.get_security_events(
        start_time=datetime.now() - timedelta(hours=24)
    )
    print(f"Found {len(events)} security events")
    
    # List users
    users = client.list_users()
    print(f"Found {len(users)} users")
    
    # Get role assignments
    role_assignments = client.get_role_assignments()
    print(f"Found {len(role_assignments)} role assignments")
```

---

# Azure IAM to Cortex XDR Integration

# 2.1 Azure IAM Events to XDR Incidents

```python
#!/usr/bin/env python3
"""
Azure IAM to Cortex XDR Integration
Purpose: Create XDR incidents from Azure IAM security events
"""

from datetime import datetime, timedelta
from typing import Dict, List
import os
import time
import json

class AzureIAMXDRIntegration:
    """Integrate Azure IAM with Cortex XDR"""
    
    def __init__(self, azure_iam_client, xdr_client):
        self.azure_iam = azure_iam_client
        self.xdr = xdr_client
    
    def monitor_iam_events(self, check_interval_minutes: int = 15):
        """Continuously monitor Azure IAM events and create XDR incidents"""
        last_check = datetime.now() - timedelta(minutes=check_interval_minutes)
        
        while True:
            try:
                # Get security events since last check
                events = self.azure_iam.get_security_events(start_time=last_check)
                
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
        operation_name = event.get('operation_name', '')
        severity = self.determine_severity(operation_name)
        
        # Only create incidents for high-severity events
        if severity in ['high', 'critical']:
            incident_data = self.create_xdr_incident_from_event(event)
            self.xdr.create_incident(incident_data)
    
    def determine_severity(self, operation_name: str) -> str:
        """Determine severity based on operation name"""
        critical_operations = [
            'Microsoft.Authorization/roleAssignments/write',
            'Microsoft.Graph/servicePrincipals/delete',
            'Microsoft.Graph/users/delete'
        ]
        
        high_operations = [
            'Microsoft.Graph/servicePrincipals/write',
            'Microsoft.Graph/users/write',
            'Microsoft.Authorization/roleAssignments/delete'
        ]
        
        if any(op in operation_name for op in critical_operations):
            return 'critical'
        elif any(op in operation_name for op in high_operations):
            return 'high'
        else:
            return 'medium'
    
    def create_xdr_incident_from_event(self, event: Dict) -> Dict:
        """Create XDR incident payload from Azure IAM event"""
        event_id = event.get('id', '')
        operation_name = event.get('operation_name', 'Unknown')
        caller = event.get('caller', 'Unknown')
        timestamp = event.get('event_timestamp', datetime.now().isoformat())
        resource_id = event.get('resource_id', 'Unknown')
        status = event.get('status', 'Unknown')
        
        # Extract principal information
        properties = event.get('properties', {})
        
        # Build incident description
        description = f"""
        Azure IAM Security Event Detected
        
        Operation: {operation_name}
        Event ID: {event_id}
        Caller: {caller}
        Timestamp: {timestamp}
        Resource ID: {resource_id}
        Status: {status}
        Subscription ID: {self.azure_iam.subscription_id}
        
        Event Properties:
        {json.dumps(properties, indent=2)}
        
        Full Event Details:
        {json.dumps(event, indent=2)}
        """
        
        return {
            "incident_name": f"Azure IAM: {operation_name} - {caller}",
            "severity": self.determine_severity(operation_name),
            "description": description,
            "labels": [
                {"key": "source", "value": "Azure IAM"},
                {"key": "operation_name", "value": operation_name},
                {"key": "caller", "value": caller},
                {"key": "subscription_id", "value": self.azure_iam.subscription_id}
            ],
            "custom_fields": {
                "azure_event_id": event_id,
                "azure_operation_name": operation_name,
                "azure_caller": caller,
                "azure_resource_id": resource_id,
                "azure_timestamp": timestamp,
                "azure_status": status,
                "azure_subscription_id": self.azure_iam.subscription_id,
                "azure_tenant_id": self.azure_iam.tenant_id
            }
        }
    
    def sync_suspicious_access_to_xdr(self, principal_id: str, event: Dict):
        """Create XDR incident for suspicious IAM access"""
        # Determine if this is a user or service principal
        operation_name = event.get('operation_name', '')
        
        # Try to get user first
        user = self.azure_iam.get_user(principal_id)
        if user:
            role_assignments = self.azure_iam.get_user_role_assignments(principal_id)
        else:
            # Try service principal
            sp = self.azure_iam.get_service_principal(principal_id)
            role_assignments = self.azure_iam.get_service_principal_role_assignments(principal_id) if sp else []
        
        # Check for suspicious patterns
        is_suspicious = self.detect_suspicious_pattern(event, role_assignments)
        
        if is_suspicious:
            principal_name = user.get('user_principal_name', '') if user else (sp.get('display_name', '') if sp else principal_id)
            
            incident = {
                "incident_name": f"Azure IAM: Suspicious Access - {principal_name}",
                "severity": "high",
                "description": f"""
                Suspicious IAM access detected for principal: {principal_name}
                
                Principal Details:
                - ID: {principal_id}
                - Type: {'User' if user else 'Service Principal'}
                - Role Assignments: {len(role_assignments)}
                
                Event Details:
                - Operation: {operation_name}
                - Caller: {event.get('caller', 'Unknown')}
                - Timestamp: {event.get('event_timestamp', '')}
                
                Risk Indicators:
                - Unusual role assignment
                - Access from unknown source
                - Privilege escalation attempt
                - Multiple role assignments
                """,
                "labels": [
                    {"key": "source", "value": "Azure IAM"},
                    {"key": "event_type", "value": "suspicious_access"},
                    {"key": "threat_type", "value": "privilege_escalation"}
                ]
            }
            
            xdr_incident = self.xdr.create_incident(incident)
            
            # Add comment with remediation steps
            self.xdr.add_incident_comment(
                xdr_incident.get('incident_id'),
                "Recommended Actions:\n1. Review principal permissions\n2. Check for unauthorized role assignments\n3. Consider disabling principal if compromised\n4. Review recent principal activity"
            )
            
            return xdr_incident
    
    def detect_suspicious_pattern(self, event: Dict, role_assignments: List[Dict]) -> bool:
        """Detect suspicious IAM access patterns"""
        operation_name = event.get('operation_name', '')
        
        # Check for privilege escalation
        if 'roleAssignments/write' in operation_name:
            # Check if role assignment grants admin permissions
            properties = event.get('properties', {})
            role_definition_id = properties.get('roleDefinitionId', '')
            
            # Check for admin roles
            admin_roles = [
                'Owner',
                'User Access Administrator',
                'Contributor',
                'Global Administrator'
            ]
            
            for assignment in role_assignments:
                role_name = assignment.get('role_name', '')
                if any(admin_role in role_name for admin_role in admin_roles):
                    return True
        
        # Check for multiple role assignments
        if len(role_assignments) > 5:
            return True
        
        # Check for service principal creation with high privileges
        if 'servicePrincipals/write' in operation_name:
            # Additional checks could be added here
            return True
        
        return False

# Usage Example
if __name__ == "__main__":
    from azure_iam_client import AzureIAMClient
    from cortex_xdr_client import CortexXDRClient
    
    # Initialize clients
    azure_iam = AzureIAMClient(
        tenant_id=os.getenv("AZURE_TENANT_ID"),
        subscription_id=os.getenv("AZURE_SUBSCRIPTION_ID"),
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_secret=os.getenv("AZURE_CLIENT_SECRET")
    )
    
    xdr = CortexXDRClient(
        api_key=os.getenv("XDR_API_KEY"),
        api_key_id=os.getenv("XDR_API_KEY_ID")
    )
    
    # Create integration
    integration = AzureIAMXDRIntegration(azure_iam, xdr)
    
    # Monitor events
    integration.monitor_iam_events(check_interval_minutes=15)
```

# 2.2 Automated Response to XDR Incidents

```python
#!/usr/bin/env python3
"""
Automated Response: XDR Incident → Azure IAM Actions
Purpose: Automatically respond to XDR incidents by taking Azure IAM actions
"""

class XDRAzureIAMResponse:
    """Automated response to XDR incidents using Azure IAM"""
    
    def __init__(self, xdr_client, azure_iam_client):
        self.xdr = xdr_client
        self.azure_iam = azure_iam_client
    
    def handle_xdr_incident(self, incident_id: str):
        """Handle XDR incident and take Azure IAM actions"""
        incident = self.xdr.get_incident(incident_id)
        
        # Check if incident is related to Azure IAM
        if self.is_iam_related(incident):
            principal_id = self.extract_principal_id(incident)
            principal_type = self.extract_principal_type(incident)
            
            if principal_id:
                # Determine response action
                action = self.determine_response_action(incident)
                
                if action == 'disable_user' and principal_type == 'user':
                    result = self.azure_iam.disable_user(principal_id)
                    self.xdr.add_incident_comment(
                        incident_id,
                        f"Automated Response: {result.get('message', 'Action completed')}"
                    )
                elif action == 'disable_service_principal' and principal_type == 'service_principal':
                    result = self.azure_iam.disable_service_principal(principal_id)
                    self.xdr.add_incident_comment(
                        incident_id,
                        f"Automated Response: {result.get('message', 'Action completed')}"
                    )
    
    def is_iam_related(self, incident: Dict) -> bool:
        """Check if incident is Azure IAM-related"""
        labels = incident.get('labels', [])
        for label in labels:
            if label.get('key') == 'source' and label.get('value') == 'Azure IAM':
                return True
            if label.get('key') == 'threat_type') and 'privilege' in label.get('value', '').lower():
                return True
        return False
    
    def extract_principal_id(self, incident: Dict) -> Optional[str]:
        """Extract principal ID from incident"""
        custom_fields = incident.get('custom_fields', {})
        # Try to extract from caller or properties
        caller = custom_fields.get('azure_caller', '')
        # Principal ID might be in the caller field or properties
        return caller
    
    def extract_principal_type(self, incident: Dict) -> str:
        """Extract principal type from incident"""
        operation_name = incident.get('custom_fields', {}).get('azure_operation_name', '')
        if 'users' in operation_name:
            return 'user'
        elif 'servicePrincipals' in operation_name:
            return 'service_principal'
        return 'unknown'
    
    def determine_response_action(self, incident: Dict) -> str:
        """Determine appropriate response action"""
        severity = incident.get('severity', 'medium')
        operation_name = incident.get('custom_fields', {}).get('azure_operation_name', '')
        
        if severity == 'critical':
            if 'users' in operation_name:
                return 'disable_user'
            elif 'servicePrincipals' in operation_name:
                return 'disable_service_principal'
        
        return 'monitor'
```

---

# Azure IAM to XSOAR Integration

# 3.1 Azure IAM Events to XSOAR Incidents

```python
#!/usr/bin/env python3
"""
Azure IAM to XSOAR Integration
Purpose: Create XSOAR incidents from Azure IAM security events and automate playbooks
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
import os
import json

class AzureIAMXSOARIntegration:
    """Integrate Azure IAM with Cortex XSOAR"""
    
    def __init__(self, azure_iam_client, xsoar_client):
        self.azure_iam = azure_iam_client
        self.xsoar = xsoar_client
    
    def create_xsoar_incident_from_event(self, event: Dict) -> Dict:
        """Create XSOAR incident from Azure IAM event"""
        event_id = event.get('id', '')
        operation_name = event.get('operation_name', 'Unknown')
        caller = event.get('caller', 'Unknown')
        resource_id = event.get('resource_id', 'Unknown')
        
        # Determine incident type and severity
        incident_type, severity = self.map_operation_to_incident_type(operation_name)
        
        # Create incident
        incident = self.xsoar.create_incident(
            name=f"Azure IAM: {operation_name} - {caller}",
            severity=severity,
            type=incident_type,
            labels=[
                {"type": "source", "value": "Azure IAM"},
                {"type": "operation_name", "value": operation_name},
                {"type": "caller", "value": caller},
                {"type": "subscription_id", "value": self.azure_iam.subscription_id}
            ],
            custom_fields={
                "azure_event_id": event_id,
                "azure_operation_name": operation_name,
                "azure_caller": caller,
                "azure_resource_id": resource_id,
                "azure_timestamp": event.get('event_timestamp', ''),
                "azure_status": event.get('status', 'Unknown'),
                "azure_subscription_id": self.azure_iam.subscription_id,
                "azure_tenant_id": self.azure_iam.tenant_id
            }
        )
        
        # Add detailed description
        description = self.build_incident_description(event, caller, operation_name)
        self.xsoar.add_incident_entry(
            incident.get('id'),
            description,
            entry_type="note"
        )
        
        return incident
    
    def map_operation_to_incident_type(self, operation_name: str) -> tuple:
        """Map Azure IAM operation name to XSOAR incident type and severity"""
        mapping = {
            'Microsoft.Authorization/roleAssignments/write': ('Access', 4),  # Critical
            'Microsoft.Graph/users/delete': ('Identity Access Management', 4),
            'Microsoft.Graph/servicePrincipals/delete': ('Identity Access Management', 4),
            'Microsoft.Graph/users/write': ('Identity Access Management', 3),  # High
            'Microsoft.Graph/servicePrincipals/write': ('Identity Access Management', 3),
            'Microsoft.Authorization/roleAssignments/delete': ('Access', 3),
            'Microsoft.Graph/applications/write': ('Identity Access Management', 2),  # Medium
            'Microsoft.Graph/applications/delete': ('Identity Access Management', 2)
        }
        
        # Try to match partial operation name
        for key, value in mapping.items():
            if key in operation_name:
                return value
        
        return ('Unclassified', 1)
    
    def build_incident_description(self, event: Dict, caller: str, operation_name: str) -> str:
        """Build detailed incident description"""
        return f"""
# Azure IAM Security Event

# Event Information
- Operation: {operation_name}
- Event ID: {event.get('id', 'Unknown')}
- Timestamp: {event.get('event_timestamp', '')}
- Caller: {caller}
- Status: {event.get('status', 'Unknown')}
- Subscription ID: {self.azure_iam.subscription_id}
- Tenant ID: {self.azure_iam.tenant_id}

# Resource Information
- Resource ID: {event.get('resource_id', 'Unknown')}
- Resource Group: {event.get('resource_group_name', 'Unknown')}
- Resource Provider: {event.get('resource_provider_name', 'Unknown')}

# Event Properties
```json
{json.dumps(event.get('properties', {}), indent=2)}
```

# Event Details
```json
{json.dumps(event, indent=2)}
```

# Recommended Actions
1. Verify principal identity and authorization
2. Review recent IAM activity for this principal
3. Check for related security events
4. Review role assignments and permissions
5. Consider additional access controls
        """
    
    def trigger_playbook_for_event(self, event: Dict):
        """Trigger XSOAR playbook based on event type"""
        operation_name = event.get('operation_name', '')
        
        # Create incident first
        incident = self.create_xsoar_incident_from_event(event)
        
        # Trigger appropriate playbook
        if 'roleAssignments/write' in operation_name:
            playbook_name = "Investigate Azure Role Assignment"
        elif 'users/delete' in operation_name or 'servicePrincipals/delete' in operation_name:
            playbook_name = "Investigate Azure Principal Deletion"
        elif 'users/write' in operation_name or 'servicePrincipals/write' in operation_name:
            playbook_name = "Investigate Azure Principal Modification"
        else:
            playbook_name = "Generic Azure IAM Investigation"
        
        # Execute playbook
        self.xsoar.execute_command(
            command="executePlaybook",
            arguments={
                "incidentId": incident.get('id'),
                "playbookName": playbook_name
            }
        )
    
    def sync_azure_users_to_xsoar(self):
        """Sync Azure AD user data to XSOAR for reference"""
        users = self.azure_iam.list_users()
        
        for user in users[:100]:  # Limit to first 100
            user_data = {
                "name": f"Azure User: {user.get('user_principal_name')}",
                "type": "Identity",
                "rawJSON": json.dumps(user),
                "labels": [
                    {"type": "source", "value": "Azure IAM"},
                    {"type": "user_id", "value": user.get('object_id')},
                    {"type": "user_principal_name", "value": user.get('user_principal_name')}
                ]
            }
            
            # Create or update indicator in XSOAR
            self.xsoar.execute_command(
                command="createIndicator",
                arguments=user_data
            )

# Usage Example
if __name__ == "__main__":
    from azure_iam_client import AzureIAMClient
    from xsoar_client import XSOARClient
    
    azure_iam = AzureIAMClient(
        tenant_id=os.getenv("AZURE_TENANT_ID"),
        subscription_id=os.getenv("AZURE_SUBSCRIPTION_ID"),
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_secret=os.getenv("AZURE_CLIENT_SECRET")
    )
    
    xsoar = XSOARClient(
        base_url=os.getenv("XSOAR_URL"),
        api_key=os.getenv("XSOAR_API_KEY")
    )
    
    integration = AzureIAMXSOARIntegration(azure_iam, xsoar)
    
    # Get recent security events
    events = azure_iam.get_security_events(
        start_time=datetime.now() - timedelta(hours=1)
    )
    
    # Create incidents for high-severity events
    for event in events:
        operation_name = event.get('operation_name', '')
        if 'roleAssignments/write' in operation_name or 'users/delete' in operation_name:
            integration.trigger_playbook_for_event(event)
```

# 3.2 XSOAR Playbook Integration with Azure IAM

```python
#!/usr/bin/env python3
"""
XSOAR Playbook: Azure IAM Principal Investigation
Purpose: Automated playbook for investigating Azure IAM principal events
"""

class AzureIAMInvestigationPlaybook:
    """XSOAR playbook for Azure IAM investigations"""
    
    def __init__(self, xsoar_client, azure_iam_client):
        self.xsoar = xsoar_client
        self.azure_iam = azure_iam_client
    
    def execute_investigation(self, incident_id: str):
        """Execute full investigation playbook"""
        incident = self.xsoar.get_incident(incident_id)
        
        # Step 1: Extract principal information
        caller = incident.get('customFields', {}).get('azure_caller')
        if not caller:
            self.xsoar.add_incident_entry(
                incident_id,
                "Error: Could not extract caller from incident",
                entry_type="note"
            )
            return
        
        # Step 2: Determine if this is a user or service principal
        principal_id = self.extract_principal_id(caller, incident)
        principal_type = self.determine_principal_type(incident)
        
        # Step 3: Gather principal details
        principal_info = self.gather_principal_information(principal_id, principal_type)
        self.xsoar.add_incident_entry(
            incident_id,
            f"Principal Information:\n{json.dumps(principal_info, indent=2)}",
            entry_type="note"
        )
        
        # Step 4: Check role assignments
        role_assignments = self.azure_iam.get_user_role_assignments(principal_id) if principal_type == 'user' else self.azure_iam.get_service_principal_role_assignments(principal_id)
        
        self.xsoar.add_incident_entry(
            incident_id,
            f"Role Assignments: {len(role_assignments)}",
            entry_type="note"
        )
        
        # Step 5: Get recent activity
        recent_events = self.azure_iam.get_activity_logs(
            filter_str=f"caller eq '{caller}'",
            start_time=datetime.now() - timedelta(days=7)
        )
        
        self.xsoar.add_incident_entry(
            incident_id,
            f"Recent Activity: {len(recent_events)} events found",
            entry_type="note"
        )
        
        # Step 6: Risk assessment
        risk_score = self.assess_risk(principal_info, role_assignments, recent_events)
        
        # Step 7: Recommend actions
        recommendations = self.generate_recommendations(risk_score, incident)
        self.xsoar.add_incident_entry(
            incident_id,
            f"Risk Assessment: {risk_score}/10\n\nRecommendations:\n{recommendations}",
            entry_type="note"
        )
        
        # Step 8: Update incident severity if needed
        if risk_score >= 8:
            self.xsoar.update_incident(incident_id, {"severity": 4})
    
    def extract_principal_id(self, caller: str, incident: Dict) -> str:
        """Extract principal ID from caller or incident"""
        # Caller might be in format: user@domain.com or service principal ID
        # Try to extract from custom fields or parse caller
        return caller
    
    def determine_principal_type(self, incident: Dict) -> str:
        """Determine if principal is user or service principal"""
        operation_name = incident.get('customFields', {}).get('azure_operation_name', '')
        if 'users' in operation_name:
            return 'user'
        elif 'servicePrincipals' in operation_name:
            return 'service_principal'
        return 'unknown'
    
    def gather_principal_information(self, principal_id: str, principal_type: str) -> Dict:
        """Gather comprehensive principal information"""
        if principal_type == 'user':
            principal = self.azure_iam.get_user(principal_id)
        else:
            principal = self.azure_iam.get_service_principal(principal_id)
        
        return {
            "principal": principal,
            "principal_type": principal_type
        }
    
    def assess_risk(self, principal_info: Dict, role_assignments: List, events: List) -> int:
        """Assess risk score (0-10)"""
        risk = 0
        
        # Check for many role assignments
        if len(role_assignments) > 5:
            risk += 2
        
        # Check for admin roles
        admin_roles = ['Owner', 'User Access Administrator', 'Contributor', 'Global Administrator']
        for assignment in role_assignments:
            role_name = assignment.get('role_name', '')
            if any(admin_role in role_name for admin_role in admin_roles):
                risk += 3
        
        # Check for recent role assignment changes
        role_events = [e for e in events if 'roleAssignments' in e.get('operation_name', '')]
        if len(role_events) > 3:
            risk += 3
        
        return min(risk, 10)
    
    def generate_recommendations(self, risk_score: int, incident: Dict) -> str:
        """Generate recommendations based on risk score"""
        recommendations = []
        
        if risk_score >= 8:
            recommendations.append("1. IMMEDIATE: Review all principal permissions")
            recommendations.append("2. Review recent role assignment changes")
            recommendations.append("3. Consider disabling principal if compromised")
            recommendations.append("4. Remove unnecessary role assignments")
            recommendations.append("5. Notify security team")
        elif risk_score >= 5:
            recommendations.append("1. Review role assignments")
            recommendations.append("2. Check for unused permissions")
            recommendations.append("3. Implement least privilege principles")
            recommendations.append("4. Monitor principal activity")
        else:
            recommendations.append("1. Monitor principal activity")
            recommendations.append("2. Review access patterns")
        
        return "\n".join(recommendations)
```

---

# Azure IAM to Prisma Cloud Integration

# 4.1 Azure IAM Identity Data to Prisma Cloud CIEM

```python
#!/usr/bin/env python3
"""
Azure IAM to Prisma Cloud CIEM Integration
Purpose: Sync Azure IAM user and service principal access data to Prisma Cloud for identity governance
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
import os
import json
import requests

class AzureIAMPrismaCloudIntegration:
    """Integrate Azure IAM with Prisma Cloud CIEM"""
    
    def __init__(self, azure_iam_client, prisma_client):
        self.azure_iam = azure_iam_client
        self.prisma = prisma_client
    
    def sync_azure_users_to_prisma(self):
        """Sync Azure AD users and their access to Prisma Cloud"""
        # Get all Azure AD users
        users = self.azure_iam.list_users()
        
        for user in users:
            user_data = self.build_user_access_data(user)
            self.send_to_prisma_ciem(user_data)
    
    def build_user_access_data(self, user: Dict) -> Dict:
        """Build user access data structure for Prisma Cloud"""
        user_object_id = user.get('object_id')
        user_principal_name = user.get('user_principal_name')
        display_name = user.get('display_name')
        
        # Get user role assignments
        role_assignments = self.azure_iam.get_user_role_assignments(user_object_id)
        role_names = [ra.get('role_name') for ra in role_assignments]
        
        # Calculate effective permissions
        effective_permissions = self.calculate_effective_permissions(role_assignments)
        
        return {
            "identity_id": f"azure://{self.azure_iam.tenant_id}/users/{user_object_id}",
            "identity_type": "user",
            "identity_name": user_principal_name or display_name,
            "source": "Azure IAM",
            "status": "ACTIVE" if user.get('account_enabled') else "DISABLED",
            "object_id": user_object_id,
            "user_principal_name": user_principal_name,
            "display_name": display_name,
            "roles": role_names,
            "role_assignments": {
                "total": len(role_assignments),
                "roles": role_names
            },
            "effective_permissions": effective_permissions,
            "metadata": {
                "azure_tenant_id": self.azure_iam.tenant_id,
                "azure_subscription_id": self.azure_iam.subscription_id,
                "azure_user_object_id": user_object_id,
                "mail": user.get('mail'),
                "account_enabled": user.get('account_enabled', False)
            }
        }
    
    def sync_azure_service_principals_to_prisma(self):
        """Sync Azure service principals and their access to Prisma Cloud"""
        # Get all service principals
        service_principals = self.azure_iam.list_service_principals()
        
        for sp in service_principals:
            sp_data = self.build_service_principal_access_data(sp)
            self.send_to_prisma_ciem(sp_data)
    
    def build_service_principal_access_data(self, sp: Dict) -> Dict:
        """Build service principal access data structure for Prisma Cloud"""
        sp_object_id = sp.get('object_id')
        app_id = sp.get('app_id')
        display_name = sp.get('display_name')
        
        # Get service principal role assignments
        role_assignments = self.azure_iam.get_service_principal_role_assignments(sp_object_id)
        role_names = [ra.get('role_name') for ra in role_assignments]
        
        # Calculate effective permissions
        effective_permissions = self.calculate_effective_permissions(role_assignments)
        
        return {
            "identity_id": f"azure://{self.azure_iam.tenant_id}/servicePrincipals/{sp_object_id}",
            "identity_type": "service_principal",
            "identity_name": display_name or app_id,
            "source": "Azure IAM",
            "status": "ACTIVE" if sp.get('account_enabled') else "DISABLED",
            "object_id": sp_object_id,
            "app_id": app_id,
            "display_name": display_name,
            "roles": role_names,
            "role_assignments": {
                "total": len(role_assignments),
                "roles": role_names
            },
            "effective_permissions": effective_permissions,
            "metadata": {
                "azure_tenant_id": self.azure_iam.tenant_id,
                "azure_subscription_id": self.azure_iam.subscription_id,
                "azure_sp_object_id": sp_object_id,
                "service_principal_type": sp.get('service_principal_type')
            }
        }
    
    def calculate_effective_permissions(self, role_assignments: List[Dict]) -> Dict:
        """Calculate effective permissions from role assignments"""
        # This is a simplified version
        # In production, you would parse role definitions and calculate actual permissions
        
        permissions = {
            "roles": [],
            "admin_access": False,
            "storage_access": False,
            "compute_access": False,
            "network_access": False
        }
        
        for assignment in role_assignments:
            role_name = assignment.get('role_name', '')
            permissions["roles"].append(role_name)
            
            # Check for admin access
            if 'Owner' in role_name or 'Contributor' in role_name or 'User Access Administrator' in role_name:
                permissions["admin_access"] = True
            
            # Check for service-specific access
            if 'Storage' in role_name or 'storage' in role_name.lower():
                permissions["storage_access"] = True
            if 'Virtual Machine' in role_name or 'compute' in role_name.lower():
                permissions["compute_access"] = True
            if 'Network' in role_name or 'network' in role_name.lower():
                permissions["network_access"] = True
        
        return permissions
    
    def send_to_prisma_ciem(self, identity_data: Dict):
        """Send identity access data to Prisma Cloud CIEM"""
        url = f"{self.prisma.api_url}/v2/identity"
        
        payload = {
            "identity": identity_data,
            "timestamp": datetime.now().isoformat()
        }
        
        response = requests.post(
            url,
            json=payload,
            headers=self.prisma._get_headers()
        )
        
        if response.status_code == 200:
            print(f"Synced identity: {identity_data.get('identity_name')}")
        else:
            print(f"Error syncing identity: {response.status_code} - {response.text}")
    
    def sync_azure_events_to_prisma(self, hours: int = 24):
        """Sync Azure IAM security events to Prisma Cloud"""
        start_time = datetime.now() - timedelta(hours=hours)
        events = self.azure_iam.get_security_events(start_time=start_time)
        
        for event in events:
            event_data = self.build_event_data(event)
            self.send_event_to_prisma(event_data)
    
    def build_event_data(self, event: Dict) -> Dict:
        """Build event data structure for Prisma Cloud"""
        return {
            "event_id": event.get('id'),
            "event_type": event.get('operation_name'),
            "timestamp": event.get('event_timestamp'),
            "source": "Azure IAM",
            "principal_id": event.get('caller'),
            "resource_id": event.get('resource_id'),
            "azure_region": self.extract_region_from_resource_id(event.get('resource_id', '')),
            "severity": self.map_event_severity(event.get('operation_name')),
            "raw_event": event
        }
    
    def extract_region_from_resource_id(self, resource_id: str) -> str:
        """Extract Azure region from resource ID"""
        # Azure resource IDs may contain region information
        # This is a simplified extraction
        if '/resourceGroups/' in resource_id:
            parts = resource_id.split('/')
            # Try to find region in resource ID structure
            return 'Unknown'
        return 'Unknown'
    
    def map_event_severity(self, operation_name: str) -> str:
        """Map Azure IAM operation type to severity"""
        severity_map = {
            'Microsoft.Authorization/roleAssignments/write': 'high',
            'Microsoft.Graph/users/delete': 'high',
            'Microsoft.Graph/servicePrincipals/delete': 'high',
            'Microsoft.Graph/users/write': 'medium',
            'Microsoft.Graph/servicePrincipals/write': 'medium',
            'Microsoft.Authorization/roleAssignments/delete': 'medium'
        }
        return severity_map.get(operation_name, 'low')
    
    def send_event_to_prisma(self, event_data: Dict):
        """Send event to Prisma Cloud"""
        url = f"{self.prisma.api_url}/v2/event"
        
        response = requests.post(
            url,
            json=event_data,
            headers=self.prisma._get_headers()
        )
        
        return response.status_code == 200
    
    def correlate_azure_access_with_cloud_resources(self, principal_id: str, principal_type: str):
        """Correlate Azure IAM principal access with cloud resources in Prisma"""
        # Get principal from Azure
        if principal_type == 'user':
            principal = self.azure_iam.get_user(principal_id)
            role_assignments = self.azure_iam.get_user_role_assignments(principal_id)
        else:
            principal = self.azure_iam.get_service_principal(principal_id)
            role_assignments = self.azure_iam.get_service_principal_role_assignments(principal_id)
        
        # Query Prisma Cloud for resources accessible by this principal
        # This uses the principal's effective permissions
        
        correlation_data = {
            "azure_principal": {
                "object_id": principal_id,
                "type": principal_type,
                "name": principal.get('user_principal_name') if principal_type == 'user' else principal.get('display_name'),
                "roles": [ra.get('role_name') for ra in role_assignments]
            },
            "cloud_resources": self.find_cloud_resources_for_principal(principal_id, role_assignments)
        }
        
        return correlation_data
    
    def find_cloud_resources_for_principal(self, principal_id: str, role_assignments: List[Dict]) -> List[Dict]:
        """Find cloud resources accessible by principal based on role assignments"""
        cloud_resources = []
        
        # Extract scopes from role assignments
        for assignment in role_assignments:
            scope = assignment.get('scope', '')
            if scope:
                # Query Prisma Cloud for resources in this scope
                # Scope could be subscription, resource group, or specific resource
                resources = self.prisma.get_resources_by_scope(scope)
                cloud_resources.extend(resources)
        
        return cloud_resources

# Usage Example
if __name__ == "__main__":
    from azure_iam_client import AzureIAMClient
    from prisma_cloud_client import PrismaCloudClient
    
    azure_iam = AzureIAMClient(
        tenant_id=os.getenv("AZURE_TENANT_ID"),
        subscription_id=os.getenv("AZURE_SUBSCRIPTION_ID"),
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_secret=os.getenv("AZURE_CLIENT_SECRET")
    )
    
    prisma = PrismaCloudClient(
        api_url=os.getenv("PRISMA_API_URL"),
        access_key=os.getenv("PRISMA_ACCESS_KEY"),
        secret_key=os.getenv("PRISMA_SECRET_KEY")
    )
    
    integration = AzureIAMPrismaCloudIntegration(azure_iam, prisma)
    
    # Sync users to Prisma Cloud
    integration.sync_azure_users_to_prisma()
    
    # Sync service principals to Prisma Cloud
    integration.sync_azure_service_principals_to_prisma()
    
    # Sync recent events
    integration.sync_azure_events_to_prisma(hours=24)
```

# 4.2 Prisma Cloud Alerts from Azure IAM Events

```python
#!/usr/bin/env python3
"""
Prisma Cloud Alert Creation from Azure IAM Events
Purpose: Create Prisma Cloud alerts based on Azure IAM security events
"""

class AzureIAMPrismaAlertIntegration:
    """Create Prisma Cloud alerts from Azure IAM events"""
    
    def __init__(self, azure_iam_client, prisma_client):
        self.azure_iam = azure_iam_client
        self.prisma = prisma_client
    
    def create_prisma_alert_from_event(self, event: Dict) -> Dict:
        """Create Prisma Cloud alert from Azure IAM event"""
        operation_name = event.get('operation_name')
        caller = event.get('caller', 'Unknown')
        
        # Determine if this should create an alert
        if not self.should_create_alert(operation_name):
            return None
        
        # Build alert payload
        alert = {
            "policy": {
                "name": f"Azure IAM Security Event: {operation_name}",
                "policyType": "config",
                "cloudType": "azure",
                "severity": self.map_severity(operation_name)
            },
            "resource": {
                "id": f"azure-iam-principal:{caller}",
                "name": caller,
                "cloudType": "azure",
                "resourceType": "iam_principal"
            },
            "alertTime": event.get('event_timestamp'),
            "description": f"""
            Azure IAM Security Event Detected
            
            Operation: {operation_name}
            Principal: {caller}
            Resource ID: {event.get('resource_id', 'Unknown')}
            Subscription ID: {self.azure_iam.subscription_id}
            Timestamp: {event.get('event_timestamp', '')}
            
            This alert was automatically created from Azure Activity Log event.
            """,
            "customFields": {
                "azure_event_id": event.get('id'),
                "azure_operation_name": operation_name,
                "azure_caller": caller,
                "azure_subscription_id": self.azure_iam.subscription_id,
                "azure_tenant_id": self.azure_iam.tenant_id
            }
        }
        
        # Create alert in Prisma Cloud
        return self.prisma.create_alert(alert)
    
    def create_prisma_alert_for_excessive_permissions(self, principal_id: str, role_assignments: List[Dict], principal_type: str) -> Dict:
        """Create Prisma Cloud alert for principal with excessive permissions"""
        # Check for admin roles
        admin_roles = ['Owner', 'User Access Administrator', 'Contributor', 'Global Administrator']
        admin_assignments = [ra for ra in role_assignments if any(admin_role in ra.get('role_name', '') for admin_role in admin_roles)]
        
        if admin_assignments:
            # Get principal details
            if principal_type == 'user':
                principal = self.azure_iam.get_user(principal_id)
                principal_name = principal.get('user_principal_name', principal_id)
            else:
                principal = self.azure_iam.get_service_principal(principal_id)
                principal_name = principal.get('display_name', principal_id)
            
            alert = {
                "policy": {
                    "name": "Azure IAM: Excessive Permissions",
                    "policyType": "config",
                    "cloudType": "azure",
                    "severity": "high"
                },
                "resource": {
                    "id": f"azure-iam-principal:{principal_id}",
                    "name": principal_name,
                    "cloudType": "azure",
                    "resourceType": "iam_principal"
                },
                "alertTime": datetime.now().isoformat(),
                "description": f"""
                Azure IAM Principal with Excessive Permissions Detected
                
                Principal: {principal_name}
                Principal Type: {principal_type}
                Admin Roles: {len(admin_assignments)}
                
                Recommendation: Review and apply least privilege principles.
                """,
                "customFields": {
                    "azure_principal_id": principal_id,
                    "azure_principal_type": principal_type,
                    "admin_role_count": len(admin_assignments),
                    "compliance_issue": "least_privilege"
                }
            }
            
            return self.prisma.create_alert(alert)
        
        return None
    
    def should_create_alert(self, operation_name: str) -> bool:
        """Determine if event should create an alert"""
        alert_worthy_operations = [
            'Microsoft.Authorization/roleAssignments/write',
            'Microsoft.Graph/users/delete',
            'Microsoft.Graph/servicePrincipals/delete',
            'Microsoft.Graph/users/write',
            'Microsoft.Graph/servicePrincipals/write'
        ]
        return any(op in operation_name for op in alert_worthy_operations)
    
    def map_severity(self, operation_name: str) -> str:
        """Map operation type to Prisma Cloud severity"""
        severity_map = {
            'Microsoft.Authorization/roleAssignments/write': 'high',
            'Microsoft.Graph/users/delete': 'high',
            'Microsoft.Graph/servicePrincipals/delete': 'high',
            'Microsoft.Graph/users/write': 'medium',
            'Microsoft.Graph/servicePrincipals/write': 'medium'
        }
        return severity_map.get(operation_name, 'low')
```

# 4.3 Least Privilege Analysis with Prisma Cloud

```python
#!/usr/bin/env python3
"""
Least Privilege Analysis with Prisma Cloud
Purpose: Analyze Azure IAM permissions and generate least privilege recommendations
"""

class AzureIAMLeastPrivilegeAnalysis:
    """Analyze Azure IAM permissions for least privilege compliance"""
    
    def __init__(self, azure_iam_client, prisma_client):
        self.azure_iam = azure_iam_client
        self.prisma = prisma_client
    
    def analyze_principal_permissions(self, principal_id: str, principal_type: str) -> Dict:
        """Analyze principal permissions and generate recommendations"""
        if principal_type == 'user':
            principal = self.azure_iam.get_user(principal_id)
            role_assignments = self.azure_iam.get_user_role_assignments(principal_id)
        else:
            principal = self.azure_iam.get_service_principal(principal_id)
            role_assignments = self.azure_iam.get_service_principal_role_assignments(principal_id)
        
        # Get usage data from Prisma Cloud
        identity_id = f"azure://{self.azure_iam.tenant_id}/{principal_type}s/{principal_id}"
        usage_data = self.prisma.get_identity_usage_data(identity_id)
        
        # Analyze permissions
        analysis = {
            "principal": principal_id,
            "principal_type": principal_type,
            "identity_id": identity_id,
            "current_roles": [ra.get('role_name') for ra in role_assignments],
            "used_permissions": usage_data.get('used_permissions', []),
            "unused_permissions": [],
            "recommendations": []
        }
        
        # Find unused permissions
        analysis["unused_permissions"] = self.find_unused_permissions(
            analysis["current_roles"],
            analysis["used_permissions"]
        )
        
        # Generate recommendations
        analysis["recommendations"] = self.generate_recommendations(analysis)
        
        # Send to Prisma Cloud
        self.send_analysis_to_prisma(analysis)
        
        return analysis
    
    def find_unused_permissions(self, current: List[str], used: List[str]) -> List[str]:
        """Find roles that are assigned but not used"""
        # This is a simplified version
        # In production, you would map roles to permissions and check usage
        unused = []
        for role in current:
            # Check if role is in used permissions
            if role not in used:
                unused.append(role)
        return unused
    
    def generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate least privilege recommendations"""
        recommendations = []
        
        unused_count = len(analysis.get('unused_permissions', []))
        if unused_count > 0:
            recommendations.append(f"Remove {unused_count} unused role assignments")
        
        # Check for admin roles
        admin_roles = ['Owner', 'User Access Administrator', 'Contributor', 'Global Administrator']
        admin_assignments = [role for role in analysis.get('current_roles', []) if any(admin_role in role for admin_role in admin_roles)]
        if admin_assignments:
            recommendations.append(f"Consider replacing {len(admin_assignments)} admin role(s) with specific permissions")
        
        # Check for multiple role assignments
        if len(analysis.get('current_roles', [])) > 5:
            recommendations.append("Review multiple role assignments - consider consolidating")
        
        return recommendations
    
    def send_analysis_to_prisma(self, analysis: Dict):
        """Send analysis results to Prisma Cloud"""
        url = f"{self.prisma.api_url}/v2/identity/analysis"
        
        payload = {
            "analysis": analysis,
            "timestamp": datetime.now().isoformat()
        }
        
        response = requests.post(
            url,
            json=payload,
            headers=self.prisma._get_headers()
        )
        
        return response.status_code == 200

# Usage Example
if __name__ == "__main__":
    from azure_iam_client import AzureIAMClient
    from prisma_cloud_client import PrismaCloudClient
    
    azure_iam = AzureIAMClient(
        tenant_id=os.getenv("AZURE_TENANT_ID"),
        subscription_id=os.getenv("AZURE_SUBSCRIPTION_ID"),
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_secret=os.getenv("AZURE_CLIENT_SECRET")
    )
    
    prisma = PrismaCloudClient(
        api_url=os.getenv("PRISMA_API_URL"),
        access_key=os.getenv("PRISMA_ACCESS_KEY"),
        secret_key=os.getenv("PRISMA_SECRET_KEY")
    )
    
    analyzer = AzureIAMLeastPrivilegeAnalysis(azure_iam, prisma)
    
    # Analyze user permissions
    analysis = analyzer.analyze_principal_permissions("user-object-id", "user")
    print(f"Unused permissions: {len(analysis.get('unused_permissions', []))}")
    print(f"Recommendations: {analysis.get('recommendations', [])}")
```

---

# Azure Monitor Activity Logs

# 4.1 Real-time Activity Logs Processing

```python
#!/usr/bin/env python3
"""
Real-time Azure Activity Logs Processing
Purpose: Process Activity Logs in real-time for IAM monitoring
"""

from datetime import datetime
from typing import Dict, List
import json

class AzureActivityLogsProcessor:
    """Process Azure Activity Logs for IAM monitoring"""
    
    def __init__(self, azure_iam_client, xdr_client, xsoar_client):
        self.azure_iam = azure_iam_client
        self.xdr = xdr_client
        self.xsoar = xsoar_client
    
    def process_activity_log(self, log_entry: Dict):
        """Process a single Activity Log entry"""
        resource_provider = log_entry.get('resource_provider_name', '')
        operation_name = log_entry.get('operation_name', '')
        
        # Only process IAM events
        if 'Microsoft.Authorization' not in resource_provider and 'Microsoft.Graph' not in resource_provider:
            return
        
        # Check if this is a security-relevant event
        if self.is_security_event(operation_name):
            # Create incidents in both XDR and XSOAR
            self.create_incidents_from_log(log_entry)
    
    def is_security_event(self, operation_name: str) -> bool:
        """Check if operation is security-relevant"""
        security_operations = [
            'roleAssignments/write',
            'roleAssignments/delete',
            'servicePrincipals/write',
            'servicePrincipals/delete',
            'users/write',
            'users/delete'
        ]
        return any(op in operation_name for op in security_operations)
    
    def create_incidents_from_log(self, log_entry: Dict):
        """Create incidents in XDR and XSOAR from Activity Log"""
        # Create XDR incident
        xdr_integration = AzureIAMXDRIntegration(self.azure_iam, self.xdr)
        xdr_integration.process_iam_event(log_entry)
        
        # Create XSOAR incident
        xsoar_integration = AzureIAMXSOARIntegration(self.azure_iam, self.xsoar)
        xsoar_integration.create_xsoar_incident_from_event(log_entry)

# Usage with Azure Event Grid
"""
This processor can be used with Azure Event Grid to process Activity Logs in real-time.
Configure Activity Log export to Event Grid and subscribe to process logs.
"""
```

---

# Webhook Integrations

# 5.1 Azure Event Grid to XDR/XSOAR Webhook

```python
#!/usr/bin/env python3
"""
Azure Event Grid Webhook Integration
Purpose: Receive Azure Event Grid events and route to XDR/XSOAR
"""

from flask import Flask, request, jsonify
import os
import json

app = Flask(__name__)

# Initialize clients (would be done in production setup)
# azure_iam_client = AzureIAMClient(...)
# xdr_client = CortexXDRClient(...)
# xsoar_client = XSOARClient(...)

@app.route('/azure/eventgrid', methods=['POST'])
def eventgrid_webhook():
    """Receive Azure Event Grid webhook"""
    try:
        # Verify webhook (implement Event Grid verification)
        if not verify_eventgrid_message(request):
            return jsonify({"error": "Invalid message"}), 401
        
        data = request.json
        
        # Event Grid sends events in an array
        events = data if isinstance(data, list) else [data]
        
        for event in events:
            event_type = event.get('eventType', '')
            data = event.get('data', {})
            
            # Only process IAM events
            if 'Microsoft.Authorization' in str(data) or 'Microsoft.Graph' in str(data):
                handle_iam_event(event)
        
        return jsonify({"status": "success"}), 200
    
    except Exception as e:
        print(f"Webhook error: {e}")
        return jsonify({"error": str(e)}), 500

def verify_eventgrid_message(request) -> bool:
    """Verify Event Grid message"""
    # Implementation would verify the message signature
    # using Event Grid's signature verification method
    # Check aeg-signature header
    signature = request.headers.get('aeg-signature')
    # Verify signature against Event Grid secret
    return True

def handle_iam_event(event: dict):
    """Handle IAM-related events"""
    data = event.get('data', {})
    operation_name = data.get('operationName', '')
    
    # Route to appropriate handler
    if 'roleAssignments/write' in operation_name:
        handle_role_assignment_event(event)
    elif 'users/delete' in operation_name or 'servicePrincipals/delete' in operation_name:
        handle_principal_deletion(event)
    elif 'users/write' in operation_name or 'servicePrincipals/write' in operation_name:
        handle_principal_modification(event)

def handle_role_assignment_event(event: dict):
    """Handle role assignment events"""
    # Send to XDR
    xdr_integration = AzureIAMXDRIntegration(azure_iam_client, xdr_client)
    xdr_integration.process_iam_event(convert_to_activity_log_format(event))
    
    # Send to XSOAR
    xsoar_integration = AzureIAMXSOARIntegration(azure_iam_client, xsoar_client)
    xsoar_integration.trigger_playbook_for_event(convert_to_activity_log_format(event))

def handle_principal_deletion(event: dict):
    """Handle principal deletion events"""
    # Send to XDR
    xdr_integration = AzureIAMXDRIntegration(azure_iam_client, xdr_client)
    xdr_integration.process_iam_event(convert_to_activity_log_format(event))
    
    # Send to XSOAR
    xsoar_integration = AzureIAMXSOARIntegration(azure_iam_client, xsoar_client)
    xsoar_integration.create_xsoar_incident_from_event(convert_to_activity_log_format(event))

def handle_principal_modification(event: dict):
    """Handle principal modification events"""
    # Send to XDR
    xdr_integration = AzureIAMXDRIntegration(azure_iam_client, xdr_client)
    xdr_integration.process_iam_event(convert_to_activity_log_format(event))
    
    # Send to XSOAR
    xsoar_integration = AzureIAMXSOARIntegration(azure_iam_client, xsoar_client)
    xsoar_integration.create_xsoar_incident_from_event(convert_to_activity_log_format(event))

def convert_to_activity_log_format(event: dict) -> dict:
    """Convert Event Grid event to Activity Log format"""
    data = event.get('data', {})
    return {
        'id': event.get('id'),
        'operation_name': data.get('operationName', ''),
        'caller': data.get('caller', ''),
        'event_timestamp': event.get('eventTime', ''),
        'resource_id': data.get('resourceUri', ''),
        'status': data.get('status', {}).get('value', 'Unknown'),
        'properties': data.get('properties', {})
    }

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
    
    def __init__(self, azure_iam_client, xdr_client, xsoar_client):
        self.azure_iam = azure_iam_client
        self.xdr = xdr_client
        self.xsoar = xsoar_client
    
    def execute_workflow(self, event: Dict):
        """Execute complete privilege escalation workflow"""
        
        # Step 1: Detect privilege escalation
        if not self.is_privilege_escalation(event):
            return
        
        caller = event.get('caller', 'Unknown')
        
        # Step 2: Gather intelligence
        intelligence = self.gather_intelligence(caller, event)
        
        # Step 3: Create incidents in all platforms
        xdr_incident = self.create_xdr_incident(event, intelligence)
        xsoar_incident = self.create_xsoar_incident(event, intelligence)
        
        # Step 4: Automated response
        response_action = self.determine_response(intelligence)
        self.execute_response(caller, response_action, xdr_incident.get('incident_id'))
        
        # Step 5: Notify stakeholders
        self.notify_stakeholders(event, intelligence, response_action)
        
        return {
            "xdr_incident": xdr_incident,
            "xsoar_incident": xsoar_incident,
            "response_action": response_action
        }
    
    def is_privilege_escalation(self, event: Dict) -> bool:
        """Determine if event indicates privilege escalation"""
        operation_name = event.get('operation_name', '')
        
        # Check for role assignment that grants admin access
        if 'roleAssignments/write' in operation_name:
            properties = event.get('properties', {})
            # Check if role assignment grants admin permissions
            role_definition_id = properties.get('roleDefinitionId', '')
            # Check for admin roles
            admin_roles = ['Owner', 'User Access Administrator', 'Contributor']
            if any(role in role_definition_id for role in admin_roles):
                return True
        
        return False
    
    def gather_intelligence(self, caller: str, event: Dict) -> Dict:
        """Gather intelligence about the principal and event"""
        # Try to get user or service principal
        principal_id = caller
        user = self.azure_iam.get_user(principal_id)
        if not user:
            sp = self.azure_iam.get_service_principal(principal_id)
        else:
            sp = None
        
        role_assignments = self.azure_iam.get_user_role_assignments(principal_id) if user else self.azure_iam.get_service_principal_role_assignments(principal_id) if sp else []
        recent_events = self.azure_iam.get_activity_logs(
            filter_str=f"caller eq '{caller}'",
            start_time=datetime.now() - timedelta(days=7)
        )
        
        return {
            "user": user,
            "service_principal": sp,
            "role_assignments": role_assignments,
            "recent_events": recent_events,
            "risk_score": self.calculate_risk_score(user, sp, role_assignments, recent_events)
        }
    
    def calculate_risk_score(self, user: Dict, sp: Dict, role_assignments: List, events: List) -> int:
        """Calculate risk score"""
        score = 0
        
        # Admin roles
        admin_roles = ['Owner', 'User Access Administrator', 'Contributor']
        for assignment in role_assignments:
            if any(role in assignment.get('role_name', '') for role in admin_roles):
                score += 3
        
        # Recent role assignment changes
        role_events = [e for e in events if 'roleAssignments' in e.get('operation_name', '')]
        score += min(len(role_events), 3)
        
        return min(score, 10)
    
    def determine_response(self, intelligence: Dict) -> str:
        """Determine response action"""
        risk_score = intelligence.get('risk_score', 0)
        
        if risk_score >= 8:
            if intelligence.get('user'):
                return 'disable_user'
            elif intelligence.get('service_principal'):
                return 'disable_service_principal'
        elif risk_score >= 5:
            return 'remove_role_assignments'
        else:
            return 'monitor'
    
    def execute_response(self, principal_id: str, action: str, incident_id: str):
        """Execute response action"""
        if action == 'disable_user':
            result = self.azure_iam.disable_user(principal_id)
            self.xdr.add_incident_comment(
                incident_id,
                f"Automated Response: {result.get('message', 'Action completed')}"
            )
        elif action == 'disable_service_principal':
            result = self.azure_iam.disable_service_principal(principal_id)
            self.xdr.add_incident_comment(
                incident_id,
                f"Automated Response: {result.get('message', 'Action completed')}"
            )
        # 'monitor' and 'remove_role_assignments' would require additional implementation
    
    def create_xdr_incident(self, event: Dict, intelligence: Dict) -> Dict:
        """Create XDR incident"""
        xdr_integration = AzureIAMXDRIntegration(self.azure_iam, self.xdr)
        return xdr_integration.create_xdr_incident_from_event(event)
    
    def create_xsoar_incident(self, event: Dict, intelligence: Dict) -> Dict:
        """Create XSOAR incident"""
        xsoar_integration = AzureIAMXSOARIntegration(self.azure_iam, self.xsoar)
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
# Azure Configuration
export AZURE_TENANT_ID="your-azure-tenant-id"
export AZURE_SUBSCRIPTION_ID="your-azure-subscription-id"
export AZURE_CLIENT_ID="your-service-principal-client-id"
export AZURE_CLIENT_SECRET="your-service-principal-client-secret"

# Alternative: Use Managed Identity (no credentials needed)
# export AZURE_USE_MANAGED_IDENTITY="true"

# Cortex XDR Configuration
export XDR_API_KEY="your-xdr-api-key"
export XDR_API_KEY_ID="your-xdr-key-id"
export XDR_BASE_URL="https://api.xdr.us.paloaltonetworks.com"

# XSOAR Configuration
export XSOAR_URL="https://xsoar.example.com"
export XSOAR_API_KEY="your-xsoar-api-key"

# Prisma Cloud Configuration
export PRISMA_API_URL="https://api.prismacloud.io"
export PRISMA_ACCESS_KEY="your-prisma-access-key"
export PRISMA_SECRET_KEY="your-prisma-secret-key"
```

# 7.2 Configuration File

```yaml
# azure_iam_integrations_config.yaml
azure:
  tenant_id: "${AZURE_TENANT_ID}"
  subscription_id: "${AZURE_SUBSCRIPTION_ID}"
  client_id: "${AZURE_CLIENT_ID}"
  client_secret: "${AZURE_CLIENT_SECRET}"
  
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
  
  prisma_cloud:
    enabled: true
    api_url: "${PRISMA_API_URL}"
    access_key: "${PRISMA_ACCESS_KEY}"
    secret_key: "${PRISMA_SECRET_KEY}"
    sync_users: true
    sync_service_principals: true
    sync_events: true
    enable_least_privilege_analysis: true

event_routing:
  Microsoft.Authorization/roleAssignments/write:
    - cortex_xdr
    - xsoar
    - prisma_cloud
  Microsoft.Graph/users/delete:
    - cortex_xdr
    - xsoar
    - prisma_cloud
  Microsoft.Graph/servicePrincipals/delete:
    - cortex_xdr
    - xsoar
    - prisma_cloud
  Microsoft.Graph/users/write:
    - cortex_xdr
    - xsoar
    - prisma_cloud

automated_responses:
  enabled: true
  actions:
    disable_user:
      trigger_severity: "critical"
      require_approval: true
    disable_service_principal:
      trigger_severity: "critical"
      require_approval: true
```

# 7.3 Azure IAM Permissions Required

```json
{
  "roleAssignments": [
    {
      "roleDefinitionId": "/subscriptions/{subscription-id}/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
      "principalId": "{service-principal-object-id}",
      "principalType": "ServicePrincipal",
      "roleDefinitionName": "Reader"
    },
    {
      "roleDefinitionId": "/subscriptions/{subscription-id}/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
      "principalId": "{service-principal-object-id}",
      "principalType": "ServicePrincipal",
      "roleDefinitionName": "Contributor"
    }
  ]
}
```

# Required Azure AD Application Permissions

- `Directory.Read.All` - Read directory data
- `User.Read.All` - Read all users' full profiles
- `Application.Read.All` - Read all applications
- `RoleManagement.Read.Directory` - Read directory role management
- `AuditLog.Read.All` - Read audit logs

---

# Troubleshooting

# Common Issues and Solutions

# 1. Authentication Failures

Problem: Azure API authentication fails

Solutions:
- Verify service principal credentials are correct
- Check service principal has required permissions
- Ensure AZURE_TENANT_ID and AZURE_SUBSCRIPTION_ID are correct
- Verify service principal is not disabled
- Check for expired client secrets
- Use Managed Identity if running on Azure resources

# 2. Activity Logs Not Available

Problem: Cannot retrieve Activity Logs

Solutions:
- Verify Activity Logs are enabled for the subscription
- Check IAM permissions include monitoring permissions
- Ensure Activity Log retention is configured
- Verify log filter syntax is correct
- Check subscription has Activity Log access

# 3. Rate Limiting

Problem: Azure API rate limits exceeded

Solutions:
- Implement exponential backoff
- Use pagination for large result sets
- Cache frequently accessed data
- Batch requests when possible
- Respect Azure API rate limits

# 4. Principal Not Found

Problem: Cannot find user or service principal

Solutions:
- Verify principal ID format is correct
- Check principal exists in Azure AD
- Ensure principal hasn't been deleted
- Verify tenant ID is correct
- Check Graph API permissions

# 5. Role Assignment Access Denied

Problem: Cannot read or modify role assignments

Solutions:
- Verify service principal has Reader role at subscription level
- Check for management locks on resources
- Ensure service principal has appropriate permissions
- Verify resource hierarchy permissions
- Check for Azure Policy restrictions

# 6. Graph API Issues

Problem: Cannot access Azure AD via Graph API

Solutions:
- Verify Graph API permissions are granted and consented
- Check application registration in Azure AD
- Ensure admin consent is provided for required permissions
- Verify tenant ID is correct
- Check for conditional access policies blocking access

---

# Best Practices

1. Service Principal Security: Use dedicated service principals for integrations with minimal required permissions
2. Least Privilege: Grant only minimum required Azure RBAC roles and Graph API permissions
3. Error Handling: Implement comprehensive error handling and logging
4. Rate Limiting: Respect Azure API rate limits and implement backoff
5. Event Deduplication: Implement logic to prevent processing duplicate events
6. Monitoring: Monitor integration health and API usage
7. Testing: Test integrations in non-production Azure subscriptions first
8. Documentation: Document custom mappings and configurations
9. Audit Logging: Log all actions taken via integrations
10. Activity Logs: Ensure Activity Logs are enabled and properly configured
11. Encryption: Use encrypted connections for all API calls
12. Managed Identity: Use Managed Identity when running on Azure resources instead of service principal secrets

---

# API Reference

# Azure IAM API Methods Used

- `authorization.roleAssignments.listForScope()` - List role assignments
- `authorization.roleDefinitions.getById()` - Get role definition
- `graphrbac.users.get()` - Get user details
- `graphrbac.users.list()` - List users
- `graphrbac.servicePrincipals.get()` - Get service principal
- `graphrbac.servicePrincipals.list()` - List service principals
- `monitor.activityLogs.list()` - List Activity Logs

# Microsoft Graph API Methods Used

- `GET /users/{id}` - Get user
- `GET /users` - List users
- `GET /servicePrincipals/{id}` - Get service principal
- `GET /servicePrincipals` - List service principals
- `PATCH /users/{id}` - Update user (for enable/disable)

# Required Azure RBAC Roles

- `Reader` - Read resources and Activity Logs
- `Monitoring Reader` - Read monitoring data
- `User Access Administrator` (optional, for remediation) - Manage user access

# Required Azure AD Application Permissions

- `Directory.Read.All`
- `User.Read.All`
- `Application.Read.All`
- `RoleManagement.Read.Directory`
- `AuditLog.Read.All`

---

Version: 1.0  
Last Updated: 2026-01-09  
Maintained By: SOC Team
