# Okta Integrations Standard Operating Procedure (SOP)

# Table of Contents

1. [Overview](#overview)
2. [Okta API Integration Basics](#okta-api-integration-basics)
3. [Okta to Cortex XDR Integration](#okta-to-cortex-xdr-integration)
4. [Okta to XSOAR Integration](#okta-to-xsoar-integration)
5. [Okta to Prisma Cloud Integration](#okta-to-prisma-cloud-integration)
6. [Webhook Integrations](#webhook-integrations)
7. [Use Cases and Workflows](#use-cases-and-workflows)
8. [Configuration and Setup](#configuration-and-setup)
9. [Troubleshooting](#troubleshooting)

---

# Overview

This SOP provides comprehensive integration code snippets and configuration examples for connecting Okta Identity Provider with Palo Alto Networks security products (Cortex XDR, XSOAR, Prisma Cloud). These integrations enable automated identity-based security operations, incident response, and compliance monitoring.

# Integration Use Cases

- Identity Threat Detection: Monitor Okta events for suspicious authentication patterns
- Automated Incident Response: Create security incidents in XDR/XSOAR based on Okta security events
- Access Governance: Sync Okta user access data to Prisma Cloud for CIEM analysis
- Compliance Monitoring: Track identity compliance violations across platforms
- Automated Remediation: Respond to identity-based threats automatically

---

# Okta API Integration Basics

# 1. Okta API Client (Python)

```python
#!/usr/bin/env python3
"""
Okta API Integration Client
Purpose: Authenticate and interact with Okta API
"""

import requests
import json
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import os

class OktaClient:
    """Okta API Client"""
    
    def __init__(self, base_url: str, api_token: str):
        """
        Initialize Okta client
        
        Args:
            base_url: Okta organization URL (e.g., https://dev-123456.okta.com)
            api_token: Okta API token
        """
        self.base_url = base_url.rstrip('/')
        self.api_token = api_token
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"SSWS {api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        })
    
    def get_user(self, user_id: str) -> Dict:
        """Get user details by ID or login"""
        url = f"{self.base_url}/api/v1/users/{user_id}"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()
    
    def search_users(self, query: str, limit: int = 200) -> List[Dict]:
        """Search users by query"""
        url = f"{self.base_url}/api/v1/users"
        params = {
            "q": query,
            "limit": limit
        }
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()
    
    def get_user_groups(self, user_id: str) -> List[Dict]:
        """Get groups for a user"""
        url = f"{self.base_url}/api/v1/users/{user_id}/groups"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()
    
    def get_user_apps(self, user_id: str) -> List[Dict]:
        """Get applications assigned to a user"""
        url = f"{self.base_url}/api/v1/users/{user_id}/appLinks"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()
    
    def get_events(self, 
                  start_time: Optional[datetime] = None,
                  end_time: Optional[datetime] = None,
                  filter: Optional[str] = None,
                  limit: int = 1000) -> List[Dict]:
        """
        Get Okta system log events
        
        Args:
            start_time: Start time for event query
            end_time: End time for event query
            filter: Event filter expression
            limit: Maximum number of events to return
        """
        url = f"{self.base_url}/api/v1/logs"
        
        params = {
            "limit": limit
        }
        
        if start_time:
            params["since"] = start_time.isoformat()
        if end_time:
            params["until"] = end_time.isoformat()
        if filter:
            params["filter"] = filter
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()
    
    def get_security_events(self, 
                           start_time: Optional[datetime] = None,
                           limit: int = 1000) -> List[Dict]:
        """Get security-related events"""
        security_filters = [
            'eventType eq "user.session.start"',
            'eventType eq "user.authentication.sso"',
            'eventType eq "user.mfa.factor.attempt_fail"',
            'eventType eq "user.account.lock"',
            'eventType eq "user.account.unlock"',
            'eventType eq "user.lifecycle.create"',
            'eventType eq "user.lifecycle.delete"',
            'eventType eq "user.lifecycle.suspend"',
            'eventType eq "user.lifecycle.unsuspend"',
            'eventType eq "application.user_membership.add"',
            'eventType eq "application.user_membership.remove"'
        ]
        
        filter_str = " or ".join(security_filters)
        
        return self.get_events(
            start_time=start_time,
            filter=filter_str,
            limit=limit
        )
    
    def suspend_user(self, user_id: str) -> Dict:
        """Suspend a user account"""
        url = f"{self.base_url}/api/v1/users/{user_id}/lifecycle/suspend"
        response = self.session.post(url)
        response.raise_for_status()
        return response.json()
    
    def unsuspend_user(self, user_id: str) -> Dict:
        """Unsuspend a user account"""
        url = f"{self.base_url}/api/v1/users/{user_id}/lifecycle/unsuspend"
        response = self.session.post(url)
        response.raise_for_status()
        return response.json()
    
    def deactivate_user(self, user_id: str) -> Dict:
        """Deactivate a user account"""
        url = f"{self.base_url}/api/v1/users/{user_id}/lifecycle/deactivate"
        response = self.session.post(url)
        response.raise_for_status()
        return response.json()
    
    def reset_user_password(self, user_id: str, send_email: bool = True) -> Dict:
        """Reset user password"""
        url = f"{self.base_url}/api/v1/users/{user_id}/lifecycle/reset_password"
        params = {"sendEmail": send_email}
        response = self.session.post(url, params=params)
        response.raise_for_status()
        return response.json()
    
    def get_factors(self, user_id: str) -> List[Dict]:
        """Get MFA factors for a user"""
        url = f"{self.base_url}/api/v1/users/{user_id}/factors"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json()
    
    def clear_user_sessions(self, user_id: str) -> Dict:
        """Clear all active sessions for a user"""
        url = f"{self.base_url}/api/v1/users/{user_id}/sessions"
        response = self.session.delete(url)
        response.raise_for_status()
        return {"status": "success"}

# Usage Example
if __name__ == "__main__":
    client = OktaClient(
        base_url=os.getenv("OKTA_BASE_URL", "https://dev-123456.okta.com"),
        api_token=os.getenv("OKTA_API_TOKEN")
    )
    
    # Get recent security events
    events = client.get_security_events(
        start_time=datetime.now() - timedelta(hours=24)
    )
    print(f"Found {len(events)} security events")
    
    # Get user details
    user = client.get_user("user@example.com")
    print(f"User: {user.get('profile', {}).get('firstName')} {user.get('profile', {}).get('lastName')}")
```

---

# Okta to Cortex XDR Integration

# 2.1 Okta Events to XDR Incidents

```python
#!/usr/bin/env python3
"""
Okta to Cortex XDR Integration
Purpose: Create XDR incidents from Okta security events
"""

from datetime import datetime, timedelta
from typing import Dict, List
import os

class OktaXDRIntegration:
    """Integrate Okta events with Cortex XDR"""
    
    def __init__(self, okta_client, xdr_client):
        self.okta = okta_client
        self.xdr = xdr_client
    
    def monitor_okta_events(self, check_interval_minutes: int = 15):
        """Continuously monitor Okta events and create XDR incidents"""
        last_check = datetime.now() - timedelta(minutes=check_interval_minutes)
        
        while True:
            try:
                # Get security events since last check
                events = self.okta.get_security_events(start_time=last_check)
                
                # Process events
                for event in events:
                    self.process_okta_event(event)
                
                last_check = datetime.now()
                time.sleep(check_interval_minutes * 60)
                
            except Exception as e:
                print(f"Error monitoring Okta events: {e}")
                time.sleep(60)
    
    def process_okta_event(self, event: Dict):
        """Process a single Okta event and create XDR incident if needed"""
        event_type = event.get('eventType')
        severity = self.determine_severity(event)
        
        # Only create incidents for high-severity events
        if severity in ['high', 'critical']:
            incident_data = self.create_xdr_incident_from_event(event)
            self.xdr.create_incident(incident_data)
    
    def determine_severity(self, event: Dict) -> str:
        """Determine severity based on event type"""
        event_type = event.get('eventType', '')
        
        critical_events = [
            'user.account.lock',
            'user.lifecycle.delete',
            'user.mfa.factor.attempt_fail'
        ]
        
        high_events = [
            'user.session.start',
            'user.authentication.sso',
            'user.lifecycle.suspend',
            'application.user_membership.add'
        ]
        
        if event_type in critical_events:
            return 'critical'
        elif event_type in high_events:
            return 'high'
        else:
            return 'medium'
    
    def create_xdr_incident_from_event(self, event: Dict) -> Dict:
        """Create XDR incident payload from Okta event"""
        event_type = event.get('eventType')
        user_id = event.get('actor', {}).get('alternateId', 'Unknown')
        timestamp = event.get('published', datetime.now().isoformat())
        
        # Build incident description
        description = f"""
        Okta Security Event Detected
        
        Event Type: {event_type}
        User: {user_id}
        Timestamp: {timestamp}
        IP Address: {event.get('client', {}).get('ipAddress', 'Unknown')}
        User Agent: {event.get('client', {}).get('userAgent', {}).get('rawUserAgent', 'Unknown')}
        
        Event Details:
        {json.dumps(event, indent=2)}
        """
        
        return {
            "incident_name": f"Okta: {event_type} - {user_id}",
            "severity": self.determine_severity(event),
            "description": description,
            "labels": [
                {"key": "source", "value": "Okta"},
                {"key": "event_type", "value": event_type},
                {"key": "user_id", "value": user_id}
            ],
            "custom_fields": {
                "okta_event_id": event.get('uuid'),
                "okta_event_type": event_type,
                "okta_user_id": user_id,
                "okta_ip_address": event.get('client', {}).get('ipAddress'),
                "okta_timestamp": timestamp
            }
        }
    
    def sync_suspicious_login_to_xdr(self, user_id: str, event: Dict):
        """Create XDR incident for suspicious login"""
        user = self.okta.get_user(user_id)
        user_groups = self.okta.get_user_groups(user_id)
        
        # Check for suspicious patterns
        is_suspicious = self.detect_suspicious_pattern(event, user, user_groups)
        
        if is_suspicious:
            incident = {
                "incident_name": f"Okta: Suspicious Login - {user_id}",
                "severity": "high",
                "description": f"""
                Suspicious login detected for user: {user_id}
                
                User Details:
                - Name: {user.get('profile', {}).get('firstName')} {user.get('profile', {}).get('lastName')}
                - Email: {user.get('profile', {}).get('email')}
                - Groups: {', '.join([g.get('profile', {}).get('name') for g in user_groups])}
                
                Login Details:
                - IP Address: {event.get('client', {}).get('ipAddress')}
                - Location: {event.get('client', {}).get('geographicalContext', {}).get('city')}
                - User Agent: {event.get('client', {}).get('userAgent', {}).get('rawUserAgent')}
                - Timestamp: {event.get('published')}
                
                Risk Indicators:
                - Unusual location
                - New device
                - Off-hours access
                """,
                "labels": [
                    {"key": "source", "value": "Okta"},
                    {"key": "event_type", "value": "suspicious_login"},
                    {"key": "threat_type", "value": "identity_compromise"}
                ]
            }
            
            xdr_incident = self.xdr.create_incident(incident)
            
            # Add comment with remediation steps
            self.xdr.add_incident_comment(
                xdr_incident.get('incident_id'),
                "Recommended Actions:\n1. Verify user identity\n2. Review recent activity\n3. Consider suspending account if confirmed compromise"
            )
            
            return xdr_incident
    
    def detect_suspicious_pattern(self, event: Dict, user: Dict, groups: List[Dict]) -> bool:
        """Detect suspicious login patterns"""
        ip_address = event.get('client', {}).get('ipAddress')
        timestamp = datetime.fromisoformat(event.get('published').replace('Z', '+00:00'))
        
        # Check for off-hours access (outside 8 AM - 6 PM)
        hour = timestamp.hour
        if hour < 8 or hour > 18:
            return True
        
        # Check for high-privilege user login from new location
        privileged_groups = ['Administrators', 'Security Team', 'IT Admins']
        user_group_names = [g.get('profile', {}).get('name') for g in groups]
        
        if any(group in privileged_groups for group in user_group_names):
            # Additional checks for privileged users
            return True
        
        return False

# Usage Example
if __name__ == "__main__":
    from okta_client import OktaClient
    from cortex_xdr_client import CortexXDRClient
    
    # Initialize clients
    okta = OktaClient(
        base_url=os.getenv("OKTA_BASE_URL"),
        api_token=os.getenv("OKTA_API_TOKEN")
    )
    
    xdr = CortexXDRClient(
        api_key=os.getenv("XDR_API_KEY"),
        api_key_id=os.getenv("XDR_API_KEY_ID")
    )
    
    # Create integration
    integration = OktaXDRIntegration(okta, xdr)
    
    # Monitor events
    integration.monitor_okta_events(check_interval_minutes=15)
```

# 2.2 Automated Response to XDR Incidents

```python
#!/usr/bin/env python3
"""
Automated Response: XDR Incident → Okta Actions
Purpose: Automatically respond to XDR incidents by taking Okta actions
"""

class XDROktaResponse:
    """Automated response to XDR incidents using Okta"""
    
    def __init__(self, xdr_client, okta_client):
        self.xdr = xdr_client
        self.okta = okta_client
    
    def handle_xdr_incident(self, incident_id: str):
        """Handle XDR incident and take Okta actions"""
        incident = self.xdr.get_incident(incident_id)
        
        # Check if incident is related to identity
        if self.is_identity_related(incident):
            user_id = self.extract_user_id(incident)
            
            if user_id:
                # Determine response action
                action = self.determine_response_action(incident)
                
                if action == 'suspend':
                    self.okta.suspend_user(user_id)
                    self.xdr.add_incident_comment(
                        incident_id,
                        f"Automated Response: Suspended Okta user {user_id}"
                    )
                elif action == 'clear_sessions':
                    self.okta.clear_user_sessions(user_id)
                    self.xdr.add_incident_comment(
                        incident_id,
                        f"Automated Response: Cleared all sessions for user {user_id}"
                    )
                elif action == 'reset_password':
                    self.okta.reset_user_password(user_id, send_email=True)
                    self.xdr.add_incident_comment(
                        incident_id,
                        f"Automated Response: Reset password for user {user_id}"
                    )
    
    def is_identity_related(self, incident: Dict) -> bool:
        """Check if incident is identity-related"""
        labels = incident.get('labels', [])
        for label in labels:
            if label.get('key') == 'source' and label.get('value') == 'Okta':
                return True
            if label.get('key') == 'threat_type') and 'identity' in label.get('value', '').lower():
                return True
        return False
    
    def extract_user_id(self, incident: Dict) -> Optional[str]:
        """Extract user ID from incident"""
        custom_fields = incident.get('custom_fields', {})
        return custom_fields.get('okta_user_id')
    
    def determine_response_action(self, incident: Dict) -> str:
        """Determine appropriate response action"""
        severity = incident.get('severity', 'medium')
        
        if severity == 'critical':
            return 'suspend'
        elif severity == 'high':
            return 'clear_sessions'
        else:
            return 'reset_password'
```

---

# Okta to XSOAR Integration

# 3.1 Okta Events to XSOAR Incidents

```python
#!/usr/bin/env python3
"""
Okta to XSOAR Integration
Purpose: Create XSOAR incidents from Okta events and automate playbooks
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
import os

class OktaXSOARIntegration:
    """Integrate Okta with Cortex XSOAR"""
    
    def __init__(self, okta_client, xsoar_client):
        self.okta = okta_client
        self.xsoar = xsoar_client
    
    def create_xsoar_incident_from_okta_event(self, event: Dict) -> Dict:
        """Create XSOAR incident from Okta event"""
        event_type = event.get('eventType')
        user_id = event.get('actor', {}).get('alternateId', 'Unknown')
        
        # Get user details
        try:
            user = self.okta.get_user(user_id)
            user_name = f"{user.get('profile', {}).get('firstName', '')} {user.get('profile', {}).get('lastName', '')}"
            user_email = user.get('profile', {}).get('email', user_id)
        except:
            user_name = user_id
            user_email = user_id
        
        # Determine incident type and severity
        incident_type, severity = self.map_event_to_incident_type(event_type)
        
        # Create incident
        incident = self.xsoar.create_incident(
            name=f"Okta: {event_type} - {user_name}",
            severity=severity,
            type=incident_type,
            labels=[
                {"type": "source", "value": "Okta"},
                {"type": "event_type", "value": event_type},
                {"type": "user_id", "value": user_id},
                {"type": "user_email", "value": user_email}
            ],
            custom_fields={
                "okta_event_id": event.get('uuid'),
                "okta_event_type": event_type,
                "okta_user_id": user_id,
                "okta_user_name": user_name,
                "okta_user_email": user_email,
                "okta_ip_address": event.get('client', {}).get('ipAddress'),
                "okta_timestamp": event.get('published'),
                "okta_outcome": event.get('outcome', {}).get('result', 'Unknown')
            }
        )
        
        # Add detailed description
        description = self.build_incident_description(event, user_name, user_email)
        self.xsoar.add_incident_entry(
            incident.get('id'),
            description,
            entry_type="note"
        )
        
        return incident
    
    def map_event_to_incident_type(self, event_type: str) -> tuple:
        """Map Okta event type to XSOAR incident type and severity"""
        mapping = {
            'user.account.lock': ('Identity Access Management', 4),  # Critical
            'user.lifecycle.delete': ('Identity Access Management', 4),
            'user.mfa.factor.attempt_fail': ('Authentication', 3),  # High
            'user.session.start': ('Authentication', 2),  # Medium
            'user.authentication.sso': ('Authentication', 2),
            'user.lifecycle.suspend': ('Identity Access Management', 3),
            'user.lifecycle.create': ('Identity Access Management', 1),  # Low
            'application.user_membership.add': ('Access', 2),
            'application.user_membership.remove': ('Access', 2)
        }
        
        return mapping.get(event_type, ('Unclassified', 1))
    
    def build_incident_description(self, event: Dict, user_name: str, user_email: str) -> str:
        """Build detailed incident description"""
        return f"""
# Okta Security Event

# Event Information
- Event Type: {event.get('eventType')}
- Event ID: {event.get('uuid')}
- Timestamp: {event.get('published')}
- Outcome: {event.get('outcome', {}).get('result', 'Unknown')}

# User Information
- User ID: {event.get('actor', {}).get('alternateId')}
- Name: {user_name}
- Email: {user_email}

# Client Information
- IP Address: {event.get('client', {}).get('ipAddress', 'Unknown')}
- User Agent: {event.get('client', {}).get('userAgent', {}).get('rawUserAgent', 'Unknown')}
- Geographic Location: {self._get_location_string(event)}

# Event Details
```json
{json.dumps(event, indent=2)}
```

# Recommended Actions
1. Verify user identity
2. Review recent user activity in Okta
3. Check for related security events
4. Consider additional authentication requirements
        """
    
    def _get_location_string(self, event: Dict) -> str:
        """Get location string from event"""
        geo = event.get('client', {}).get('geographicalContext', {})
        city = geo.get('city', 'Unknown')
        state = geo.get('state', 'Unknown')
        country = geo.get('country', 'Unknown')
        return f"{city}, {state}, {country}"
    
    def trigger_playbook_for_okta_event(self, event: Dict):
        """Trigger XSOAR playbook based on Okta event"""
        event_type = event.get('eventType')
        
        # Create incident first
        incident = self.create_xsoar_incident_from_okta_event(event)
        
        # Trigger appropriate playbook
        if event_type in ['user.account.lock', 'user.mfa.factor.attempt_fail']:
            playbook_name = "Investigate Failed Authentication"
        elif event_type == 'user.lifecycle.delete':
            playbook_name = "Investigate User Deletion"
        elif event_type in ['user.session.start', 'user.authentication.sso']:
            playbook_name = "Investigate Suspicious Login"
        else:
            playbook_name = "Generic Identity Investigation"
        
        # Execute playbook
        self.xsoar.execute_command(
            command="executePlaybook",
            arguments={
                "incidentId": incident.get('id'),
                "playbookName": playbook_name
            }
        )
    
    def sync_okta_users_to_xsoar(self):
        """Sync Okta user data to XSOAR for reference"""
        # This would typically be done via XSOAR's Okta integration
        # But can also be done via API
        
        users = self.okta.search_users("status eq \"ACTIVE\"")
        
        for user in users[:100]:  # Limit to first 100
            user_data = {
                "name": f"Okta User: {user.get('profile', {}).get('email')}",
                "type": "Identity",
                "rawJSON": json.dumps(user),
                "labels": [
                    {"type": "source", "value": "Okta"},
                    {"type": "user_id", "value": user.get('id')},
                    {"type": "email", "value": user.get('profile', {}).get('email')}
                ]
            }
            
            # Create or update indicator in XSOAR
            self.xsoar.execute_command(
                command="createIndicator",
                arguments=user_data
            )

# Usage Example
if __name__ == "__main__":
    from okta_client import OktaClient
    from xsoar_client import XSOARClient
    
    okta = OktaClient(
        base_url=os.getenv("OKTA_BASE_URL"),
        api_token=os.getenv("OKTA_API_TOKEN")
    )
    
    xsoar = XSOARClient(
        base_url=os.getenv("XSOAR_URL"),
        api_key=os.getenv("XSOAR_API_KEY")
    )
    
    integration = OktaXSOARIntegration(okta, xsoar)
    
    # Get recent security events
    events = okta.get_security_events(
        start_time=datetime.now() - timedelta(hours=1)
    )
    
    # Create incidents for high-severity events
    for event in events:
        if event.get('eventType') in ['user.account.lock', 'user.mfa.factor.attempt_fail']:
            integration.trigger_playbook_for_okta_event(event)
```

# 3.2 XSOAR Playbook Integration with Okta

```python
#!/usr/bin/env python3
"""
XSOAR Playbook: Okta User Investigation
Purpose: Automated playbook for investigating Okta user events
"""

class OktaInvestigationPlaybook:
    """XSOAR playbook for Okta investigations"""
    
    def __init__(self, xsoar_client, okta_client):
        self.xsoar = xsoar_client
        self.okta = okta_client
    
    def execute_investigation(self, incident_id: str):
        """Execute full investigation playbook"""
        incident = self.xsoar.get_incident(incident_id)
        
        # Step 1: Extract user information
        user_id = incident.get('customFields', {}).get('okta_user_id')
        if not user_id:
            self.xsoar.add_incident_entry(
                incident_id,
                "Error: Could not extract user ID from incident",
                entry_type="note"
            )
            return
        
        # Step 2: Gather user details
        user_info = self.gather_user_information(user_id)
        self.xsoar.add_incident_entry(
            incident_id,
            f"User Information:\n{json.dumps(user_info, indent=2)}",
            entry_type="note"
        )
        
        # Step 3: Check user groups and permissions
        groups = self.okta.get_user_groups(user_id)
        apps = self.okta.get_user_apps(user_id)
        
        self.xsoar.add_incident_entry(
            incident_id,
            f"User Groups: {len(groups)}\nUser Applications: {len(apps)}",
            entry_type="note"
        )
        
        # Step 4: Get recent activity
        recent_events = self.okta.get_events(
            filter=f'actor.id eq "{user_id}"',
            limit=50
        )
        
        self.xsoar.add_incident_entry(
            incident_id,
            f"Recent Activity: {len(recent_events)} events found",
            entry_type="note"
        )
        
        # Step 5: Risk assessment
        risk_score = self.assess_risk(user_info, groups, apps, recent_events)
        
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
    
    def gather_user_information(self, user_id: str) -> Dict:
        """Gather comprehensive user information"""
        user = self.okta.get_user(user_id)
        groups = self.okta.get_user_groups(user_id)
        apps = self.okta.get_user_apps(user_id)
        factors = self.okta.get_factors(user_id)
        
        return {
            "user": {
                "id": user.get('id'),
                "email": user.get('profile', {}).get('email'),
                "status": user.get('status'),
                "created": user.get('created'),
                "lastLogin": user.get('lastLogin')
            },
            "groups": [g.get('profile', {}).get('name') for g in groups],
            "applications": [a.get('appName') for a in apps],
            "mfa_factors": [f.get('factorType') for f in factors]
        }
    
    def assess_risk(self, user_info: Dict, groups: List, apps: List, events: List) -> int:
        """Assess risk score (0-10)"""
        risk = 0
        
        # Check for privileged groups
        privileged_groups = ['Administrators', 'Security', 'IT']
        if any(g in privileged_groups for g in user_info.get('groups', [])):
            risk += 3
        
        # Check for many applications
        if len(apps) > 10:
            risk += 2
        
        # Check for recent failed logins
        failed_logins = [e for e in events if 'fail' in e.get('outcome', {}).get('result', '').lower()]
        if len(failed_logins) > 5:
            risk += 3
        
        # Check for account status
        if user_info.get('user', {}).get('status') != 'ACTIVE':
            risk += 2
        
        return min(risk, 10)
    
    def generate_recommendations(self, risk_score: int, incident: Dict) -> str:
        """Generate recommendations based on risk score"""
        recommendations = []
        
        if risk_score >= 8:
            recommendations.append("1. IMMEDIATE: Suspend user account")
            recommendations.append("2. Review all recent user activity")
            recommendations.append("3. Check for data exfiltration")
            recommendations.append("4. Notify security team")
        elif risk_score >= 5:
            recommendations.append("1. Require password reset")
            recommendations.append("2. Review user group memberships")
            recommendations.append("3. Enable additional MFA")
        else:
            recommendations.append("1. Monitor user activity")
            recommendations.append("2. Review access patterns")
        
        return "\n".join(recommendations)
```

---

# Okta to Prisma Cloud Integration

# 4.1 Okta User Access to Prisma Cloud CIEM

```python
#!/usr/bin/env python3
"""
Okta to Prisma Cloud CIEM Integration
Purpose: Sync Okta user access data to Prisma Cloud for identity governance
"""

from datetime import datetime
from typing import Dict, List, Optional
import os

class OktaPrismaCloudIntegration:
    """Integrate Okta with Prisma Cloud CIEM"""
    
    def __init__(self, okta_client, prisma_client):
        self.okta = okta_client
        self.prisma = prisma_client
    
    def sync_okta_users_to_prisma(self):
        """Sync Okta users and their access to Prisma Cloud"""
        # Get all active users
        users = self.okta.search_users("status eq \"ACTIVE\"")
        
        for user in users:
            user_data = self.build_user_access_data(user)
            self.send_to_prisma_ciem(user_data)
    
    def build_user_access_data(self, user: Dict) -> Dict:
        """Build user access data structure for Prisma Cloud"""
        user_id = user.get('id')
        email = user.get('profile', {}).get('email')
        
        # Get user groups
        groups = self.okta.get_user_groups(user_id)
        group_names = [g.get('profile', {}).get('name') for g in groups]
        
        # Get user applications
        apps = self.okta.get_user_apps(user_id)
        app_names = [a.get('appName') for a in apps]
        
        # Get MFA factors
        factors = self.okta.get_factors(user_id)
        mfa_enabled = len(factors) > 0
        
        return {
            "identity_id": f"okta:{user_id}",
            "identity_type": "user",
            "identity_name": email,
            "source": "Okta",
            "status": user.get('status'),
            "groups": group_names,
            "applications": app_names,
            "mfa_enabled": mfa_enabled,
            "last_login": user.get('lastLogin'),
            "created_at": user.get('created'),
            "metadata": {
                "okta_user_id": user_id,
                "first_name": user.get('profile', {}).get('firstName'),
                "last_name": user.get('profile', {}).get('lastName'),
                "department": user.get('profile', {}).get('department'),
                "title": user.get('profile', {}).get('title')
            }
        }
    
    def send_to_prisma_ciem(self, user_data: Dict):
        """Send user access data to Prisma Cloud CIEM"""
        # Prisma Cloud CIEM API endpoint for identity data
        url = f"{self.prisma.api_url}/v2/identity"
        
        payload = {
            "identity": user_data,
            "timestamp": datetime.now().isoformat()
        }
        
        response = requests.post(
            url,
            json=payload,
            headers=self.prisma._get_headers()
        )
        
        if response.status_code == 200:
            print(f"Synced user: {user_data.get('identity_name')}")
        else:
            print(f"Error syncing user: {response.status_code} - {response.text}")
    
    def sync_okta_events_to_prisma(self, hours: int = 24):
        """Sync Okta security events to Prisma Cloud"""
        start_time = datetime.now() - timedelta(hours=hours)
        events = self.okta.get_security_events(start_time=start_time)
        
        for event in events:
            event_data = self.build_event_data(event)
            self.send_event_to_prisma(event_data)
    
    def build_event_data(self, event: Dict) -> Dict:
        """Build event data structure for Prisma Cloud"""
        return {
            "event_id": event.get('uuid'),
            "event_type": event.get('eventType'),
            "timestamp": event.get('published'),
            "source": "Okta",
            "user_id": event.get('actor', {}).get('alternateId'),
            "ip_address": event.get('client', {}).get('ipAddress'),
            "outcome": event.get('outcome', {}).get('result'),
            "severity": self.map_event_severity(event.get('eventType')),
            "raw_event": event
        }
    
    def map_event_severity(self, event_type: str) -> str:
        """Map Okta event type to severity"""
        severity_map = {
            'user.account.lock': 'high',
            'user.lifecycle.delete': 'high',
            'user.mfa.factor.attempt_fail': 'medium',
            'user.session.start': 'low',
            'user.authentication.sso': 'low'
        }
        return severity_map.get(event_type, 'low')
    
    def send_event_to_prisma(self, event_data: Dict):
        """Send event to Prisma Cloud"""
        url = f"{self.prisma.api_url}/v2/event"
        
        response = requests.post(
            url,
            json=event_data,
            headers=self.prisma._get_headers()
        )
        
        return response.status_code == 200
    
    def correlate_okta_access_with_cloud_resources(self, user_id: str):
        """Correlate Okta user access with cloud resources in Prisma"""
        # Get user from Okta
        user = self.okta.get_user(user_id)
        groups = self.okta.get_user_groups(user_id)
        apps = self.okta.get_user_apps(user_id)
        
        # Query Prisma Cloud for resources accessed by this user
        # This would require mapping Okta groups/apps to cloud IAM roles
        
        correlation_data = {
            "okta_user": {
                "id": user_id,
                "email": user.get('profile', {}).get('email'),
                "groups": [g.get('profile', {}).get('name') for g in groups],
                "applications": [a.get('appName') for a in apps]
            },
            "cloud_resources": self.find_cloud_resources_for_user(user_id, groups)
        }
        
        return correlation_data
    
    def find_cloud_resources_for_user(self, user_id: str, groups: List[Dict]) -> List[Dict]:
        """Find cloud resources accessible by user based on Okta groups"""
        # This is a simplified example
        # In practice, you'd need to map Okta groups to cloud IAM roles
        
        cloud_resources = []
        
        # Example: Map Okta group to AWS role
        group_to_role_mapping = {
            'AWS-Admins': 'arn:aws:iam::123456789012:role/AdminRole',
            'AWS-Developers': 'arn:aws:iam::123456789012:role/DeveloperRole'
        }
        
        for group in groups:
            group_name = group.get('profile', {}).get('name')
            if group_name in group_to_role_mapping:
                # Query Prisma Cloud for resources with this role
                resources = self.prisma.get_resources_by_iam_role(
                    group_to_role_mapping[group_name]
                )
                cloud_resources.extend(resources)
        
        return cloud_resources

# Usage Example
if __name__ == "__main__":
    from okta_client import OktaClient
    from prisma_cloud_client import PrismaCloudClient
    
    okta = OktaClient(
        base_url=os.getenv("OKTA_BASE_URL"),
        api_token=os.getenv("OKTA_API_TOKEN")
    )
    
    prisma = PrismaCloudClient(
        api_url=os.getenv("PRISMA_API_URL"),
        access_key=os.getenv("PRISMA_ACCESS_KEY"),
        secret_key=os.getenv("PRISMA_SECRET_KEY")
    )
    
    integration = OktaPrismaCloudIntegration(okta, prisma)
    
    # Sync users to Prisma Cloud
    integration.sync_okta_users_to_prisma()
    
    # Sync recent events
    integration.sync_okta_events_to_prisma(hours=24)
```

# 4.2 Prisma Cloud Alerts from Okta Events

```python
#!/usr/bin/env python3
"""
Prisma Cloud Alert Creation from Okta Events
Purpose: Create Prisma Cloud alerts based on Okta security events
"""

class OktaPrismaAlertIntegration:
    """Create Prisma Cloud alerts from Okta events"""
    
    def __init__(self, okta_client, prisma_client):
        self.okta = okta_client
        self.prisma = prisma_client
    
    def create_prisma_alert_from_okta_event(self, event: Dict) -> Dict:
        """Create Prisma Cloud alert from Okta event"""
        event_type = event.get('eventType')
        user_id = event.get('actor', {}).get('alternateId')
        
        # Determine if this should create an alert
        if not self.should_create_alert(event_type):
            return None
        
        # Build alert payload
        alert = {
            "policy": {
                "name": f"Okta Security Event: {event_type}",
                "policyType": "config",
                "cloudType": "okta",
                "severity": self.map_severity(event_type)
            },
            "resource": {
                "id": f"okta-user:{user_id}",
                "name": user_id,
                "cloudType": "okta",
                "resourceType": "user"
            },
            "alertTime": event.get('published'),
            "description": f"""
            Okta Security Event Detected
            
            Event Type: {event_type}
            User: {user_id}
            IP Address: {event.get('client', {}).get('ipAddress')}
            Outcome: {event.get('outcome', {}).get('result')}
            
            This alert was automatically created from Okta system log event.
            """,
            "customFields": {
                "okta_event_id": event.get('uuid'),
                "okta_event_type": event_type,
                "okta_user_id": user_id
            }
        }
        
        # Create alert in Prisma Cloud
        return self.prisma.create_alert(alert)
    
    def should_create_alert(self, event_type: str) -> bool:
        """Determine if event should create an alert"""
        alert_worthy_events = [
            'user.account.lock',
            'user.lifecycle.delete',
            'user.mfa.factor.attempt_fail',
            'user.lifecycle.suspend'
        ]
        return event_type in alert_worthy_events
    
    def map_severity(self, event_type: str) -> str:
        """Map event type to Prisma Cloud severity"""
        severity_map = {
            'user.account.lock': 'high',
            'user.lifecycle.delete': 'high',
            'user.mfa.factor.attempt_fail': 'medium',
            'user.lifecycle.suspend': 'medium'
        }
        return severity_map.get(event_type, 'low')
```

---

# Webhook Integrations

# 5.1 Okta Event Hooks to XDR/XSOAR/Prisma

```python
#!/usr/bin/env python3
"""
Okta Event Hooks Integration
Purpose: Receive Okta webhooks and route to security platforms
"""

from flask import Flask, request, jsonify
import requests
import os

app = Flask(__name__)

# Initialize clients (would be done in production setup)
# okta_client = OktaClient(...)
# xdr_client = CortexXDRClient(...)
# xsoar_client = XSOARClient(...)
# prisma_client = PrismaCloudClient(...)

@app.route('/okta/webhook', methods=['POST'])
def okta_webhook():
    """Receive Okta Event Hook"""
    try:
        # Verify webhook signature
        if not verify_okta_webhook(request):
            return jsonify({"error": "Invalid signature"}), 401
        
        data = request.json
        event_type = data.get('eventType')
        
        # Route to appropriate handler
        if event_type in ['user.account.lock', 'user.mfa.factor.attempt_fail']:
            handle_security_event(data)
        elif event_type in ['user.lifecycle.create', 'user.lifecycle.delete']:
            handle_lifecycle_event(data)
        elif event_type in ['user.session.start', 'user.authentication.sso']:
            handle_authentication_event(data)
        
        return jsonify({"status": "success"}), 200
    
    except Exception as e:
        print(f"Webhook error: {e}")
        return jsonify({"error": str(e)}), 500

def verify_okta_webhook(request) -> bool:
    """Verify Okta webhook signature"""
    # Implementation would verify the webhook signature
    # using Okta's webhook verification method
    return True

def handle_security_event(event: dict):
    """Handle security-related events"""
    # Send to XDR
    xdr_integration = OktaXDRIntegration(okta_client, xdr_client)
    xdr_integration.process_okta_event(event)
    
    # Send to XSOAR
    xsoar_integration = OktaXSOARIntegration(okta_client, xsoar_client)
    xsoar_integration.create_xsoar_incident_from_okta_event(event)
    
    # Send to Prisma Cloud
    prisma_integration = OktaPrismaAlertIntegration(okta_client, prisma_client)
    prisma_integration.create_prisma_alert_from_okta_event(event)

def handle_lifecycle_event(event: dict):
    """Handle user lifecycle events"""
    # Create incidents in XSOAR
    xsoar_integration = OktaXSOARIntegration(okta_client, xsoar_client)
    xsoar_integration.create_xsoar_incident_from_okta_event(event)
    
    # Update Prisma Cloud CIEM
    prisma_integration = OktaPrismaCloudIntegration(okta_client, prisma_client)
    user_data = prisma_integration.build_user_access_data(
        okta_client.get_user(event.get('target', [{}])[0].get('id'))
    )
    prisma_integration.send_to_prisma_ciem(user_data)

def handle_authentication_event(event: dict):
    """Handle authentication events"""
    # Check for suspicious patterns
    if is_suspicious_login(event):
        # Create high-priority incident
        xdr_integration = OktaXDRIntegration(okta_client, xdr_client)
        xdr_integration.sync_suspicious_login_to_xdr(
            event.get('actor', {}).get('alternateId'),
            event
        )

def is_suspicious_login(event: dict) -> bool:
    """Determine if login is suspicious"""
    # Check IP address, location, time, etc.
    ip_address = event.get('client', {}).get('ipAddress')
    outcome = event.get('outcome', {}).get('result')
    
    # Example: Failed login or unusual location
    if outcome == 'FAILURE':
        return True
    
    # Add more sophisticated checks
    return False

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')
```

---

# Use Cases and Workflows

# 6.1 Complete Workflow: Suspicious Login Detection

```python
#!/usr/bin/env python3
"""
Complete Workflow: Suspicious Login Detection and Response
Purpose: End-to-end workflow from detection to remediation
"""

class SuspiciousLoginWorkflow:
    """Complete workflow for suspicious login handling"""
    
    def __init__(self, okta_client, xdr_client, xsoar_client, prisma_client):
        self.okta = okta_client
        self.xdr = xdr_client
        self.xsoar = xsoar_client
        self.prisma = prisma_client
    
    def execute_workflow(self, event: Dict):
        """Execute complete suspicious login workflow"""
        
        # Step 1: Detect suspicious login
        if not self.is_suspicious(event):
            return
        
        user_id = event.get('actor', {}).get('alternateId')
        
        # Step 2: Gather intelligence
        intelligence = self.gather_intelligence(user_id, event)
        
        # Step 3: Create incidents in all platforms
        xdr_incident = self.create_xdr_incident(event, intelligence)
        xsoar_incident = self.create_xsoar_incident(event, intelligence)
        prisma_alert = self.create_prisma_alert(event, intelligence)
        
        # Step 4: Automated response
        response_action = self.determine_response(intelligence)
        self.execute_response(user_id, response_action)
        
        # Step 5: Notify stakeholders
        self.notify_stakeholders(event, intelligence, response_action)
        
        return {
            "xdr_incident": xdr_incident,
            "xsoar_incident": xsoar_incident,
            "prisma_alert": prisma_alert,
            "response_action": response_action
        }
    
    def is_suspicious(self, event: Dict) -> bool:
        """Determine if login is suspicious"""
        # Multiple checks
        checks = [
            self.check_ip_reputation(event),
            self.check_time_pattern(event),
            self.check_location_anomaly(event),
            self.check_failed_attempts(event)
        ]
        return any(checks)
    
    def gather_intelligence(self, user_id: str, event: Dict) -> Dict:
        """Gather intelligence about the user and event"""
        user = self.okta.get_user(user_id)
        groups = self.okta.get_user_groups(user_id)
        recent_events = self.okta.get_events(
            filter=f'actor.id eq "{user_id}"',
            limit=20
        )
        
        return {
            "user": user,
            "groups": groups,
            "recent_events": recent_events,
            "risk_score": self.calculate_risk_score(user, groups, recent_events)
        }
    
    def calculate_risk_score(self, user: Dict, groups: List, events: List) -> int:
        """Calculate risk score"""
        score = 0
        
        # Privileged user
        if any('admin' in g.get('profile', {}).get('name', '').lower() for g in groups):
            score += 3
        
        # Recent failed attempts
        failed = sum(1 for e in events if 'fail' in e.get('outcome', {}).get('result', '').lower())
        score += min(failed, 3)
        
        # Unusual time
        hour = datetime.fromisoformat(events[0].get('published')).hour
        if hour < 6 or hour > 22:
            score += 2
        
        return min(score, 10)
    
    def determine_response(self, intelligence: Dict) -> str:
        """Determine response action"""
        risk_score = intelligence.get('risk_score', 0)
        
        if risk_score >= 8:
            return 'suspend'
        elif risk_score >= 5:
            return 'clear_sessions'
        else:
            return 'monitor'
    
    def execute_response(self, user_id: str, action: str):
        """Execute response action"""
        if action == 'suspend':
            self.okta.suspend_user(user_id)
        elif action == 'clear_sessions':
            self.okta.clear_user_sessions(user_id)
        # 'monitor' requires no action
    
    def notify_stakeholders(self, event: Dict, intelligence: Dict, action: str):
        """Notify security team and stakeholders"""
        # Implementation would send notifications via Slack, email, etc.
        pass
```

---

# Configuration and Setup

# 7.1 Environment Variables

```bash
# Okta Configuration
export OKTA_BASE_URL="https://dev-123456.okta.com"
export OKTA_API_TOKEN="your-okta-api-token"

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
# okta_integrations_config.yaml
okta:
  base_url: "${OKTA_BASE_URL}"
  api_token: "${OKTA_API_TOKEN}"
  webhook_secret: "${OKTA_WEBHOOK_SECRET}"
  
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
    sync_events: true

event_routing:
  user.account.lock:
    - cortex_xdr
    - xsoar
    - prisma_cloud
  user.mfa.factor.attempt_fail:
    - cortex_xdr
    - xsoar
  user.session.start:
    - xsoar
  user.lifecycle.delete:
    - cortex_xdr
    - xsoar
    - prisma_cloud

automated_responses:
  enabled: true
  actions:
    suspend_user:
      trigger_severity: "critical"
      require_approval: true
    clear_sessions:
      trigger_severity: "high"
      require_approval: false
    reset_password:
      trigger_severity: "medium"
      require_approval: false
```

# 7.3 Okta Event Hook Configuration

```json
{
  "events": {
    "type": "EVENT_TYPE",
    "items": [
      "user.session.start",
      "user.authentication.sso",
      "user.account.lock",
      "user.mfa.factor.attempt_fail",
      "user.lifecycle.create",
      "user.lifecycle.delete",
      "user.lifecycle.suspend",
      "application.user_membership.add",
      "application.user_membership.remove"
    ]
  },
  "channel": {
    "type": "HTTP",
    "version": "1.0.0",
    "config": {
      "uri": "https://your-server.com/okta/webhook",
      "headers": [
        {
          "key": "Authorization",
          "value": "Bearer your-webhook-token"
        }
      ],
      "authScheme": {
        "type": "HEADER",
        "key": "Authorization"
      }
    }
  }
}
```

---

# Troubleshooting

# Common Issues and Solutions

# 1. Authentication Failures

Problem: Okta API authentication fails

Solutions:
- Verify API token is correct and not expired
- Check token has required scopes: `okta.logs.read`, `okta.users.read`, `okta.groups.read`
- Ensure base URL is correct (format: `https://dev-XXXXXX.okta.com`)

# 2. Rate Limiting

Problem: API rate limits exceeded

Solutions:
- Implement exponential backoff
- Use pagination for large result sets
- Cache frequently accessed data
- Batch requests when possible

# 3. Webhook Delivery Failures

Problem: Webhooks not being received

Solutions:
- Verify webhook URL is publicly accessible
- Check firewall rules allow inbound connections
- Validate webhook signature verification
- Implement retry logic for failed deliveries
- Check Okta Event Hook status in Okta Admin Console

# 4. Event Filtering Issues

Problem: Too many or too few events being processed

Solutions:
- Refine event filters in `get_security_events()` method
- Adjust severity thresholds in configuration
- Use more specific event type filters
- Implement event deduplication logic

# 5. User Lookup Failures

Problem: Cannot find user by ID or email

Solutions:
- Verify user exists and is active
- Check user ID format (Okta user IDs are specific format)
- Use search API for email lookups
- Handle case sensitivity in email searches

---

# Best Practices

1. API Token Security: Store tokens in environment variables or secrets management
2. Error Handling: Implement comprehensive error handling and logging
3. Rate Limiting: Respect Okta API rate limits (typically 600 requests per minute)
4. Event Deduplication: Implement logic to prevent processing duplicate events
5. Monitoring: Monitor integration health and API usage
6. Testing: Test integrations in non-production environments first
7. Documentation: Document custom mappings and configurations
8. Audit Logging: Log all actions taken via integrations

---

# API Reference

# Okta API Endpoints Used

- `GET /api/v1/users/{userId}` - Get user details
- `GET /api/v1/users` - List/search users
- `GET /api/v1/users/{userId}/groups` - Get user groups
- `GET /api/v1/users/{userId}/appLinks` - Get user applications
- `GET /api/v1/logs` - Get system log events
- `POST /api/v1/users/{userId}/lifecycle/suspend` - Suspend user
- `POST /api/v1/users/{userId}/lifecycle/unsuspend` - Unsuspend user
- `DELETE /api/v1/users/{userId}/sessions` - Clear user sessions

# Required Okta API Scopes

- `okta.logs.read` - Read system log events
- `okta.users.read` - Read user information
- `okta.users.manage` - Manage user lifecycle
- `okta.groups.read` - Read group information

---

Version: 1.0  
Last Updated: 2026-01-09  
Maintained By: SOC Team
