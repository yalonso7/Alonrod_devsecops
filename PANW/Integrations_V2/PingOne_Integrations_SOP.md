# PingOne Integrations Standard Operating Procedure (SOP)

# Table of Contents

1. [Overview](#overview)
2. [PingOne API Integration Basics](#pingone-api-integration-basics)
3. [PingOne to Cortex XDR Integration](#pingone-to-cortex-xdr-integration)
4. [PingOne to XSOAR Integration](#pingone-to-xsoar-integration)
5. [PingOne to Prisma Cloud Integration](#pingone-to-prisma-cloud-integration)
6. [Webhook Integrations](#webhook-integrations)
7. [Use Cases and Workflows](#use-cases-and-workflows)
8. [Configuration and Setup](#configuration-and-setup)
9. [Troubleshooting](#troubleshooting)

---

# Overview

This SOP provides comprehensive integration code snippets and configuration examples for connecting PingOne Identity Platform with Palo Alto Networks security products (Cortex XDR, XSOAR, Prisma Cloud). These integrations enable automated identity-based security operations, incident response, and compliance monitoring.

# Integration Use Cases

- Identity Threat Detection: Monitor PingOne events for suspicious authentication patterns
- Automated Incident Response: Create XDR/XSOAR incidents from PingOne security events
- Access Governance: Track user access changes and violations
- Compliance Monitoring: Monitor identity compliance violations
- Automated Remediation: Respond to identity-based threats automatically
- Playbook Automation: Trigger XSOAR playbooks for identity investigations
- CIEM Integration: Sync PingOne identity data to Prisma Cloud for identity governance

---

# PingOne API Integration Basics

# 1. PingOne API Client (Python)

```python
#!/usr/bin/env python3
"""
PingOne API Integration Client
Purpose: Authenticate and interact with PingOne API
"""

import requests
import json
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import os
import base64

class PingOneClient:
    """PingOne API Client"""
    
    def __init__(self, environment_id: str, client_id: str, client_secret: str, region: str = "us"):
        """
        Initialize PingOne client
        
        Args:
            environment_id: PingOne environment ID
            client_id: OAuth client ID
            client_secret: OAuth client secret
            region: PingOne region (us, eu, asia)
        """
        self.environment_id = environment_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.region = region
        self.base_url = f"https://api.pingone.{region}.pingidentity.com"
        self.token = None
        self.token_expiry = None
        self._authenticate()
    
    def _authenticate(self):
        """Authenticate and get access token"""
        url = f"{self.base_url}/{self.environment_id}/as/token"
        
        # Base64 encode client credentials
        credentials = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode()
        ).decode()
        
        headers = {
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        data = {
            "grant_type": "client_credentials"
        }
        
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()
        
        token_data = response.json()
        self.token = token_data.get('access_token')
        expires_in = token_data.get('expires_in', 3600)
        self.token_expiry = datetime.now() + timedelta(seconds=expires_in - 60)
    
    def _get_headers(self) -> Dict:
        """Get request headers with auth token"""
        if not self.token or datetime.now() >= self.token_expiry:
            self._authenticate()
        
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
    
    def get_users(self, 
                  filter: Optional[str] = None,
                  limit: int = 100,
                  offset: int = 0) -> Dict:
        """
        Get users
        
        Args:
            filter: Filter expression (e.g., "email eq \"user@example.com\"")
            limit: Maximum number of results
            offset: Offset for pagination
        """
        url = f"{self.base_url}/{self.environment_id}/users"
        
        params = {
            "limit": limit,
            "offset": offset
        }
        
        if filter:
            params["filter"] = filter
        
        response = requests.get(url, params=params, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def get_user(self, user_id: str) -> Dict:
        """Get user details by ID"""
        url = f"{self.base_url}/{self.environment_id}/users/{user_id}"
        response = requests.get(url, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def get_user_groups(self, user_id: str) -> List[Dict]:
        """Get groups for a user"""
        url = f"{self.base_url}/{self.environment_id}/users/{user_id}/memberOfGroups"
        response = requests.get(url, headers=self._get_headers())
        response.raise_for_status()
        return response.json().get('_embedded', {}).get('groups', [])
    
    def get_user_roles(self, user_id: str) -> List[Dict]:
        """Get roles for a user"""
        url = f"{self.base_url}/{self.environment_id}/users/{user_id}/roleAssignments"
        response = requests.get(url, headers=self._get_headers())
        response.raise_for_status()
        return response.json().get('_embedded', {}).get('roleAssignments', [])
    
    def get_applications(self, limit: int = 100) -> Dict:
        """Get applications"""
        url = f"{self.base_url}/{self.environment_id}/applications"
        params = {"limit": limit}
        response = requests.get(url, params=params, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def get_events(self,
                  start_time: Optional[datetime] = None,
                  end_time: Optional[datetime] = None,
                  filter: Optional[str] = None,
                  limit: int = 1000) -> List[Dict]:
        """
        Get audit events
        
        Args:
            start_time: Start time for event query
            end_time: End time for event query
            filter: Filter expression
            limit: Maximum number of events
        """
        url = f"{self.base_url}/{self.environment_id}/logs"
        
        params = {
            "limit": limit
        }
        
        if start_time:
            params["since"] = start_time.isoformat()
        if end_time:
            params["until"] = end_time.isoformat()
        if filter:
            params["filter"] = filter
        
        response = requests.get(url, params=params, headers=self._get_headers())
        response.raise_for_status()
        return response.json().get('_embedded', {}).get('logs', [])
    
    def get_security_events(self,
                           start_time: Optional[datetime] = None,
                           limit: int = 1000) -> List[Dict]:
        """Get security-related events"""
        security_event_types = [
            "USER_LOGIN",
            "USER_LOGOUT",
            "USER_LOCKED",
            "USER_UNLOCKED",
            "USER_PASSWORD_CHANGED",
            "USER_PASSWORD_RESET",
            "USER_CREATED",
            "USER_DELETED",
            "USER_UPDATED",
            "USER_ACCOUNT_ENABLED",
            "USER_ACCOUNT_DISABLED",
            "MFA_DEVICE_ENROLLED",
            "MFA_DEVICE_UNENROLLED",
            "MFA_VERIFY_FAILED",
            "APPLICATION_ACCESS_GRANTED",
            "APPLICATION_ACCESS_REVOKED"
        ]
        
        all_events = []
        for event_type in security_event_types:
            filter_expr = f"type eq \"{event_type}\""
            events = self.get_events(
                start_time=start_time,
                filter=filter_expr,
                limit=limit
            )
            all_events.extend(events)
        
        return all_events
    
    def lock_user(self, user_id: str) -> Dict:
        """Lock a user account"""
        url = f"{self.base_url}/{self.environment_id}/users/{user_id}/account"
        
        payload = {
            "account": {
                "locked": True
            }
        }
        
        response = requests.put(url, json=payload, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def unlock_user(self, user_id: str) -> Dict:
        """Unlock a user account"""
        url = f"{self.base_url}/{self.environment_id}/users/{user_id}/account"
        
        payload = {
            "account": {
                "locked": False
            }
        }
        
        response = requests.put(url, json=payload, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def disable_user(self, user_id: str) -> Dict:
        """Disable a user account"""
        url = f"{self.base_url}/{self.environment_id}/users/{user_id}/account"
        
        payload = {
            "account": {
                "enabled": False
            }
        }
        
        response = requests.put(url, json=payload, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def enable_user(self, user_id: str) -> Dict:
        """Enable a user account"""
        url = f"{self.base_url}/{self.environment_id}/users/{user_id}/account"
        
        payload = {
            "account": {
                "enabled": True
            }
        }
        
        response = requests.put(url, json=payload, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def reset_user_password(self, user_id: str, send_email: bool = True) -> Dict:
        """Reset user password"""
        url = f"{self.base_url}/{self.environment_id}/users/{user_id}/password"
        
        payload = {
            "sendEmail": send_email
        }
        
        response = requests.post(url, json=payload, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def get_user_sessions(self, user_id: str) -> List[Dict]:
        """Get active sessions for a user"""
        url = f"{self.base_url}/{self.environment_id}/users/{user_id}/sessions"
        response = requests.get(url, headers=self._get_headers())
        response.raise_for_status()
        return response.json().get('_embedded', {}).get('sessions', [])
    
    def terminate_user_sessions(self, user_id: str) -> Dict:
        """Terminate all active sessions for a user"""
        url = f"{self.base_url}/{self.environment_id}/users/{user_id}/sessions"
        response = requests.delete(url, headers=self._get_headers())
        response.raise_for_status()
        return {"status": "success"}
    
    def get_risk_events(self,
                       start_time: Optional[datetime] = None,
                       limit: int = 1000) -> List[Dict]:
        """Get risk assessment events"""
        url = f"{self.base_url}/{self.environment_id}/riskEvents"
        
        params = {"limit": limit}
        if start_time:
            params["since"] = start_time.isoformat()
        
        response = requests.get(url, params=params, headers=self._get_headers())
        response.raise_for_status()
        return response.json().get('_embedded', {}).get('riskEvents', [])

# Usage Example
if __name__ == "__main__":
    client = PingOneClient(
        environment_id=os.getenv("PINGONE_ENVIRONMENT_ID"),
        client_id=os.getenv("PINGONE_CLIENT_ID"),
        client_secret=os.getenv("PINGONE_CLIENT_SECRET"),
        region=os.getenv("PINGONE_REGION", "us")
    )
    
    # Get recent security events
    events = client.get_security_events(
        start_time=datetime.now() - timedelta(hours=24)
    )
    print(f"Found {len(events)} security events")
    
    # Get users
    users = client.get_users(limit=10)
    print(f"Found {users.get('count', 0)} users")
    
    # Get risk events
    risk_events = client.get_risk_events(
        start_time=datetime.now() - timedelta(hours=24)
    )
    print(f"Found {len(risk_events)} risk events")
```

---

# PingOne to Cortex XDR Integration

# 2.1 PingOne Events to XDR Incidents

```python
#!/usr/bin/env python3
"""
PingOne to Cortex XDR Integration
Purpose: Create XDR incidents from PingOne security events
"""

from datetime import datetime, timedelta
from typing import Dict, List
import os
import time

class PingOneXDRIntegration:
    """Integrate PingOne with Cortex XDR"""
    
    def __init__(self, pingone_client, xdr_client):
        self.pingone = pingone_client
        self.xdr = xdr_client
    
    def monitor_pingone_events(self, check_interval_minutes: int = 15):
        """Continuously monitor PingOne events and create XDR incidents"""
        last_check = datetime.now() - timedelta(minutes=check_interval_minutes)
        
        while True:
            try:
                # Get security events since last check
                events = self.pingone.get_security_events(start_time=last_check)
                
                # Process events
                for event in events:
                    self.process_pingone_event(event)
                
                # Get risk events
                risk_events = self.pingone.get_risk_events(start_time=last_check)
                for risk_event in risk_events:
                    self.process_risk_event(risk_event)
                
                last_check = datetime.now()
                time.sleep(check_interval_minutes * 60)
                
            except Exception as e:
                print(f"Error monitoring PingOne events: {e}")
                time.sleep(60)
    
    def process_pingone_event(self, event: Dict):
        """Process a PingOne event and create XDR incident if needed"""
        event_type = event.get('type')
        severity = self.determine_severity(event_type)
        
        # Only create incidents for high-severity events
        if severity in ['high', 'critical']:
            incident_data = self.create_xdr_incident_from_event(event)
            self.xdr.create_incident(incident_data)
    
    def determine_severity(self, event_type: str) -> str:
        """Determine severity based on event type"""
        critical_events = [
            'USER_DELETED',
            'USER_LOCKED',
            'MFA_VERIFY_FAILED'
        ]
        
        high_events = [
            'USER_CREATED',
            'USER_ACCOUNT_DISABLED',
            'APPLICATION_ACCESS_GRANTED',
            'USER_PASSWORD_RESET'
        ]
        
        if event_type in critical_events:
            return 'critical'
        elif event_type in high_events:
            return 'high'
        else:
            return 'medium'
    
    def create_xdr_incident_from_event(self, event: Dict) -> Dict:
        """Create XDR incident payload from PingOne event"""
        event_id = event.get('id')
        event_type = event.get('type')
        user_id = event.get('user', {}).get('id', 'Unknown')
        timestamp = event.get('createdAt', datetime.now().isoformat())
        
        # Get user details if available
        user_name = 'Unknown'
        user_email = 'Unknown'
        if user_id and user_id != 'Unknown':
            try:
                user = self.pingone.get_user(user_id)
                user_name = user.get('name', {}).get('given', '') + ' ' + user.get('name', {}).get('family', '')
                user_email = user.get('email', 'Unknown')
            except:
                pass
        
        # Build incident description
        description = f"""
        PingOne Security Event Detected
        
        Event Type: {event_type}
        Event ID: {event_id}
        User: {user_name} ({user_email})
        User ID: {user_id}
        Timestamp: {timestamp}
        IP Address: {event.get('ip', 'Unknown')}
        User Agent: {event.get('userAgent', 'Unknown')}
        
        Event Details:
        {json.dumps(event, indent=2)}
        """
        
        return {
            "incident_name": f"PingOne: {event_type} - {user_name}",
            "severity": self.determine_severity(event_type),
            "description": description,
            "labels": [
                {"key": "source", "value": "PingOne"},
                {"key": "event_type", "value": event_type},
                {"key": "user_id", "value": user_id}
            ],
            "custom_fields": {
                "pingone_event_id": event_id,
                "pingone_event_type": event_type,
                "pingone_user_id": user_id,
                "pingone_user_name": user_name,
                "pingone_user_email": user_email,
                "pingone_ip_address": event.get('ip'),
                "pingone_timestamp": timestamp
            }
        }
    
    def process_risk_event(self, risk_event: Dict):
        """Process a PingOne risk event and create XDR incident"""
        risk_level = risk_event.get('level', 'UNKNOWN')
        
        # Only create incidents for high/critical risk
        if risk_level in ['HIGH', 'CRITICAL']:
            incident_data = self.create_xdr_incident_from_risk_event(risk_event)
            self.xdr.create_incident(incident_data)
    
    def create_xdr_incident_from_risk_event(self, risk_event: Dict) -> Dict:
        """Create XDR incident from PingOne risk event"""
        risk_event_id = risk_event.get('id')
        user_id = risk_event.get('user', {}).get('id', 'Unknown')
        risk_level = risk_event.get('level', 'UNKNOWN')
        risk_type = risk_event.get('type', 'Unknown')
        
        # Get user details
        user_name = 'Unknown'
        user_email = 'Unknown'
        if user_id and user_id != 'Unknown':
            try:
                user = self.pingone.get_user(user_id)
                user_name = user.get('name', {}).get('given', '') + ' ' + user.get('name', {}).get('family', '')
                user_email = user.get('email', 'Unknown')
            except:
                pass
        
        # Map risk level to severity
        severity_map = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low'
        }
        severity = severity_map.get(risk_level, 'medium')
        
        description = f"""
        PingOne Risk Event Detected
        
        Risk Level: {risk_level}
        Risk Type: {risk_type}
        User: {user_name} ({user_email})
        User ID: {user_id}
        Timestamp: {risk_event.get('createdAt', '')}
        
        Risk Event Details:
        {json.dumps(risk_event, indent=2)}
        """
        
        return {
            "incident_name": f"PingOne Risk: {risk_level} - {user_name}",
            "severity": severity,
            "description": description,
            "labels": [
                {"key": "source", "value": "PingOne"},
                {"key": "event_type", "value": "risk_event"},
                {"key": "risk_level", "value": risk_level},
                {"key": "user_id", "value": user_id}
            ],
            "custom_fields": {
                "pingone_risk_event_id": risk_event_id,
                "pingone_risk_level": risk_level,
                "pingone_risk_type": risk_type,
                "pingone_user_id": user_id,
                "pingone_user_name": user_name,
                "pingone_user_email": user_email
            }
        }
    
    def sync_suspicious_login_to_xdr(self, user_id: str, event: Dict):
        """Create XDR incident for suspicious login"""
        user = self.pingone.get_user(user_id)
        user_groups = self.pingone.get_user_groups(user_id)
        user_roles = self.pingone.get_user_roles(user_id)
        
        # Check for suspicious patterns
        is_suspicious = self.detect_suspicious_pattern(event, user, user_groups, user_roles)
        
        if is_suspicious:
            user_name = user.get('name', {}).get('given', '') + ' ' + user.get('name', {}).get('family', '')
            user_email = user.get('email', '')
            
            incident = {
                "incident_name": f"PingOne: Suspicious Login - {user_name}",
                "severity": "high",
                "description": f"""
                Suspicious login detected for user: {user_name}
                
                User Details:
                - Name: {user_name}
                - Email: {user_email}
                - Groups: {len(user_groups)}
                - Roles: {len(user_roles)}
                
                Login Details:
                - IP Address: {event.get('ip', 'Unknown')}
                - User Agent: {event.get('userAgent', 'Unknown')}
                - Timestamp: {event.get('createdAt', '')}
                - Event Type: {event.get('type')}
                
                Risk Indicators:
                - Unusual location
                - New device
                - Off-hours access
                - Failed MFA attempts
                """,
                "labels": [
                    {"key": "source", "value": "PingOne"},
                    {"key": "event_type", "value": "suspicious_login"},
                    {"key": "threat_type", "value": "identity_compromise"}
                ]
            }
            
            xdr_incident = self.xdr.create_incident(incident)
            
            # Add comment with remediation steps
            self.xdr.add_incident_comment(
                xdr_incident.get('incident_id'),
                "Recommended Actions:\n1. Verify user identity\n2. Review recent activity\n3. Consider locking account if confirmed compromise\n4. Check for unauthorized access"
            )
            
            return xdr_incident
    
    def detect_suspicious_pattern(self, event: Dict, user: Dict, groups: List[Dict], roles: List[Dict]) -> bool:
        """Detect suspicious login patterns"""
        ip_address = event.get('ip', '')
        timestamp = datetime.fromisoformat(event.get('createdAt', datetime.now().isoformat()).replace('Z', '+00:00'))
        event_type = event.get('type', '')
        
        # Check for failed MFA
        if 'MFA_VERIFY_FAILED' in event_type:
            return True
        
        # Check for off-hours access (outside 8 AM - 6 PM)
        hour = timestamp.hour
        if hour < 8 or hour > 18:
            return True
        
        # Check for high-privilege user login from new location
        privileged_roles = ['Administrator', 'Security', 'IT Admin']
        user_role_names = [role.get('role', {}).get('name', '') for role in roles]
        
        if any(role in privileged_roles for role in user_role_names):
            # Additional checks for privileged users
            return True
        
        # Check for multiple failed login attempts
        # This would require querying recent events
        return False

# Usage Example
if __name__ == "__main__":
    from pingone_client import PingOneClient
    from cortex_xdr_client import CortexXDRClient
    
    # Initialize clients
    pingone = PingOneClient(
        environment_id=os.getenv("PINGONE_ENVIRONMENT_ID"),
        client_id=os.getenv("PINGONE_CLIENT_ID"),
        client_secret=os.getenv("PINGONE_CLIENT_SECRET"),
        region=os.getenv("PINGONE_REGION", "us")
    )
    
    xdr = CortexXDRClient(
        api_key=os.getenv("XDR_API_KEY"),
        api_key_id=os.getenv("XDR_API_KEY_ID")
    )
    
    # Create integration
    integration = PingOneXDRIntegration(pingone, xdr)
    
    # Monitor events
    integration.monitor_pingone_events(check_interval_minutes=15)
```

# 2.2 Advanced XDR Integration: Batch Event Processing

```python
#!/usr/bin/env python3
"""
Advanced XDR Integration: Batch Event Processing
Purpose: Efficiently process multiple PingOne events and create XDR incidents in batches
"""

from datetime import datetime, timedelta
from typing import Dict, List
import os
import json

class PingOneXDRBatchProcessor:
    """Batch process PingOne events for XDR"""
    
    def __init__(self, pingone_client, xdr_client):
        self.pingone = pingone_client
        self.xdr = xdr_client
        self.batch_size = 50
    
    def process_events_batch(self, events: List[Dict]) -> List[Dict]:
        """Process events in batches to optimize API calls"""
        incidents_created = []
        
        # Group events by severity
        critical_events = []
        high_events = []
        medium_events = []
        
        for event in events:
            severity = self.determine_severity(event.get('type'))
            if severity == 'critical':
                critical_events.append(event)
            elif severity == 'high':
                high_events.append(event)
            else:
                medium_events.append(event)
        
        # Process critical events first
        for event_batch in self._chunk_list(critical_events, self.batch_size):
            incidents = self._create_incidents_batch(event_batch, 'critical')
            incidents_created.extend(incidents)
        
        # Process high severity events
        for event_batch in self._chunk_list(high_events, self.batch_size):
            incidents = self._create_incidents_batch(event_batch, 'high')
            incidents_created.extend(incidents)
        
        # Process medium severity events (optional, based on threshold)
        if self.should_process_medium_severity():
            for event_batch in self._chunk_list(medium_events, self.batch_size):
                incidents = self._create_incidents_batch(event_batch, 'medium')
                incidents_created.extend(incidents)
        
        return incidents_created
    
    def _chunk_list(self, lst: List, chunk_size: int) -> List[List]:
        """Split list into chunks"""
        for i in range(0, len(lst), chunk_size):
            yield lst[i:i + chunk_size]
    
    def _create_incidents_batch(self, events: List[Dict], severity: str) -> List[Dict]:
        """Create XDR incidents from a batch of events"""
        incidents = []
        integration = PingOneXDRIntegration(self.pingone, self.xdr)
        
        for event in events:
            try:
                incident_data = integration.create_xdr_incident_from_event(event)
                incident = self.xdr.create_incident(incident_data)
                incidents.append(incident)
            except Exception as e:
                print(f"Error creating incident for event {event.get('id')}: {e}")
        
        return incidents
    
    def determine_severity(self, event_type: str) -> str:
        """Determine severity based on event type"""
        critical_events = ['USER_DELETED', 'USER_LOCKED', 'MFA_VERIFY_FAILED']
        high_events = ['USER_CREATED', 'USER_ACCOUNT_DISABLED', 'APPLICATION_ACCESS_GRANTED']
        
        if event_type in critical_events:
            return 'critical'
        elif event_type in high_events:
            return 'high'
        else:
            return 'medium'
    
    def should_process_medium_severity(self) -> bool:
        """Determine if medium severity events should be processed"""
        # Can be configured based on business rules
        return True

# Usage Example
if __name__ == "__main__":
    from pingone_client import PingOneClient
    from cortex_xdr_client import CortexXDRClient
    
    pingone = PingOneClient(
        environment_id=os.getenv("PINGONE_ENVIRONMENT_ID"),
        client_id=os.getenv("PINGONE_CLIENT_ID"),
        client_secret=os.getenv("PINGONE_CLIENT_SECRET"),
        region=os.getenv("PINGONE_REGION", "us")
    )
    
    xdr = CortexXDRClient(
        api_key=os.getenv("XDR_API_KEY"),
        api_key_id=os.getenv("XDR_API_KEY_ID")
    )
    
    processor = PingOneXDRBatchProcessor(pingone, xdr)
    
    # Get events from last hour
    events = pingone.get_security_events(
        start_time=datetime.now() - timedelta(hours=1)
    )
    
    # Process in batches
    incidents = processor.process_events_batch(events)
    print(f"Created {len(incidents)} XDR incidents")
```

# 2.3 XDR Incident Enrichment with PingOne Data

```python
#!/usr/bin/env python3
"""
XDR Incident Enrichment with PingOne Data
Purpose: Enrich XDR incidents with detailed PingOne user and access information
"""

from datetime import datetime, timedelta
from typing import Dict, List
import os
import json

class XDRIncidentEnrichment:
    """Enrich XDR incidents with PingOne data"""
    
    def __init__(self, pingone_client, xdr_client):
        self.pingone = pingone_client
        self.xdr = xdr_client
    
    def enrich_incident(self, incident_id: str):
        """Enrich XDR incident with PingOne user data"""
        incident = self.xdr.get_incident(incident_id)
        user_id = incident.get('custom_fields', {}).get('pingone_user_id')
        
        if not user_id:
            return
        
        # Gather comprehensive user data
        enrichment_data = self.gather_enrichment_data(user_id)
        
        # Add enrichment as comment
        enrichment_comment = self.format_enrichment_comment(enrichment_data)
        self.xdr.add_incident_comment(incident_id, enrichment_comment)
        
        # Update incident labels with additional context
        new_labels = self.generate_enrichment_labels(enrichment_data)
        self.xdr.update_incident(incident_id, {"labels": new_labels})
    
    def gather_enrichment_data(self, user_id: str) -> Dict:
        """Gather comprehensive enrichment data"""
        user = self.pingone.get_user(user_id)
        groups = self.pingone.get_user_groups(user_id)
        roles = self.pingone.get_user_roles(user_id)
        sessions = self.pingone.get_user_sessions(user_id)
        
        # Get recent risk events
        risk_events = self.pingone.get_risk_events(
            start_time=datetime.now() - timedelta(days=7),
            limit=10
        )
        user_risk_events = [r for r in risk_events if r.get('user', {}).get('id') == user_id]
        
        # Get recent security events
        recent_events = self.pingone.get_events(
            filter=f"user.id eq \"{user_id}\"",
            limit=20
        )
        
        return {
            "user": user,
            "groups": groups,
            "roles": roles,
            "active_sessions": sessions,
            "recent_risk_events": user_risk_events,
            "recent_security_events": recent_events,
            "risk_score": self.calculate_user_risk_score(user, groups, roles, user_risk_events)
        }
    
    def calculate_user_risk_score(self, user: Dict, groups: List, roles: List, risk_events: List) -> int:
        """Calculate overall user risk score"""
        score = 0
        
        # Account status
        if user.get('account', {}).get('locked'):
            score += 3
        if not user.get('account', {}).get('enabled'):
            score += 2
        
        # Privileged access
        privileged_roles = ['Administrator', 'Security', 'IT Admin']
        role_names = [r.get('role', {}).get('name', '') for r in roles]
        if any(role in privileged_roles for role in role_names):
            score += 2
        
        # Recent risk events
        high_risk_events = [r for r in risk_events if r.get('level') in ['HIGH', 'CRITICAL']]
        score += len(high_risk_events) * 2
        
        return min(score, 10)
    
    def format_enrichment_comment(self, data: Dict) -> str:
        """Format enrichment data as comment"""
        user = data.get('user', {})
        user_name = f"{user.get('name', {}).get('given', '')} {user.get('name', {}).get('family', '')}"
        
        return f"""
# PingOne User Enrichment Data

# User Information
- Name: {user_name}
- Email: {user.get('email', 'N/A')}
- Status: {'Enabled' if user.get('account', {}).get('enabled') else 'Disabled'}
- Locked: {'Yes' if user.get('account', {}).get('locked') else 'No'}
- Risk Score: {data.get('risk_score', 0)}/10

# Access Information
- Groups: {len(data.get('groups', []))}
- Roles: {len(data.get('roles', []))}
- Active Sessions: {len(data.get('active_sessions', []))}

# Recent Activity
- Risk Events (7 days): {len(data.get('recent_risk_events', []))}
- Security Events (recent): {len(data.get('recent_security_events', []))}

# Groups
{', '.join([g.get('name', '') for g in data.get('groups', [])])}

# Roles
{', '.join([r.get('role', {}).get('name', '') for r in data.get('roles', [])])}
        """
    
    def generate_enrichment_labels(self, data: Dict) -> List[Dict]:
        """Generate additional labels from enrichment data"""
        labels = []
        
        user = data.get('user', {})
        if user.get('account', {}).get('locked'):
            labels.append({"key": "account_status", "value": "locked"})
        
        risk_score = data.get('risk_score', 0)
        if risk_score >= 8:
            labels.append({"key": "risk_level", "value": "critical"})
        elif risk_score >= 5:
            labels.append({"key": "risk_level", "value": "high"})
        
        # Add privileged access label
        roles = data.get('roles', [])
        privileged_roles = ['Administrator', 'Security', 'IT Admin']
        role_names = [r.get('role', {}).get('name', '') for r in roles]
        if any(role in privileged_roles for role in role_names):
            labels.append({"key": "access_level", "value": "privileged"})
        
        return labels

# Usage Example
if __name__ == "__main__":
    from pingone_client import PingOneClient
    from cortex_xdr_client import CortexXDRClient
    
    pingone = PingOneClient(
        environment_id=os.getenv("PINGONE_ENVIRONMENT_ID"),
        client_id=os.getenv("PINGONE_CLIENT_ID"),
        client_secret=os.getenv("PINGONE_CLIENT_SECRET"),
        region=os.getenv("PINGONE_REGION", "us")
    )
    
    xdr = CortexXDRClient(
        api_key=os.getenv("XDR_API_KEY"),
        api_key_id=os.getenv("XDR_API_KEY_ID")
    )
    
    enrichment = XDRIncidentEnrichment(pingone, xdr)
    
    # Enrich a specific incident
    enrichment.enrich_incident("incident_id_here")
```

# 2.4 Automated Response to XDR Incidents

```python
#!/usr/bin/env python3
"""
Automated Response: XDR Incident → PingOne Actions
Purpose: Automatically respond to XDR incidents by taking PingOne actions
"""

class XDRPingOneResponse:
    """Automated response to XDR incidents using PingOne"""
    
    def __init__(self, xdr_client, pingone_client):
        self.xdr = xdr_client
        self.pingone = pingone_client
    
    def handle_xdr_incident(self, incident_id: str):
        """Handle XDR incident and take PingOne actions"""
        incident = self.xdr.get_incident(incident_id)
        
        # Check if incident is related to identity
        if self.is_identity_related(incident):
            user_id = self.extract_user_id(incident)
            
            if user_id:
                # Determine response action
                action = self.determine_response_action(incident)
                
                if action == 'lock':
                    self.pingone.lock_user(user_id)
                    self.xdr.add_incident_comment(
                        incident_id,
                        f"Automated Response: Locked PingOne user {user_id}"
                    )
                elif action == 'disable':
                    self.pingone.disable_user(user_id)
                    self.xdr.add_incident_comment(
                        incident_id,
                        f"Automated Response: Disabled PingOne user {user_id}"
                    )
                elif action == 'terminate_sessions':
                    self.pingone.terminate_user_sessions(user_id)
                    self.xdr.add_incident_comment(
                        incident_id,
                        f"Automated Response: Terminated all sessions for user {user_id}"
                    )
                elif action == 'reset_password':
                    self.pingone.reset_user_password(user_id, send_email=True)
                    self.xdr.add_incident_comment(
                        incident_id,
                        f"Automated Response: Reset password for user {user_id}"
                    )
    
    def is_identity_related(self, incident: Dict) -> bool:
        """Check if incident is identity-related"""
        labels = incident.get('labels', [])
        for label in labels:
            if label.get('key') == 'source' and label.get('value') == 'PingOne':
                return True
            if label.get('key') == 'threat_type') and 'identity' in label.get('value', '').lower():
                return True
        return False
    
    def extract_user_id(self, incident: Dict) -> Optional[str]:
        """Extract user ID from incident"""
        custom_fields = incident.get('custom_fields', {})
        return custom_fields.get('pingone_user_id')
    
    def determine_response_action(self, incident: Dict) -> str:
        """Determine appropriate response action"""
        severity = incident.get('severity', 'medium')
        event_type = incident.get('custom_fields', {}).get('pingone_event_type', '')
        risk_level = incident.get('custom_fields', {}).get('pingone_risk_level', '')
        
        if severity == 'critical' or risk_level == 'CRITICAL':
            return 'lock'
        elif severity == 'high' or risk_level == 'HIGH':
            return 'terminate_sessions'
        elif event_type == 'MFA_VERIFY_FAILED':
            return 'reset_password'
        else:
            return 'monitor'
```

---

# PingOne to XSOAR Integration

# 3.1 PingOne Events to XSOAR Incidents

```python
#!/usr/bin/env python3
"""
PingOne to XSOAR Integration
Purpose: Create XSOAR incidents from PingOne security events and automate playbooks
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
import os

class PingOneXSOARIntegration:
    """Integrate PingOne with Cortex XSOAR"""
    
    def __init__(self, pingone_client, xsoar_client):
        self.pingone = pingone_client
        self.xsoar = xsoar_client
    
    def create_xsoar_incident_from_event(self, event: Dict) -> Dict:
        """Create XSOAR incident from PingOne event"""
        event_id = event.get('id')
        event_type = event.get('type')
        user_id = event.get('user', {}).get('id', 'Unknown')
        
        # Get user details
        user_name = 'Unknown'
        user_email = 'Unknown'
        if user_id and user_id != 'Unknown':
            try:
                user = self.pingone.get_user(user_id)
                user_name = user.get('name', {}).get('given', '') + ' ' + user.get('name', {}).get('family', '')
                user_email = user.get('email', 'Unknown')
            except:
                pass
        
        # Determine incident type and severity
        incident_type, severity = self.map_event_to_incident_type(event_type)
        
        # Create incident
        incident = self.xsoar.create_incident(
            name=f"PingOne: {event_type} - {user_name}",
            severity=severity,
            type=incident_type,
            labels=[
                {"type": "source", "value": "PingOne"},
                {"type": "event_type", "value": event_type},
                {"type": "user_id", "value": user_id},
                {"type": "user_email", "value": user_email}
            ],
            custom_fields={
                "pingone_event_id": event_id,
                "pingone_event_type": event_type,
                "pingone_user_id": user_id,
                "pingone_user_name": user_name,
                "pingone_user_email": user_email,
                "pingone_ip_address": event.get('ip'),
                "pingone_timestamp": event.get('createdAt', '')
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
        """Map PingOne event type to XSOAR incident type and severity"""
        mapping = {
            'USER_LOCKED': ('Identity Access Management', 4),  # Critical
            'USER_DELETED': ('Identity Access Management', 4),
            'MFA_VERIFY_FAILED': ('Authentication', 3),  # High
            'USER_LOGIN': ('Authentication', 2),  # Medium
            'USER_LOGOUT': ('Authentication', 1),  # Low
            'USER_CREATED': ('Identity Access Management', 2),
            'USER_ACCOUNT_DISABLED': ('Identity Access Management', 3),
            'USER_ACCOUNT_ENABLED': ('Identity Access Management', 1),
            'USER_PASSWORD_RESET': ('Authentication', 2),
            'APPLICATION_ACCESS_GRANTED': ('Access', 2),
            'APPLICATION_ACCESS_REVOKED': ('Access', 2)
        }
        
        return mapping.get(event_type, ('Unclassified', 1))
    
    def build_incident_description(self, event: Dict, user_name: str, user_email: str) -> str:
        """Build detailed incident description"""
        return f"""
# PingOne Security Event

# Event Information
- Event Type: {event.get('type')}
- Event ID: {event.get('id')}
- Timestamp: {event.get('createdAt', '')}
- IP Address: {event.get('ip', 'Unknown')}
- User Agent: {event.get('userAgent', 'Unknown')}

# User Information
- User ID: {event.get('user', {}).get('id', 'Unknown')}
- Name: {user_name}
- Email: {user_email}

# Event Details
```json
{json.dumps(event, indent=2)}
```

# Recommended Actions
1. Verify user identity
2. Review recent user activity in PingOne
3. Check for related security events
4. Consider additional authentication requirements
        """
    
    def trigger_playbook_for_event(self, event: Dict):
        """Trigger XSOAR playbook based on event type"""
        event_type = event.get('type')
        
        # Create incident first
        incident = self.create_xsoar_incident_from_event(event)
        
        # Trigger appropriate playbook
        if event_type == 'USER_LOCKED':
            playbook_name = "Investigate User Account Lock"
        elif event_type == 'MFA_VERIFY_FAILED':
            playbook_name = "Investigate Failed MFA"
        elif event_type == 'USER_DELETED':
            playbook_name = "Investigate User Deletion"
        elif event_type == 'USER_LOGIN':
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
    
    def create_xsoar_incident_from_risk_event(self, risk_event: Dict) -> Dict:
        """Create XSOAR incident from PingOne risk event"""
        risk_event_id = risk_event.get('id')
        user_id = risk_event.get('user', {}).get('id', 'Unknown')
        risk_level = risk_event.get('level', 'UNKNOWN')
        risk_type = risk_event.get('type', 'Unknown')
        
        # Get user details
        user_name = 'Unknown'
        user_email = 'Unknown'
        if user_id and user_id != 'Unknown':
            try:
                user = self.pingone.get_user(user_id)
                user_name = user.get('name', {}).get('given', '') + ' ' + user.get('name', {}).get('family', '')
                user_email = user.get('email', 'Unknown')
            except:
                pass
        
        # Map risk level to severity
        severity_map = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1
        }
        severity = severity_map.get(risk_level, 1)
        
        incident = self.xsoar.create_incident(
            name=f"PingOne Risk: {risk_level} - {user_name}",
            severity=severity,
            type="Identity Access Management",
            labels=[
                {"type": "source", "value": "PingOne"},
                {"type": "event_type", "value": "risk_event"},
                {"type": "risk_level", "value": risk_level},
                {"type": "user_id", "value": user_id}
            ],
            custom_fields={
                "pingone_risk_event_id": risk_event_id,
                "pingone_risk_level": risk_level,
                "pingone_risk_type": risk_type,
                "pingone_user_id": user_id,
                "pingone_user_name": user_name,
                "pingone_user_email": user_email
            }
        )
        
        return incident
    
    def sync_pingone_users_to_xsoar(self):
        """Sync PingOne user data to XSOAR for reference"""
        users = self.pingone.get_users(limit=100)
        
        for user in users.get('_embedded', {}).get('users', []):
            user_data = {
                "name": f"PingOne User: {user.get('email', user.get('id'))}",
                "type": "Identity",
                "rawJSON": json.dumps(user),
                "labels": [
                    {"type": "source", "value": "PingOne"},
                    {"type": "user_id", "value": user.get('id')},
                    {"type": "email", "value": user.get('email', '')}
                ]
            }
            
            # Create or update indicator in XSOAR
            self.xsoar.execute_command(
                command="createIndicator",
                arguments=user_data
            )

# Usage Example
if __name__ == "__main__":
    from pingone_client import PingOneClient
    from xsoar_client import XSOARClient
    
    pingone = PingOneClient(
        environment_id=os.getenv("PINGONE_ENVIRONMENT_ID"),
        client_id=os.getenv("PINGONE_CLIENT_ID"),
        client_secret=os.getenv("PINGONE_CLIENT_SECRET"),
        region=os.getenv("PINGONE_REGION", "us")
    )
    
    xsoar = XSOARClient(
        base_url=os.getenv("XSOAR_URL"),
        api_key=os.getenv("XSOAR_API_KEY")
    )
    
    integration = PingOneXSOARIntegration(pingone, xsoar)
    
    # Get recent security events
    events = pingone.get_security_events(
        start_time=datetime.now() - timedelta(hours=1)
    )
    
    # Create incidents for high-severity events
    for event in events:
        event_type = event.get('type')
        if event_type in ['USER_LOCKED', 'MFA_VERIFY_FAILED', 'USER_DELETED']:
            integration.trigger_playbook_for_event(event)
```

# 3.2 XSOAR Playbook Integration with PingOne

```python
#!/usr/bin/env python3
"""
XSOAR Playbook: PingOne User Investigation
Purpose: Automated playbook for investigating PingOne user events
"""

class PingOneInvestigationPlaybook:
    """XSOAR playbook for PingOne investigations"""
    
    def __init__(self, xsoar_client, pingone_client):
        self.xsoar = xsoar_client
        self.pingone = pingone_client
    
    def execute_investigation(self, incident_id: str):
        """Execute full investigation playbook"""
        incident = self.xsoar.get_incident(incident_id)
        
        # Step 1: Extract user information
        user_id = incident.get('customFields', {}).get('pingone_user_id')
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
        
        # Step 3: Check user groups and roles
        groups = self.pingone.get_user_groups(user_id)
        roles = self.pingone.get_user_roles(user_id)
        
        self.xsoar.add_incident_entry(
            incident_id,
            f"User Groups: {len(groups)}\nUser Roles: {len(roles)}",
            entry_type="note"
        )
        
        # Step 4: Get recent activity
        recent_events = self.pingone.get_events(
            filter=f"user.id eq \"{user_id}\"",
            limit=50
        )
        
        self.xsoar.add_incident_entry(
            incident_id,
            f"Recent Activity: {len(recent_events)} events found",
            entry_type="note"
        )
        
        # Step 5: Get active sessions
        sessions = self.pingone.get_user_sessions(user_id)
        self.xsoar.add_incident_entry(
            incident_id,
            f"Active Sessions: {len(sessions)}",
            entry_type="note"
        )
        
        # Step 6: Risk assessment
        risk_score = self.assess_risk(user_info, groups, roles, recent_events, sessions)
        
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
    
    def gather_user_information(self, user_id: str) -> Dict:
        """Gather comprehensive user information"""
        user = self.pingone.get_user(user_id)
        groups = self.pingone.get_user_groups(user_id)
        roles = self.pingone.get_user_roles(user_id)
        sessions = self.pingone.get_user_sessions(user_id)
        
        return {
            "user": {
                "id": user.get('id'),
                "email": user.get('email'),
                "name": f"{user.get('name', {}).get('given', '')} {user.get('name', {}).get('family', '')}",
                "status": user.get('account', {}).get('enabled', False),
                "locked": user.get('account', {}).get('locked', False)
            },
            "groups": [g.get('name') for g in groups],
            "roles": [r.get('role', {}).get('name') for r in roles],
            "active_sessions": len(sessions)
        }
    
    def assess_risk(self, user_info: Dict, groups: List, roles: List, events: List, sessions: List) -> int:
        """Assess risk score (0-10)"""
        risk = 0
        
        # Check for privileged roles
        privileged_roles = ['Administrator', 'Security', 'IT Admin']
        role_names = [role.get('role', {}).get('name', '') for role in roles]
        if any(role in privileged_roles for role in role_names):
            risk += 3
        
        # Check for many groups
        if len(groups) > 10:
            risk += 2
        
        # Check for recent failed logins
        failed_logins = [e for e in events if 'FAILED' in e.get('type', '')]
        if len(failed_logins) > 5:
            risk += 3
        
        # Check for account status
        if user_info.get('user', {}).get('locked'):
            risk += 2
        
        # Check for multiple active sessions
        if len(sessions) > 3:
            risk += 1
        
        return min(risk, 10)
    
    def generate_recommendations(self, risk_score: int, incident: Dict) -> str:
        """Generate recommendations based on risk score"""
        recommendations = []
        
        if risk_score >= 8:
            recommendations.append("1. IMMEDIATE: Lock user account")
            recommendations.append("2. Terminate all active sessions")
            recommendations.append("3. Review all recent user activity")
            recommendations.append("4. Check for data exfiltration")
            recommendations.append("5. Notify security team")
        elif risk_score >= 5:
            recommendations.append("1. Require password reset")
            recommendations.append("2. Review user group memberships")
            recommendations.append("3. Enable additional MFA")
            recommendations.append("4. Monitor user activity")
        else:
            recommendations.append("1. Monitor user activity")
            recommendations.append("2. Review access patterns")
        
        return "\n".join(recommendations)
```

# 3.3 Advanced XSOAR Automation: Custom Commands

```python
#!/usr/bin/env python3
"""
Advanced XSOAR Automation: Custom PingOne Commands
Purpose: Create custom XSOAR commands for PingOne operations
"""

from datetime import datetime, timedelta
from typing import Dict, List
import os
import json

class PingOneXSOARCommands:
    """Custom XSOAR commands for PingOne operations"""
    
    def __init__(self, xsoar_client, pingone_client):
        self.xsoar = xsoar_client
        self.pingone = pingone_client
    
    def execute_pingone_command(self, command: str, args: Dict) -> Dict:
        """Execute custom PingOne command from XSOAR"""
        command_map = {
            'pingone-get-user': self.get_user_command,
            'pingone-lock-user': self.lock_user_command,
            'pingone-unlock-user': self.unlock_user_command,
            'pingone-get-user-sessions': self.get_sessions_command,
            'pingone-terminate-sessions': self.terminate_sessions_command,
            'pingone-reset-password': self.reset_password_command,
            'pingone-get-user-groups': self.get_groups_command,
            'pingone-get-user-roles': self.get_roles_command,
            'pingone-get-user-events': self.get_events_command,
            'pingone-get-risk-events': self.get_risk_events_command
        }
        
        handler = command_map.get(command)
        if not handler:
            return {"error": f"Unknown command: {command}"}
        
        return handler(args)
    
    def get_user_command(self, args: Dict) -> Dict:
        """Get user information command"""
        user_id = args.get('user_id')
        if not user_id:
            return {"error": "user_id is required"}
        
        try:
            user = self.pingone.get_user(user_id)
            groups = self.pingone.get_user_groups(user_id)
            roles = self.pingone.get_user_roles(user_id)
            
            return {
                "success": True,
                "user": user,
                "groups": groups,
                "roles": roles
            }
        except Exception as e:
            return {"error": str(e)}
    
    def lock_user_command(self, args: Dict) -> Dict:
        """Lock user command"""
        user_id = args.get('user_id')
        incident_id = args.get('incident_id')
        
        if not user_id:
            return {"error": "user_id is required"}
        
        try:
            result = self.pingone.lock_user(user_id)
            
            # Add entry to incident if provided
            if incident_id:
                self.xsoar.add_incident_entry(
                    incident_id,
                    f"User {user_id} has been locked in PingOne",
                    entry_type="note"
                )
            
            return {"success": True, "result": result}
        except Exception as e:
            return {"error": str(e)}
    
    def unlock_user_command(self, args: Dict) -> Dict:
        """Unlock user command"""
        user_id = args.get('user_id')
        incident_id = args.get('incident_id')
        
        if not user_id:
            return {"error": "user_id is required"}
        
        try:
            result = self.pingone.unlock_user(user_id)
            
            if incident_id:
                self.xsoar.add_incident_entry(
                    incident_id,
                    f"User {user_id} has been unlocked in PingOne",
                    entry_type="note"
                )
            
            return {"success": True, "result": result}
        except Exception as e:
            return {"error": str(e)}
    
    def get_sessions_command(self, args: Dict) -> Dict:
        """Get user sessions command"""
        user_id = args.get('user_id')
        if not user_id:
            return {"error": "user_id is required"}
        
        try:
            sessions = self.pingone.get_user_sessions(user_id)
            return {"success": True, "sessions": sessions}
        except Exception as e:
            return {"error": str(e)}
    
    def terminate_sessions_command(self, args: Dict) -> Dict:
        """Terminate user sessions command"""
        user_id = args.get('user_id')
        incident_id = args.get('incident_id')
        
        if not user_id:
            return {"error": "user_id is required"}
        
        try:
            result = self.pingone.terminate_user_sessions(user_id)
            
            if incident_id:
                self.xsoar.add_incident_entry(
                    incident_id,
                    f"All sessions for user {user_id} have been terminated",
                    entry_type="note"
                )
            
            return {"success": True, "result": result}
        except Exception as e:
            return {"error": str(e)}
    
    def reset_password_command(self, args: Dict) -> Dict:
        """Reset user password command"""
        user_id = args.get('user_id')
        send_email = args.get('send_email', True)
        incident_id = args.get('incident_id')
        
        if not user_id:
            return {"error": "user_id is required"}
        
        try:
            result = self.pingone.reset_user_password(user_id, send_email=send_email)
            
            if incident_id:
                self.xsoar.add_incident_entry(
                    incident_id,
                    f"Password reset initiated for user {user_id}",
                    entry_type="note"
                )
            
            return {"success": True, "result": result}
        except Exception as e:
            return {"error": str(e)}
    
    def get_groups_command(self, args: Dict) -> Dict:
        """Get user groups command"""
        user_id = args.get('user_id')
        if not user_id:
            return {"error": "user_id is required"}
        
        try:
            groups = self.pingone.get_user_groups(user_id)
            return {"success": True, "groups": groups}
        except Exception as e:
            return {"error": str(e)}
    
    def get_roles_command(self, args: Dict) -> Dict:
        """Get user roles command"""
        user_id = args.get('user_id')
        if not user_id:
            return {"error": "user_id is required"}
        
        try:
            roles = self.pingone.get_user_roles(user_id)
            return {"success": True, "roles": roles}
        except Exception as e:
            return {"error": str(e)}
    
    def get_events_command(self, args: Dict) -> Dict:
        """Get user events command"""
        user_id = args.get('user_id')
        hours = args.get('hours', 24)
        
        if not user_id:
            return {"error": "user_id is required"}
        
        try:
            start_time = datetime.now() - timedelta(hours=hours)
            events = self.pingone.get_events(
                filter=f"user.id eq \"{user_id}\"",
                start_time=start_time,
                limit=args.get('limit', 100)
            )
            return {"success": True, "events": events, "count": len(events)}
        except Exception as e:
            return {"error": str(e)}
    
    def get_risk_events_command(self, args: Dict) -> Dict:
        """Get user risk events command"""
        user_id = args.get('user_id')
        hours = args.get('hours', 24)
        
        if not user_id:
            return {"error": "user_id is required"}
        
        try:
            start_time = datetime.now() - timedelta(hours=hours)
            risk_events = self.pingone.get_risk_events(
                start_time=start_time,
                limit=args.get('limit', 100)
            )
            
            # Filter for specific user
            user_risk_events = [
                r for r in risk_events 
                if r.get('user', {}).get('id') == user_id
            ]
            
            return {
                "success": True,
                "risk_events": user_risk_events,
                "count": len(user_risk_events)
            }
        except Exception as e:
            return {"error": str(e)}

# Usage Example in XSOAR Playbook
"""
# Example XSOAR Playbook Step
- name: Get PingOne User Information
  pingone-get-user:
    user_id: ${incident.pingone_user_id}
  
- name: Lock User if High Risk
  condition: ${incident.severity} >= 3
  pingone-lock-user:
    user_id: ${incident.pingone_user_id}
    incident_id: ${incident.id}
  
- name: Get User Sessions
  pingone-get-user-sessions:
    user_id: ${incident.pingone_user_id}
  
- name: Terminate Sessions
  condition: ${incident.severity} >= 4
  pingone-terminate-sessions:
    user_id: ${incident.pingone_user_id}
    incident_id: ${incident.id}
"""

# 3.4 Real-time XSOAR Incident Correlation

```python
#!/usr/bin/env python3
"""
Real-time XSOAR Incident Correlation with PingOne
Purpose: Correlate XSOAR incidents with PingOne events and risk data
"""

from datetime import datetime, timedelta
from typing import Dict, List
import os
import json

class PingOneXSOARCorrelation:
    """Correlate XSOAR incidents with PingOne data"""
    
    def __init__(self, xsoar_client, pingone_client):
        self.xsoar = xsoar_client
        self.pingone = pingone_client
    
    def correlate_incident(self, incident_id: str) -> Dict:
        """Correlate XSOAR incident with PingOne events"""
        incident = self.xsoar.get_incident(incident_id)
        user_id = incident.get('customFields', {}).get('pingone_user_id')
        
        if not user_id:
            return {"error": "No PingOne user ID found in incident"}
        
        # Get related events
        correlation_data = {
            "incident_id": incident_id,
            "user_id": user_id,
            "related_events": self.find_related_events(user_id, incident),
            "risk_events": self.find_related_risk_events(user_id, incident),
            "user_context": self.get_user_context(user_id),
            "correlation_score": 0
        }
        
        # Calculate correlation score
        correlation_data["correlation_score"] = self.calculate_correlation_score(
            correlation_data
        )
        
        # Add correlation data to incident
        self.add_correlation_to_incident(incident_id, correlation_data)
        
        return correlation_data
    
    def find_related_events(self, user_id: str, incident: Dict) -> List[Dict]:
        """Find PingOne events related to the incident"""
        # Get time window (1 hour before and after incident creation)
        incident_time = datetime.fromisoformat(incident.get('created', datetime.now().isoformat()))
        start_time = incident_time - timedelta(hours=1)
        end_time = incident_time + timedelta(hours=1)
        
        # Get events in time window
        events = self.pingone.get_events(
            filter=f"user.id eq \"{user_id}\"",
            start_time=start_time,
            end_time=end_time,
            limit=100
        )
        
        # Filter for security-relevant events
        security_event_types = [
            'USER_LOGIN', 'USER_LOCKED', 'MFA_VERIFY_FAILED',
            'USER_PASSWORD_RESET', 'APPLICATION_ACCESS_GRANTED'
        ]
        
        related_events = [
            e for e in events 
            if e.get('type') in security_event_types
        ]
        
        return related_events
    
    def find_related_risk_events(self, user_id: str, incident: Dict) -> List[Dict]:
        """Find PingOne risk events related to the incident"""
        incident_time = datetime.fromisoformat(incident.get('created', datetime.now().isoformat()))
        start_time = incident_time - timedelta(hours=2)
        
        risk_events = self.pingone.get_risk_events(
            start_time=start_time,
            limit=50
        )
        
        # Filter for user and high/critical risk
        user_risk_events = [
            r for r in risk_events
            if r.get('user', {}).get('id') == user_id
            and r.get('level') in ['HIGH', 'CRITICAL']
        ]
        
        return user_risk_events
    
    def get_user_context(self, user_id: str) -> Dict:
        """Get comprehensive user context"""
        user = self.pingone.get_user(user_id)
        groups = self.pingone.get_user_groups(user_id)
        roles = self.pingone.get_user_roles(user_id)
        sessions = self.pingone.get_user_sessions(user_id)
        
        return {
            "user": user,
            "groups": groups,
            "roles": roles,
            "active_sessions": len(sessions),
            "account_locked": user.get('account', {}).get('locked', False),
            "account_enabled": user.get('account', {}).get('enabled', False)
        }
    
    def calculate_correlation_score(self, correlation_data: Dict) -> float:
        """Calculate correlation score (0-1)"""
        score = 0.0
        
        # Related events increase score
        related_events = correlation_data.get('related_events', [])
        score += min(len(related_events) * 0.1, 0.4)
        
        # Risk events increase score
        risk_events = correlation_data.get('risk_events', [])
        score += min(len(risk_events) * 0.2, 0.4)
        
        # User context factors
        user_context = correlation_data.get('user_context', {})
        if user_context.get('account_locked'):
            score += 0.1
        if not user_context.get('account_enabled'):
            score += 0.1
        
        return min(score, 1.0)
    
    def add_correlation_to_incident(self, incident_id: str, correlation_data: Dict):
        """Add correlation data to XSOAR incident"""
        correlation_summary = f"""
# PingOne Correlation Analysis

# Correlation Score: {correlation_data.get('correlation_score', 0):.2f}

# Related Events: {len(correlation_data.get('related_events', []))}
{self.format_events_summary(correlation_data.get('related_events', []))}

# Risk Events: {len(correlation_data.get('risk_events', []))}
{self.format_risk_events_summary(correlation_data.get('risk_events', []))}

# User Context
- Groups: {len(correlation_data.get('user_context', {}).get('groups', []))}
- Roles: {len(correlation_data.get('user_context', {}).get('roles', []))}
- Active Sessions: {correlation_data.get('user_context', {}).get('active_sessions', 0)}
- Account Locked: {correlation_data.get('user_context', {}).get('account_locked', False)}
        """
        
        self.xsoar.add_incident_entry(
            incident_id,
            correlation_summary,
            entry_type="note"
        )
    
    def format_events_summary(self, events: List[Dict]) -> str:
        """Format events summary"""
        if not events:
            return "No related events found"
        
        summary = []
        for event in events[:10]:  # Limit to 10 events
            summary.append(
                f"- {event.get('type')} at {event.get('createdAt', '')}"
            )
        
        return "\n".join(summary)
    
    def format_risk_events_summary(self, risk_events: List[Dict]) -> str:
        """Format risk events summary"""
        if not risk_events:
            return "No risk events found"
        
        summary = []
        for risk_event in risk_events[:10]:  # Limit to 10 events
            summary.append(
                f"- {risk_event.get('level')} risk: {risk_event.get('type')} at {risk_event.get('createdAt', '')}"
            )
        
        return "\n".join(summary)

# Usage Example
if __name__ == "__main__":
    from pingone_client import PingOneClient
    from xsoar_client import XSOARClient
    
    pingone = PingOneClient(
        environment_id=os.getenv("PINGONE_ENVIRONMENT_ID"),
        client_id=os.getenv("PINGONE_CLIENT_ID"),
        client_secret=os.getenv("PINGONE_CLIENT_SECRET"),
        region=os.getenv("PINGONE_REGION", "us")
    )
    
    xsoar = XSOARClient(
        base_url=os.getenv("XSOAR_URL"),
        api_key=os.getenv("XSOAR_API_KEY")
    )
    
    correlation = PingOneXSOARCorrelation(xsoar, pingone)
    
    # Correlate an incident
    result = correlation.correlate_incident("incident_id_here")
    print(f"Correlation Score: {result.get('correlation_score', 0)}")
```

---

# PingOne to Prisma Cloud Integration

# 4.1 PingOne User Access to Prisma Cloud CIEM

```python
#!/usr/bin/env python3
"""
PingOne to Prisma Cloud CIEM Integration
Purpose: Sync PingOne user access data to Prisma Cloud for identity governance
"""

from datetime import datetime
from typing import Dict, List, Optional
import os

class PingOnePrismaCloudIntegration:
    """Integrate PingOne with Prisma Cloud CIEM"""
    
    def __init__(self, pingone_client, prisma_client):
        self.pingone = pingone_client
        self.prisma = prisma_client
    
    def sync_pingone_users_to_prisma(self):
        """Sync PingOne users and their access to Prisma Cloud"""
        # Get all users
        users = self.pingone.get_users(limit=1000)
        
        for user in users.get('_embedded', {}).get('users', []):
            user_data = self.build_user_access_data(user)
            self.send_to_prisma_ciem(user_data)
    
    def build_user_access_data(self, user: Dict) -> Dict:
        """Build user access data structure for Prisma Cloud"""
        user_id = user.get('id')
        user_email = user.get('email', '')
        user_name = f"{user.get('name', {}).get('given', '')} {user.get('name', {}).get('family', '')}"
        
        # Get user groups
        groups = self.pingone.get_user_groups(user_id)
        group_names = [g.get('name') for g in groups]
        
        # Get user roles
        roles = self.pingone.get_user_roles(user_id)
        role_names = [r.get('role', {}).get('name') for r in roles]
        
        # Get user applications (if available via API)
        # Note: This may require additional API calls depending on PingOne version
        
        # Get account status
        account_enabled = user.get('account', {}).get('enabled', False)
        account_locked = user.get('account', {}).get('locked', False)
        
        return {
            "identity_id": f"pingone:{user_id}",
            "identity_type": "user",
            "identity_name": user_name or user_email,
            "source": "PingOne",
            "status": "ACTIVE" if account_enabled and not account_locked else "INACTIVE",
            "groups": group_names,
            "roles": role_names,
            "account_enabled": account_enabled,
            "account_locked": account_locked,
            "created_at": user.get('createdAt'),
            "metadata": {
                "pingone_user_id": user_id,
                "email": user_email,
                "first_name": user.get('name', {}).get('given', ''),
                "last_name": user.get('name', {}).get('family', ''),
                "username": user.get('username', '')
            }
        }
    
    def send_to_prisma_ciem(self, user_data: Dict):
        """Send user access data to Prisma Cloud CIEM"""
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
    
    def sync_pingone_events_to_prisma(self, hours: int = 24):
        """Sync PingOne security events to Prisma Cloud"""
        start_time = datetime.now() - timedelta(hours=hours)
        events = self.pingone.get_security_events(start_time=start_time)
        
        for event in events:
            event_data = self.build_event_data(event)
            self.send_event_to_prisma(event_data)
    
    def build_event_data(self, event: Dict) -> Dict:
        """Build event data structure for Prisma Cloud"""
        return {
            "event_id": event.get('id'),
            "event_type": event.get('type'),
            "timestamp": event.get('createdAt'),
            "source": "PingOne",
            "user_id": event.get('user', {}).get('id'),
            "ip_address": event.get('ip'),
            "severity": self.map_event_severity(event.get('type')),
            "raw_event": event
        }
    
    def map_event_severity(self, event_type: str) -> str:
        """Map PingOne event type to severity"""
        severity_map = {
            'USER_LOCKED': 'high',
            'USER_DELETED': 'high',
            'MFA_VERIFY_FAILED': 'medium',
            'USER_ACCOUNT_DISABLED': 'medium',
            'USER_LOGIN': 'low',
            'USER_LOGOUT': 'low'
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
    
    def sync_risk_events_to_prisma(self, hours: int = 24):
        """Sync PingOne risk events to Prisma Cloud"""
        start_time = datetime.now() - timedelta(hours=hours)
        risk_events = self.pingone.get_risk_events(start_time=start_time)
        
        for risk_event in risk_events:
            risk_data = self.build_risk_event_data(risk_event)
            self.send_risk_event_to_prisma(risk_data)
    
    def build_risk_event_data(self, risk_event: Dict) -> Dict:
        """Build risk event data structure for Prisma Cloud"""
        return {
            "risk_event_id": risk_event.get('id'),
            "risk_level": risk_event.get('level'),
            "risk_type": risk_event.get('type'),
            "timestamp": risk_event.get('createdAt'),
            "source": "PingOne",
            "user_id": risk_event.get('user', {}).get('id'),
            "severity": self.map_risk_level_to_severity(risk_event.get('level')),
            "raw_risk_event": risk_event
        }
    
    def map_risk_level_to_severity(self, risk_level: str) -> str:
        """Map PingOne risk level to severity"""
        severity_map = {
            'CRITICAL': 'high',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low'
        }
        return severity_map.get(risk_level, 'low')
    
    def send_risk_event_to_prisma(self, risk_data: Dict):
        """Send risk event to Prisma Cloud"""
        url = f"{self.prisma.api_url}/v2/event"
        
        response = requests.post(
            url,
            json=risk_data,
            headers=self.prisma._get_headers()
        )
        
        return response.status_code == 200
    
    def correlate_pingone_access_with_cloud_resources(self, user_id: str):
        """Correlate PingOne user access with cloud resources in Prisma"""
        # Get user from PingOne
        user = self.pingone.get_user(user_id)
        groups = self.pingone.get_user_groups(user_id)
        roles = self.pingone.get_user_roles(user_id)
        
        # Query Prisma Cloud for resources accessed by this user
        # This would require mapping PingOne groups/roles to cloud IAM roles
        
        correlation_data = {
            "pingone_user": {
                "id": user_id,
                "email": user.get('email'),
                "name": f"{user.get('name', {}).get('given', '')} {user.get('name', {}).get('family', '')}",
                "groups": [g.get('name') for g in groups],
                "roles": [r.get('role', {}).get('name') for r in roles]
            },
            "cloud_resources": self.find_cloud_resources_for_user(user_id, groups, roles)
        }
        
        return correlation_data
    
    def find_cloud_resources_for_user(self, user_id: str, groups: List[Dict], roles: List[Dict]) -> List[Dict]:
        """Find cloud resources accessible by user based on PingOne groups/roles"""
        cloud_resources = []
        
        # Map PingOne roles to cloud IAM roles
        # This is a simplified example
        role_to_cloud_role_mapping = {
            'AWS-Administrator': 'arn:aws:iam::123456789012:role/AdminRole',
            'AWS-Developer': 'arn:aws:iam::123456789012:role/DeveloperRole',
            'Azure-Admin': '/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Authorization/roleDefinitions/xxx'
        }
        
        for role in roles:
            role_name = role.get('role', {}).get('name')
            if role_name in role_to_cloud_role_mapping:
                # Query Prisma Cloud for resources with this role
                resources = self.prisma.get_resources_by_iam_role(
                    role_to_cloud_role_mapping[role_name]
                )
                cloud_resources.extend(resources)
        
        return cloud_resources

# Usage Example
if __name__ == "__main__":
    from pingone_client import PingOneClient
    from prisma_cloud_client import PrismaCloudClient
    
    pingone = PingOneClient(
        environment_id=os.getenv("PINGONE_ENVIRONMENT_ID"),
        client_id=os.getenv("PINGONE_CLIENT_ID"),
        client_secret=os.getenv("PINGONE_CLIENT_SECRET"),
        region=os.getenv("PINGONE_REGION", "us")
    )
    
    prisma = PrismaCloudClient(
        api_url=os.getenv("PRISMA_API_URL"),
        access_key=os.getenv("PRISMA_ACCESS_KEY"),
        secret_key=os.getenv("PRISMA_SECRET_KEY")
    )
    
    integration = PingOnePrismaCloudIntegration(pingone, prisma)
    
    # Sync users to Prisma Cloud
    integration.sync_pingone_users_to_prisma()
    
    # Sync recent events
    integration.sync_pingone_events_to_prisma(hours=24)
    
    # Sync risk events
    integration.sync_risk_events_to_prisma(hours=24)
```

# 4.2 Prisma Cloud Alerts from PingOne Events

```python
#!/usr/bin/env python3
"""
Prisma Cloud Alert Creation from PingOne Events
Purpose: Create Prisma Cloud alerts based on PingOne security events
"""

class PingOnePrismaAlertIntegration:
    """Create Prisma Cloud alerts from PingOne events"""
    
    def __init__(self, pingone_client, prisma_client):
        self.pingone = pingone_client
        self.prisma = prisma_client
    
    def create_prisma_alert_from_event(self, event: Dict) -> Dict:
        """Create Prisma Cloud alert from PingOne event"""
        event_type = event.get('type')
        user_id = event.get('user', {}).get('id')
        
        # Determine if this should create an alert
        if not self.should_create_alert(event_type):
            return None
        
        # Get user details
        try:
            user = self.pingone.get_user(user_id)
            user_name = f"{user.get('name', {}).get('given', '')} {user.get('name', {}).get('family', '')}"
            user_email = user.get('email', '')
        except:
            user_name = user_id
            user_email = ''
        
        # Build alert payload
        alert = {
            "policy": {
                "name": f"PingOne Security Event: {event_type}",
                "policyType": "config",
                "cloudType": "pingone",
                "severity": self.map_severity(event_type)
            },
            "resource": {
                "id": f"pingone-user:{user_id}",
                "name": user_name or user_email,
                "cloudType": "pingone",
                "resourceType": "user"
            },
            "alertTime": event.get('createdAt'),
            "description": f"""
            PingOne Security Event Detected
            
            Event Type: {event_type}
            User: {user_name} ({user_email})
            IP Address: {event.get('ip', 'Unknown')}
            Timestamp: {event.get('createdAt', '')}
            
            This alert was automatically created from PingOne audit log event.
            """,
            "customFields": {
                "pingone_event_id": event.get('id'),
                "pingone_event_type": event_type,
                "pingone_user_id": user_id,
                "pingone_user_email": user_email
            }
        }
        
        # Create alert in Prisma Cloud
        return self.prisma.create_alert(alert)
    
    def create_prisma_alert_from_risk_event(self, risk_event: Dict) -> Dict:
        """Create Prisma Cloud alert from PingOne risk event"""
        risk_level = risk_event.get('level', 'UNKNOWN')
        risk_type = risk_event.get('type', 'Unknown')
        user_id = risk_event.get('user', {}).get('id')
        
        # Only create alerts for HIGH/CRITICAL risk
        if risk_level not in ['HIGH', 'CRITICAL']:
            return None
        
        # Get user details
        try:
            user = self.pingone.get_user(user_id)
            user_name = f"{user.get('name', {}).get('given', '')} {user.get('name', {}).get('family', '')}"
            user_email = user.get('email', '')
        except:
            user_name = user_id
            user_email = ''
        
        alert = {
            "policy": {
                "name": f"PingOne Risk Event: {risk_level}",
                "policyType": "config",
                "cloudType": "pingone",
                "severity": self.map_risk_severity(risk_level)
            },
            "resource": {
                "id": f"pingone-user:{user_id}",
                "name": user_name or user_email,
                "cloudType": "pingone",
                "resourceType": "user"
            },
            "alertTime": risk_event.get('createdAt'),
            "description": f"""
            PingOne Risk Event Detected
            
            Risk Level: {risk_level}
            Risk Type: {risk_type}
            User: {user_name} ({user_email})
            Timestamp: {risk_event.get('createdAt', '')}
            
            This alert was automatically created from PingOne risk assessment.
            """,
            "customFields": {
                "pingone_risk_event_id": risk_event.get('id'),
                "pingone_risk_level": risk_level,
                "pingone_risk_type": risk_type,
                "pingone_user_id": user_id
            }
        }
        
        return self.prisma.create_alert(alert)
    
    def should_create_alert(self, event_type: str) -> bool:
        """Determine if event should create an alert"""
        alert_worthy_events = [
            'USER_LOCKED',
            'USER_DELETED',
            'USER_ACCOUNT_DISABLED',
            'MFA_VERIFY_FAILED',
            'USER_PASSWORD_RESET'
        ]
        return event_type in alert_worthy_events
    
    def map_severity(self, event_type: str) -> str:
        """Map event type to Prisma Cloud severity"""
        severity_map = {
            'USER_LOCKED': 'high',
            'USER_DELETED': 'high',
            'USER_ACCOUNT_DISABLED': 'medium',
            'MFA_VERIFY_FAILED': 'medium',
            'USER_PASSWORD_RESET': 'low'
        }
        return severity_map.get(event_type, 'low')
    
    def map_risk_severity(self, risk_level: str) -> str:
        """Map risk level to Prisma Cloud severity"""
        severity_map = {
            'CRITICAL': 'high',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low'
        }
        return severity_map.get(risk_level, 'low')
```

---

# Webhook Integrations

# 5.1 PingOne Webhooks to XDR, XSOAR, and Prisma Cloud

```python
#!/usr/bin/env python3
"""
PingOne Webhook Integration
Purpose: Receive PingOne webhooks and route to Cortex XDR
"""

from flask import Flask, request, jsonify
import requests
import os

app = Flask(__name__)

# Initialize clients (would be done in production setup)
# pingone_client = PingOneClient(...)
# xdr_client = CortexXDRClient(...)

@app.route('/pingone/webhook', methods=['POST'])
def pingone_webhook():
    """Receive PingOne Webhook"""
    try:
        # Verify webhook signature
        if not verify_pingone_webhook(request):
            return jsonify({"error": "Invalid signature"}), 401
        
        data = request.json
        event_type = data.get('type')
        
        # Route to appropriate handler
        if event_type in ['USER_LOGIN', 'USER_LOGOUT']:
            handle_authentication_event(data)
        elif event_type in ['USER_LOCKED', 'USER_DELETED', 'USER_ACCOUNT_DISABLED']:
            handle_security_event(data)
        elif event_type in ['MFA_VERIFY_FAILED', 'USER_PASSWORD_RESET']:
            handle_security_event(data)
        elif 'RISK' in event_type:
            handle_risk_event(data)
        
        return jsonify({"status": "success"}), 200
    
    except Exception as e:
        print(f"Webhook error: {e}")
        return jsonify({"error": str(e)}), 500

def handle_authentication_event(event: dict):
    """Handle authentication events"""
    # Send to XDR
    xdr_integration = PingOneXDRIntegration(pingone_client, xdr_client)
    
    # Check for suspicious patterns
    if is_suspicious_login(event):
        user_id = event.get('user', {}).get('id')
        xdr_integration.sync_suspicious_login_to_xdr(user_id, event)
    else:
        # Process normal authentication event
        xdr_integration.process_pingone_event(event)
    
    # Send to XSOAR
    xsoar_integration = PingOneXSOARIntegration(pingone_client, xsoar_client)
    xsoar_integration.create_xsoar_incident_from_event(event)

def handle_security_event(event: dict):
    """Handle security-related events"""
    # Send to XDR
    xdr_integration = PingOneXDRIntegration(pingone_client, xdr_client)
    xdr_integration.process_pingone_event(event)
    
    # Send to XSOAR
    xsoar_integration = PingOneXSOARIntegration(pingone_client, xsoar_client)
    xsoar_integration.create_xsoar_incident_from_event(event)
    
    # Trigger playbook for critical events
    event_type = event.get('type')
    if event_type in ['USER_LOCKED', 'USER_DELETED', 'MFA_VERIFY_FAILED']:
        xsoar_integration.trigger_playbook_for_event(event)
    
    # Send to Prisma Cloud
    prisma_integration = PingOnePrismaAlertIntegration(pingone_client, prisma_client)
    prisma_integration.create_prisma_alert_from_event(event)

def handle_risk_event(event: dict):
    """Handle risk assessment events"""
    # Send to XDR
    xdr_integration = PingOneXDRIntegration(pingone_client, xdr_client)
    xdr_integration.process_risk_event(event)
    
    # Send to XSOAR
    xsoar_integration = PingOneXSOARIntegration(pingone_client, xsoar_client)
    xsoar_integration.create_xsoar_incident_from_risk_event(event)
    
    # Send to Prisma Cloud
    prisma_integration = PingOnePrismaAlertIntegration(pingone_client, prisma_client)
    prisma_integration.create_prisma_alert_from_risk_event(event)

def verify_pingone_webhook(request) -> bool:
    """Verify PingOne webhook signature"""
    # Implementation would verify the webhook signature
    # using PingOne's webhook verification method
    # Check X-PingOne-Signature header
    signature = request.headers.get('X-PingOne-Signature')
    # Verify signature against webhook secret
    return True


def is_suspicious_login(event: dict) -> bool:
    """Determine if login is suspicious"""
    # Check IP address, location, time, etc.
    ip_address = event.get('ip', '')
    event_type = event.get('type', '')
    
    # Failed MFA
    if 'MFA_VERIFY_FAILED' in event_type:
        return True
    
    # Add more sophisticated checks
    return False

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')
```

---

# Use Cases and Workflows

# 6.1 Complete Workflow: Suspicious Login Detection and Response

```python
#!/usr/bin/env python3
"""
Complete Workflow: Suspicious Login Detection and Response
Purpose: End-to-end workflow from detection to remediation
"""

class SuspiciousLoginWorkflow:
    """Complete workflow for suspicious login handling"""
    
    def __init__(self, pingone_client, xdr_client):
        self.pingone = pingone_client
        self.xdr = xdr_client
    
    def execute_workflow(self, event: Dict):
        """Execute complete suspicious login workflow"""
        
        # Step 1: Detect suspicious login
        if not self.is_suspicious(event):
            return
        
        user_id = event.get('user', {}).get('id')
        
        # Step 2: Gather intelligence
        intelligence = self.gather_intelligence(user_id, event)
        
        # Step 3: Create XDR incident
        xdr_incident = self.create_xdr_incident(event, intelligence)
        
        # Step 4: Automated response
        response_action = self.determine_response(intelligence)
        self.execute_response(user_id, response_action, xdr_incident.get('incident_id'))
        
        # Step 5: Notify stakeholders
        self.notify_stakeholders(event, intelligence, response_action)
        
        return {
            "xdr_incident": xdr_incident,
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
        user = self.pingone.get_user(user_id)
        groups = self.pingone.get_user_groups(user_id)
        roles = self.pingone.get_user_roles(user_id)
        sessions = self.pingone.get_user_sessions(user_id)
        recent_events = self.pingone.get_events(
            filter=f"user.id eq \"{user_id}\"",
            limit=20
        )
        
        return {
            "user": user,
            "groups": groups,
            "roles": roles,
            "sessions": sessions,
            "recent_events": recent_events,
            "risk_score": self.calculate_risk_score(user, groups, roles, recent_events)
        }
    
    def calculate_risk_score(self, user: Dict, groups: List, roles: List, events: List) -> int:
        """Calculate risk score"""
        score = 0
        
        # Privileged user
        privileged_roles = ['Administrator', 'Security', 'IT Admin']
        role_names = [role.get('role', {}).get('name', '') for role in roles]
        if any(role in privileged_roles for role in role_names):
            score += 3
        
        # Recent failed attempts
        failed = sum(1 for e in events if 'FAILED' in e.get('type', ''))
        score += min(failed, 3)
        
        # Unusual time
        hour = datetime.fromisoformat(events[0].get('createdAt', datetime.now().isoformat())).hour
        if hour < 6 or hour > 22:
            score += 2
        
        # Multiple active sessions
        if len(events) > 5:
            score += 2
        
        return min(score, 10)
    
    def determine_response(self, intelligence: Dict) -> str:
        """Determine response action"""
        risk_score = intelligence.get('risk_score', 0)
        
        if risk_score >= 8:
            return 'lock'
        elif risk_score >= 5:
            return 'terminate_sessions'
        else:
            return 'monitor'
    
    def execute_response(self, user_id: str, action: str, incident_id: str):
        """Execute response action"""
        if action == 'lock':
            self.pingone.lock_user(user_id)
            self.xdr.add_incident_comment(
                incident_id,
                f"Automated Response: Locked user {user_id}"
            )
        elif action == 'terminate_sessions':
            self.pingone.terminate_user_sessions(user_id)
            self.xdr.add_incident_comment(
                incident_id,
                f"Automated Response: Terminated all sessions for user {user_id}"
            )
        # 'monitor' requires no action
    
    def notify_stakeholders(self, event: Dict, intelligence: Dict, action: str):
        """Notify security team and stakeholders"""
        # Implementation would send notifications via Slack, email, etc.
        pass
    
    def check_ip_reputation(self, event: Dict) -> bool:
        """Check IP address reputation"""
        # Simplified - would use threat intelligence
        return False
    
    def check_time_pattern(self, event: Dict) -> bool:
        """Check if login time is unusual"""
        timestamp = datetime.fromisoformat(event.get('createdAt', datetime.now().isoformat()))
        hour = timestamp.hour
        return hour < 6 or hour > 22
    
    def check_location_anomaly(self, event: Dict) -> bool:
        """Check for location anomalies"""
        # Would compare against user's typical locations
        return False
    
    def check_failed_attempts(self, event: Dict) -> bool:
        """Check for multiple failed login attempts"""
        # Would query recent events for failed attempts
        return False
```

---

# Configuration and Setup

# 7.1 Environment Variables

```bash
# PingOne Configuration
export PINGONE_ENVIRONMENT_ID="your-environment-id"
export PINGONE_CLIENT_ID="your-client-id"
export PINGONE_CLIENT_SECRET="your-client-secret"
export PINGONE_REGION="us"  # us, eu, asia

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
# pingone_integrations_config.yaml
pingone:
  environment_id: "${PINGONE_ENVIRONMENT_ID}"
  client_id: "${PINGONE_CLIENT_ID}"
  client_secret: "${PINGONE_CLIENT_SECRET}"
  region: "${PINGONE_REGION}"
  
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
    sync_risk_events: true

event_routing:
  USER_LOCKED:
    - cortex_xdr
  USER_DELETED:
    - cortex_xdr
  MFA_VERIFY_FAILED:
    - cortex_xdr
  USER_LOGIN:
    - cortex_xdr  # Only if suspicious
  RISK_EVENT:
    - cortex_xdr  # Only if HIGH or CRITICAL

automated_responses:
  enabled: true
  actions:
    lock_user:
      trigger_severity: "critical"
      require_approval: true
    terminate_sessions:
      trigger_severity: "high"
      require_approval: false
    reset_password:
      trigger_severity: "medium"
      require_approval: false
```

# 7.3 PingOne Webhook Configuration

```json
{
  "name": "Cortex XDR Integration",
  "enabled": true,
  "url": "https://your-server.com/pingone/webhook",
  "secret": "your-webhook-secret",
  "events": [
    "USER_LOGIN",
    "USER_LOGOUT",
    "USER_LOCKED",
    "USER_UNLOCKED",
    "USER_DELETED",
    "USER_CREATED",
    "USER_ACCOUNT_DISABLED",
    "USER_ACCOUNT_ENABLED",
    "MFA_VERIFY_FAILED",
    "MFA_DEVICE_ENROLLED",
    "USER_PASSWORD_RESET",
    "RISK_EVENT"
  ],
  "filter": {
    "risk": {
      "level": ["HIGH", "CRITICAL"]
    }
  }
}
```

---

# Troubleshooting

# Common Issues and Solutions

# 1. Authentication Failures

Problem: PingOne API authentication fails

Solutions:
- Verify client ID and secret are correct
- Check OAuth token expiration (tokens expire after 1 hour)
- Ensure client has required scopes in PingOne
- Verify environment ID is correct
- Check region setting matches your PingOne environment

# 2. Rate Limiting

Problem: API rate limits exceeded

Solutions:
- Implement exponential backoff
- Use pagination for large result sets
- Cache frequently accessed data
- Batch requests when possible
- Respect PingOne's rate limits (typically 100 requests per minute)

# 3. Webhook Delivery Failures

Problem: Webhooks not being received

Solutions:
- Verify webhook URL is publicly accessible
- Check firewall rules allow inbound connections
- Validate webhook signature verification
- Implement retry logic for failed deliveries
- Check Webhook configuration in PingOne Admin Console
- Verify X-PingOne-Signature header is being validated

# 4. Event Filtering Issues

Problem: Too many or too few events being processed

Solutions:
- Refine event filters in `get_security_events()` method
- Adjust severity thresholds in configuration
- Use more specific event type filters
- Implement event deduplication logic
- Use PingOne's filter expressions for better filtering

# 5. User Lookup Failures

Problem: Cannot find user by ID

Solutions:
- Verify user exists and is active
- Check user ID format
- Use search API for email/username lookups
- Handle case sensitivity in searches
- Verify user hasn't been deleted

# 6. Risk Event Processing

Problem: Risk events not being captured

Solutions:
- Verify Risk API is enabled in your PingOne environment
- Check risk assessment policies are configured
- Ensure risk events are being generated
- Verify API client has risk.read scope

---

# Best Practices

1. OAuth Token Management: Implement automatic token refresh (tokens expire after 1 hour)
2. Error Handling: Implement comprehensive error handling and logging
3. Rate Limiting: Respect PingOne API rate limits
4. Event Deduplication: Implement logic to prevent processing duplicate events
5. Monitoring: Monitor integration health and API usage
6. Testing: Test integrations in non-production environments first
7. Documentation: Document custom mappings and configurations
8. Audit Logging: Log all actions taken via integrations
9. Webhook Security: Always verify webhook signatures
10. Risk Assessment: Leverage PingOne's risk assessment capabilities

---

# API Reference

# PingOne API Endpoints Used

- `POST /{environmentId}/as/token` - OAuth token endpoint
- `GET /{environmentId}/users` - List/search users
- `GET /{environmentId}/users/{userId}` - Get user details
- `GET /{environmentId}/users/{userId}/memberOfGroups` - Get user groups
- `GET /{environmentId}/users/{userId}/roleAssignments` - Get user roles
- `GET /{environmentId}/users/{userId}/sessions` - Get user sessions
- `DELETE /{environmentId}/users/{userId}/sessions` - Terminate sessions
- `PUT /{environmentId}/users/{userId}/account` - Update account (lock/unlock, enable/disable)
- `POST /{environmentId}/users/{userId}/password` - Reset password
- `GET /{environmentId}/logs` - Get audit events
- `GET /{environmentId}/riskEvents` - Get risk events
- `GET /{environmentId}/applications` - Get applications

# Required PingOne OAuth Scopes

- `p1:read:user` - Read user information
- `p1:update:user` - Update user information
- `p1:read:group` - Read group information
- `p1:read:role` - Read role information
- `p1:read:log` - Read audit logs
- `p1:read:risk` - Read risk events
- `p1:read:application` - Read application information

---

Version: 1.0  
Last Updated: 2026-01-09  
Maintained By: SOC Team
