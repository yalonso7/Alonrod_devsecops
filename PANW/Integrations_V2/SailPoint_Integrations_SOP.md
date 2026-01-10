# SailPoint Identity Integrations Standard Operating Procedure (SOP)

# Table of Contents

1. [Overview](#overview)
2. [SailPoint IdentityNow API Integration Basics](#sailpoint-identitynow-api-integration-basics)
3. [SailPoint to Cortex XDR Integration](#sailpoint-to-cortex-xdr-integration)
4. [SailPoint to XSOAR Integration](#sailpoint-to-xsoar-integration)
5. [SailPoint to Prisma Cloud Integration](#sailpoint-to-prisma-cloud-integration)
6. [Webhook Integrations](#webhook-integrations)
7. [Use Cases and Workflows](#use-cases-and-workflows)
8. [Configuration and Setup](#configuration-and-setup)
9. [Troubleshooting](#troubleshooting)

---

# Overview

This SOP provides comprehensive integration code snippets and configuration examples for connecting SailPoint IdentityNow (IdentityIQ) with Palo Alto Networks security products (Cortex XDR, XSOAR, Prisma Cloud). These integrations enable automated identity governance, access certification, and security incident response.

# Integration Use Cases

- **Identity Governance**: Monitor access certifications and access requests
- **Automated Incident Response**: Create security incidents in XDR/XSOAR based on SailPoint violations
- **Access Analytics**: Sync SailPoint access data to Prisma Cloud for CIEM analysis
- **Compliance Monitoring**: Track access compliance violations across platforms
- **Automated Remediation**: Respond to access violations automatically
- **Certification Campaigns**: Integrate certification data with security operations

---

# SailPoint IdentityNow API Integration Basics

# 1. SailPoint IdentityNow API Client (Python)

```python
#!/usr/bin/env python3
"""
SailPoint IdentityNow API Integration Client
Purpose: Authenticate and interact with SailPoint IdentityNow API
"""

import requests
import json
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import os
import base64

class SailPointClient:
    """SailPoint IdentityNow API Client"""
    
    def __init__(self, tenant: str, client_id: str, client_secret: str):
        """
        Initialize SailPoint IdentityNow client
        
        Args:
            tenant: SailPoint tenant name (e.g., 'yourtenant')
            client_id: OAuth client ID
            client_secret: OAuth client secret
        """
        self.tenant = tenant
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = f"https://{tenant}.api.identitynow.com"
        self.token = None
        self.token_expiry = None
        self._authenticate()
    
    def _authenticate(self):
        """Authenticate and get access token"""
        url = f"{self.base_url}/oauth/token"
        
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
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
    
    def get_identities(self, 
                      filters: Optional[str] = None,
                      limit: int = 250,
                      offset: int = 0) -> List[Dict]:
        """
        Get identities (users)
        
        Args:
            filters: Filter expression (e.g., "name eq \"John Doe\"")
            limit: Maximum number of results
            offset: Offset for pagination
        """
        url = f"{self.base_url}/v3/identities"
        
        params = {
            "limit": limit,
            "offset": offset
        }
        
        if filters:
            params["filters"] = filters
        
        response = requests.get(url, params=params, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def get_identity(self, identity_id: str) -> Dict:
        """Get identity details by ID"""
        url = f"{self.base_url}/v3/identities/{identity_id}"
        response = requests.get(url, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def get_identity_access(self, identity_id: str) -> List[Dict]:
        """Get access items for an identity"""
        url = f"{self.base_url}/v3/identities/{identity_id}/access"
        response = requests.get(url, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def get_accounts(self, 
                    identity_id: Optional[str] = None,
                    source_id: Optional[str] = None,
                    limit: int = 250) -> List[Dict]:
        """Get accounts"""
        url = f"{self.base_url}/v3/accounts"
        
        params = {"limit": limit}
        if identity_id:
            params["filters"] = f"identity.id eq \"{identity_id}\""
        if source_id:
            params["filters"] = f"source.id eq \"{source_id}\""
        
        response = requests.get(url, params=params, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def get_access_profiles(self, limit: int = 250) -> List[Dict]:
        """Get access profiles"""
        url = f"{self.base_url}/v3/access-profiles"
        params = {"limit": limit}
        response = requests.get(url, params=params, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def get_roles(self, limit: int = 250) -> List[Dict]:
        """Get roles"""
        url = f"{self.base_url}/v3/roles"
        params = {"limit": limit}
        response = requests.get(url, params=params, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def get_certifications(self,
                          reviewer_id: Optional[str] = None,
                          status: Optional[str] = None,
                          limit: int = 250) -> List[Dict]:
        """
        Get certification campaigns
        
        Args:
            reviewer_id: Filter by reviewer ID
            status: Filter by status (PENDING, COMPLETED, etc.)
            limit: Maximum number of results
        """
        url = f"{self.base_url}/v3/certifications"
        
        params = {"limit": limit}
        if reviewer_id:
            params["filters"] = f"reviewer.id eq \"{reviewer_id}\""
        if status:
            params["filters"] = f"status eq \"{status}\""
        
        response = requests.get(url, params=params, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def get_certification_items(self, certification_id: str) -> List[Dict]:
        """Get items in a certification campaign"""
        url = f"{self.base_url}/v3/certifications/{certification_id}/items"
        response = requests.get(url, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def get_access_requests(self,
                           requestor_id: Optional[str] = None,
                           status: Optional[str] = None,
                           limit: int = 250) -> List[Dict]:
        """Get access requests"""
        url = f"{self.base_url}/v3/access-requests"
        
        params = {"limit": limit}
        if requestor_id:
            params["filters"] = f"requestedFor.id eq \"{requestor_id}\""
        if status:
            params["filters"] = f"status eq \"{status}\""
        
        response = requests.get(url, params=params, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def get_events(self,
                  start_time: Optional[datetime] = None,
                  end_time: Optional[datetime] = None,
                  event_type: Optional[str] = None,
                  limit: int = 1000) -> List[Dict]:
        """
        Get audit events
        
        Args:
            start_time: Start time for event query
            end_time: End time for event query
            event_type: Filter by event type
            limit: Maximum number of events
        """
        url = f"{self.base_url}/v3/events"
        
        params = {"limit": limit}
        if start_time:
            params["since"] = start_time.isoformat()
        if end_time:
            params["until"] = end_time.isoformat()
        if event_type:
            params["filters"] = f"type eq \"{event_type}\""
        
        response = requests.get(url, params=params, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def get_security_events(self,
                           start_time: Optional[datetime] = None,
                           limit: int = 1000) -> List[Dict]:
        """Get security-related events"""
        security_event_types = [
            "access.request.approved",
            "access.request.denied",
            "access.request.revoked",
            "identity.created",
            "identity.deleted",
            "identity.updated",
            "account.aggregation.completed",
            "account.aggregation.failed",
            "account.correlated",
            "account.uncorrelated"
        ]
        
        all_events = []
        for event_type in security_event_types:
            events = self.get_events(
                start_time=start_time,
                event_type=event_type,
                limit=limit
            )
            all_events.extend(events)
        
        return all_events
    
    def revoke_access(self, identity_id: str, access_item_id: str, reason: str) -> Dict:
        """Revoke access for an identity"""
        url = f"{self.base_url}/v3/identities/{identity_id}/access-items/{access_item_id}/revoke"
        
        payload = {
            "reason": reason
        }
        
        response = requests.post(url, json=payload, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def grant_access(self, identity_id: str, access_item_id: str, reason: str) -> Dict:
        """Grant access to an identity"""
        url = f"{self.base_url}/v3/identities/{identity_id}/access-items/{access_item_id}/grant"
        
        payload = {
            "reason": reason
        }
        
        response = requests.post(url, json=payload, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def create_access_request(self,
                             identity_id: str,
                             access_item_ids: List[str],
                             reason: str) -> Dict:
        """Create an access request"""
        url = f"{self.base_url}/v3/access-requests"
        
        payload = {
            "requestedFor": identity_id,
            "requestedItems": [
                {"id": item_id, "type": "ACCESS_PROFILE"}
                for item_id in access_item_ids
            ],
            "requestedComments": reason
        }
        
        response = requests.post(url, json=payload, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def get_violations(self,
                      identity_id: Optional[str] = None,
                      status: Optional[str] = None,
                      limit: int = 250) -> List[Dict]:
        """Get policy violations"""
        url = f"{self.base_url}/v3/policy-violations"
        
        params = {"limit": limit}
        if identity_id:
            params["filters"] = f"identity.id eq \"{identity_id}\""
        if status:
            params["filters"] = f"status eq \"{status}\""
        
        response = requests.get(url, params=params, headers=self._get_headers())
        response.raise_for_status()
        return response.json()
    
    def get_entitlements(self,
                        identity_id: Optional[str] = None,
                        source_id: Optional[str] = None,
                        limit: int = 250) -> List[Dict]:
        """Get entitlements"""
        url = f"{self.base_url}/v3/entitlements"
        
        params = {"limit": limit}
        if identity_id:
            params["filters"] = f"identity.id eq \"{identity_id}\""
        if source_id:
            params["filters"] = f"source.id eq \"{source_id}\""
        
        response = requests.get(url, params=params, headers=self._get_headers())
        response.raise_for_status()
        return response.json()

# Usage Example
if __name__ == "__main__":
    client = SailPointClient(
        tenant=os.getenv("SAILPOINT_TENANT", "yourtenant"),
        client_id=os.getenv("SAILPOINT_CLIENT_ID"),
        client_secret=os.getenv("SAILPOINT_CLIENT_SECRET")
    )
    
    # Get recent security events
    events = client.get_security_events(
        start_time=datetime.now() - timedelta(hours=24)
    )
    print(f"Found {len(events)} security events")
    
    # Get identities
    identities = client.get_identities(limit=10)
    print(f"Found {len(identities)} identities")
    
    # Get policy violations
    violations = client.get_violations(status="OPEN")
    print(f"Found {len(violations)} open violations")
```

---

# SailPoint to Cortex XDR Integration

# 2.1 SailPoint Violations to XDR Incidents

```python
#!/usr/bin/env python3
"""
SailPoint to Cortex XDR Integration
Purpose: Create XDR incidents from SailPoint policy violations and security events
"""

from datetime import datetime, timedelta
from typing import Dict, List
import os
import time

class SailPointXDRIntegration:
    """Integrate SailPoint with Cortex XDR"""
    
    def __init__(self, sailpoint_client, xdr_client):
        self.sailpoint = sailpoint_client
        self.xdr = xdr_client
    
    def monitor_sailpoint_violations(self, check_interval_minutes: int = 30):
        """Continuously monitor SailPoint violations and create XDR incidents"""
        last_check = datetime.now() - timedelta(minutes=check_interval_minutes)
        
        while True:
            try:
                # Get new violations since last check
                violations = self.sailpoint.get_violations(status="OPEN")
                
                # Process violations
                for violation in violations:
                    if self.is_new_violation(violation, last_check):
                        self.process_violation(violation)
                
                last_check = datetime.now()
                time.sleep(check_interval_minutes * 60)
                
            except Exception as e:
                print(f"Error monitoring SailPoint violations: {e}")
                time.sleep(60)
    
    def is_new_violation(self, violation: Dict, since: datetime) -> bool:
        """Check if violation is new"""
        created = datetime.fromisoformat(violation.get('created', '').replace('Z', '+00:00'))
        return created >= since
    
    def process_violation(self, violation: Dict):
        """Process a policy violation and create XDR incident"""
        severity = self.determine_severity(violation)
        
        # Only create incidents for high-severity violations
        if severity in ['high', 'critical']:
            incident_data = self.create_xdr_incident_from_violation(violation)
            self.xdr.create_incident(incident_data)
    
    def determine_severity(self, violation: Dict) -> str:
        """Determine severity based on violation type and policy"""
        violation_type = violation.get('policy', {}).get('type', '')
        policy_name = violation.get('policy', {}).get('name', '').lower()
        
        # Critical violations
        if 'segregation' in policy_name or 'separation' in policy_name:
            return 'critical'
        if 'privileged' in policy_name or 'admin' in policy_name:
            return 'critical'
        
        # High violations
        if 'orphaned' in policy_name or 'inactive' in policy_name:
            return 'high'
        if violation_type == 'SEGREGATION_OF_DUTY':
            return 'high'
        
        return 'medium'
    
    def create_xdr_incident_from_violation(self, violation: Dict) -> Dict:
        """Create XDR incident payload from SailPoint violation"""
        violation_id = violation.get('id')
        identity_id = violation.get('identity', {}).get('id', 'Unknown')
        policy_name = violation.get('policy', {}).get('name', 'Unknown')
        violation_type = violation.get('policy', {}).get('type', 'Unknown')
        
        # Get identity details
        try:
            identity = self.sailpoint.get_identity(identity_id)
            identity_name = identity.get('name', identity_id)
            identity_email = identity.get('email', '')
        except:
            identity_name = identity_id
            identity_email = ''
        
        # Build incident description
        description = f"""
        SailPoint Policy Violation Detected
        
        Violation ID: {violation_id}
        Policy: {policy_name}
        Violation Type: {violation_type}
        Identity: {identity_name} ({identity_email})
        Status: {violation.get('status', 'OPEN')}
        Created: {violation.get('created', '')}
        
        Violation Details:
        {json.dumps(violation, indent=2)}
        """
        
        return {
            "incident_name": f"SailPoint: {policy_name} - {identity_name}",
            "severity": self.determine_severity(violation),
            "description": description,
            "labels": [
                {"key": "source", "value": "SailPoint"},
                {"key": "violation_type", "value": violation_type},
                {"key": "identity_id", "value": identity_id},
                {"key": "policy_name", "value": policy_name}
            ],
            "custom_fields": {
                "sailpoint_violation_id": violation_id,
                "sailpoint_policy_name": policy_name,
                "sailpoint_violation_type": violation_type,
                "sailpoint_identity_id": identity_id,
                "sailpoint_identity_name": identity_name,
                "sailpoint_identity_email": identity_email,
                "sailpoint_created": violation.get('created', '')
            }
        }
    
    def sync_access_request_to_xdr(self, access_request: Dict):
        """Create XDR incident for suspicious access requests"""
        requestor_id = access_request.get('requestedFor', {}).get('id')
        requested_items = access_request.get('requestedItems', [])
        
        # Check for suspicious patterns
        is_suspicious = self.detect_suspicious_access_request(access_request)
        
        if is_suspicious:
            # Get requestor details
            try:
                requestor = self.sailpoint.get_identity(requestor_id)
                requestor_name = requestor.get('name', requestor_id)
                requestor_email = requestor.get('email', '')
            except:
                requestor_name = requestor_id
                requestor_email = ''
            
            incident = {
                "incident_name": f"SailPoint: Suspicious Access Request - {requestor_name}",
                "severity": "high",
                "description": f"""
                Suspicious access request detected
        
                Requestor: {requestor_name} ({requestor_email})
                Requested Items: {len(requested_items)}
                Request Time: {access_request.get('created', '')}
                
                Requested Access:
                {json.dumps(requested_items, indent=2)}
                
                Risk Indicators:
                - Unusual access request pattern
                - Request for privileged access
                - Off-hours request
                """,
                "labels": [
                    {"key": "source", "value": "SailPoint"},
                    {"key": "event_type", "value": "suspicious_access_request"},
                    {"key": "threat_type", "value": "privilege_escalation"}
                ]
            }
            
            xdr_incident = self.xdr.create_incident(incident)
            
            # Add comment with remediation steps
            self.xdr.add_incident_comment(
                xdr_incident.get('incident_id'),
                "Recommended Actions:\n1. Review access request justification\n2. Verify requestor identity\n3. Consider denying request if suspicious"
            )
            
            return xdr_incident
    
    def detect_suspicious_access_request(self, request: Dict) -> bool:
        """Detect suspicious access request patterns"""
        requested_items = request.get('requestedItems', [])
        
        # Check for many items requested at once
        if len(requested_items) > 10:
            return True
        
        # Check for privileged access requests
        for item in requested_items:
            item_name = item.get('name', '').lower()
            if any(keyword in item_name for keyword in ['admin', 'privileged', 'root', 'sudo']):
                return True
        
        # Check for off-hours request
        created = datetime.fromisoformat(request.get('created', '').replace('Z', '+00:00'))
        hour = created.hour
        if hour < 6 or hour > 22:
            return True
        
        return False

# Usage Example
if __name__ == "__main__":
    from sailpoint_client import SailPointClient
    from cortex_xdr_client import CortexXDRClient
    
    # Initialize clients
    sailpoint = SailPointClient(
        tenant=os.getenv("SAILPOINT_TENANT"),
        client_id=os.getenv("SAILPOINT_CLIENT_ID"),
        client_secret=os.getenv("SAILPOINT_CLIENT_SECRET")
    )
    
    xdr = CortexXDRClient(
        api_key=os.getenv("XDR_API_KEY"),
        api_key_id=os.getenv("XDR_API_KEY_ID")
    )
    
    # Create integration
    integration = SailPointXDRIntegration(sailpoint, xdr)
    
    # Monitor violations
    integration.monitor_sailpoint_violations(check_interval_minutes=30)
```

# 2.2 Automated Response to XDR Incidents

```python
#!/usr/bin/env python3
"""
Automated Response: XDR Incident → SailPoint Actions
Purpose: Automatically respond to XDR incidents by taking SailPoint actions
"""

class XDRSailPointResponse:
    """Automated response to XDR incidents using SailPoint"""
    
    def __init__(self, xdr_client, sailpoint_client):
        self.xdr = xdr_client
        self.sailpoint = sailpoint_client
    
    def handle_xdr_incident(self, incident_id: str):
        """Handle XDR incident and take SailPoint actions"""
        incident = self.xdr.get_incident(incident_id)
        
        # Check if incident is related to identity/access
        if self.is_access_related(incident):
            identity_id = self.extract_identity_id(incident)
            
            if identity_id:
                # Determine response action
                action = self.determine_response_action(incident)
                
                if action == 'revoke_access':
                    access_items = self.get_identity_access_items(identity_id, incident)
                    for item in access_items:
                        self.sailpoint.revoke_access(
                            identity_id,
                            item.get('id'),
                            f"Revoked due to XDR incident: {incident_id}"
                        )
                    self.xdr.add_incident_comment(
                        incident_id,
                        f"Automated Response: Revoked access for identity {identity_id}"
                    )
                elif action == 'create_violation_review':
                    # Create a certification review for the identity
                    self.create_certification_review(identity_id, incident_id)
                    self.xdr.add_incident_comment(
                        incident_id,
                        f"Automated Response: Created certification review for identity {identity_id}"
                    )
    
    def is_access_related(self, incident: Dict) -> bool:
        """Check if incident is access-related"""
        labels = incident.get('labels', [])
        for label in labels:
            if label.get('key') == 'source' and label.get('value') == 'SailPoint':
                return True
            if label.get('key') == 'threat_type') and 'access' in label.get('value', '').lower():
                return True
        return False
    
    def extract_identity_id(self, incident: Dict) -> Optional[str]:
        """Extract identity ID from incident"""
        custom_fields = incident.get('custom_fields', {})
        return custom_fields.get('sailpoint_identity_id')
    
    def get_identity_access_items(self, identity_id: str, incident: Dict) -> List[Dict]:
        """Get access items to revoke based on incident"""
        # Get all access for the identity
        access = self.sailpoint.get_identity_access(identity_id)
        
        # Filter based on incident context
        # For example, if incident mentions privileged access, filter for privileged items
        return access
    
    def determine_response_action(self, incident: Dict) -> str:
        """Determine appropriate response action"""
        severity = incident.get('severity', 'medium')
        violation_type = incident.get('custom_fields', {}).get('sailpoint_violation_type', '')
        
        if severity == 'critical' or violation_type == 'SEGREGATION_OF_DUTY':
            return 'revoke_access'
        elif severity == 'high':
            return 'create_violation_review'
        else:
            return 'monitor'
    
    def create_certification_review(self, identity_id: str, incident_id: str):
        """Create a certification review for an identity"""
        # This would typically be done via SailPoint's certification API
        # Implementation depends on SailPoint version and API availability
        pass
```

---

# SailPoint to XSOAR Integration

# 3.1 SailPoint Violations to XSOAR Incidents

```python
#!/usr/bin/env python3
"""
SailPoint to XSOAR Integration
Purpose: Create XSOAR incidents from SailPoint violations and automate playbooks
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
import os

class SailPointXSOARIntegration:
    """Integrate SailPoint with Cortex XSOAR"""
    
    def __init__(self, sailpoint_client, xsoar_client):
        self.sailpoint = sailpoint_client
        self.xsoar = xsoar_client
    
    def create_xsoar_incident_from_violation(self, violation: Dict) -> Dict:
        """Create XSOAR incident from SailPoint violation"""
        violation_id = violation.get('id')
        identity_id = violation.get('identity', {}).get('id', 'Unknown')
        policy_name = violation.get('policy', {}).get('name', 'Unknown')
        violation_type = violation.get('policy', {}).get('type', 'Unknown')
        
        # Get identity details
        try:
            identity = self.sailpoint.get_identity(identity_id)
            identity_name = identity.get('name', identity_id)
            identity_email = identity.get('email', '')
        except:
            identity_name = identity_id
            identity_email = ''
        
        # Determine incident type and severity
        incident_type, severity = self.map_violation_to_incident_type(violation_type)
        
        # Create incident
        incident = self.xsoar.create_incident(
            name=f"SailPoint: {policy_name} - {identity_name}",
            severity=severity,
            type=incident_type,
            labels=[
                {"type": "source", "value": "SailPoint"},
                {"type": "violation_type", "value": violation_type},
                {"type": "identity_id", "value": identity_id},
                {"type": "identity_email", "value": identity_email},
                {"type": "policy_name", "value": policy_name}
            ],
            custom_fields={
                "sailpoint_violation_id": violation_id,
                "sailpoint_policy_name": policy_name,
                "sailpoint_violation_type": violation_type,
                "sailpoint_identity_id": identity_id,
                "sailpoint_identity_name": identity_name,
                "sailpoint_identity_email": identity_email,
                "sailpoint_status": violation.get('status', 'OPEN'),
                "sailpoint_created": violation.get('created', '')
            }
        )
        
        # Add detailed description
        description = self.build_incident_description(violation, identity_name, identity_email)
        self.xsoar.add_incident_entry(
            incident.get('id'),
            description,
            entry_type="note"
        )
        
        return incident
    
    def map_violation_to_incident_type(self, violation_type: str) -> tuple:
        """Map SailPoint violation type to XSOAR incident type and severity"""
        mapping = {
            'SEGREGATION_OF_DUTY': ('Identity Access Management', 4),  # Critical
            'PRIVILEGED_ACCESS': ('Identity Access Management', 4),
            'ORPHANED_ACCOUNT': ('Identity Access Management', 3),  # High
            'INACTIVE_ACCOUNT': ('Identity Access Management', 2),  # Medium
            'EXCESSIVE_ACCESS': ('Access', 3),
            'RISK_SCORE': ('Identity Access Management', 2)
        }
        
        return mapping.get(violation_type, ('Unclassified', 1))
    
    def build_incident_description(self, violation: Dict, identity_name: str, identity_email: str) -> str:
        """Build detailed incident description"""
        return f"""
# SailPoint Policy Violation

## Violation Information
- **Violation ID**: {violation.get('id')}
- **Policy**: {violation.get('policy', {}).get('name')}
- **Type**: {violation.get('policy', {}).get('type')}
- **Status**: {violation.get('status', 'OPEN')}
- **Created**: {violation.get('created', '')}

## Identity Information
- **Identity ID**: {violation.get('identity', {}).get('id')}
- **Name**: {identity_name}
- **Email**: {identity_email}

## Violation Details
```json
{json.dumps(violation, indent=2)}
```

## Recommended Actions
1. Review violation details
2. Verify identity access requirements
3. Determine if access should be revoked
4. Update access if needed
5. Close violation after remediation
        """
    
    def trigger_playbook_for_violation(self, violation: Dict):
        """Trigger XSOAR playbook based on violation type"""
        violation_type = violation.get('policy', {}).get('type')
        
        # Create incident first
        incident = self.create_xsoar_incident_from_violation(violation)
        
        # Trigger appropriate playbook
        if violation_type == 'SEGREGATION_OF_DUTY':
            playbook_name = "Investigate Segregation of Duty Violation"
        elif violation_type == 'PRIVILEGED_ACCESS':
            playbook_name = "Investigate Privileged Access Violation"
        elif violation_type == 'ORPHANED_ACCOUNT':
            playbook_name = "Investigate Orphaned Account"
        else:
            playbook_name = "Generic Access Violation Investigation"
        
        # Execute playbook
        self.xsoar.execute_command(
            command="executePlaybook",
            arguments={
                "incidentId": incident.get('id'),
                "playbookName": playbook_name
            }
        )
    
    def sync_certification_to_xsoar(self, certification_id: str):
        """Sync certification campaign data to XSOAR"""
        certification = self.sailpoint.get_certifications()[0]  # Simplified
        items = self.sailpoint.get_certification_items(certification_id)
        
        # Create incident for overdue certifications
        overdue_items = [item for item in items if item.get('status') == 'PENDING']
        
        if len(overdue_items) > 10:
            incident = self.xsoar.create_incident(
                name=f"SailPoint: Overdue Certification Items - {len(overdue_items)} items",
                severity=2,
                type="Compliance",
                labels=[
                    {"type": "source", "value": "SailPoint"},
                    {"type": "certification_id", "value": certification_id}
                ]
            )

# Usage Example
if __name__ == "__main__":
    from sailpoint_client import SailPointClient
    from xsoar_client import XSOARClient
    
    sailpoint = SailPointClient(
        tenant=os.getenv("SAILPOINT_TENANT"),
        client_id=os.getenv("SAILPOINT_CLIENT_ID"),
        client_secret=os.getenv("SAILPOINT_CLIENT_SECRET")
    )
    
    xsoar = XSOARClient(
        base_url=os.getenv("XSOAR_URL"),
        api_key=os.getenv("XSOAR_API_KEY")
    )
    
    integration = SailPointXSOARIntegration(sailpoint, xsoar)
    
    # Get open violations
    violations = sailpoint.get_violations(status="OPEN")
    
    # Create incidents for high-severity violations
    for violation in violations:
        violation_type = violation.get('policy', {}).get('type')
        if violation_type in ['SEGREGATION_OF_DUTY', 'PRIVILEGED_ACCESS']:
            integration.trigger_playbook_for_violation(violation)
```

# 3.2 XSOAR Playbook Integration with SailPoint

```python
#!/usr/bin/env python3
"""
XSOAR Playbook: SailPoint Violation Investigation
Purpose: Automated playbook for investigating SailPoint violations
"""

class SailPointViolationInvestigationPlaybook:
    """XSOAR playbook for SailPoint violation investigations"""
    
    def __init__(self, xsoar_client, sailpoint_client):
        self.xsoar = xsoar_client
        self.sailpoint = sailpoint_client
    
    def execute_investigation(self, incident_id: str):
        """Execute full investigation playbook"""
        incident = self.xsoar.get_incident(incident_id)
        
        # Step 1: Extract violation information
        violation_id = incident.get('customFields', {}).get('sailpoint_violation_id')
        identity_id = incident.get('customFields', {}).get('sailpoint_identity_id')
        
        if not violation_id or not identity_id:
            self.xsoar.add_incident_entry(
                incident_id,
                "Error: Could not extract violation or identity ID from incident",
                entry_type="note"
            )
            return
        
        # Step 2: Gather identity details
        identity_info = self.gather_identity_information(identity_id)
        self.xsoar.add_incident_entry(
            incident_id,
            f"Identity Information:\n{json.dumps(identity_info, indent=2)}",
            entry_type="note"
        )
        
        # Step 3: Get identity access
        access = self.sailpoint.get_identity_access(identity_id)
        self.xsoar.add_incident_entry(
            incident_id,
            f"Identity Access: {len(access)} access items",
            entry_type="note"
        )
        
        # Step 4: Analyze violation
        violation_analysis = self.analyze_violation(violation_id, identity_id, access)
        self.xsoar.add_incident_entry(
            incident_id,
            f"Violation Analysis:\n{json.dumps(violation_analysis, indent=2)}",
            entry_type="note"
        )
        
        # Step 5: Risk assessment
        risk_score = self.assess_risk(identity_info, access, violation_analysis)
        
        # Step 6: Recommend actions
        recommendations = self.generate_recommendations(risk_score, violation_analysis)
        self.xsoar.add_incident_entry(
            incident_id,
            f"Risk Assessment: {risk_score}/10\n\nRecommendations:\n{recommendations}",
            entry_type="note"
        )
        
        # Step 7: Update incident severity if needed
        if risk_score >= 8:
            self.xsoar.update_incident(incident_id, {"severity": 4})
    
    def gather_identity_information(self, identity_id: str) -> Dict:
        """Gather comprehensive identity information"""
        identity = self.sailpoint.get_identity(identity_id)
        access = self.sailpoint.get_identity_access(identity_id)
        accounts = self.sailpoint.get_accounts(identity_id=identity_id)
        
        return {
            "identity": {
                "id": identity.get('id'),
                "name": identity.get('name'),
                "email": identity.get('email'),
                "status": identity.get('status')
            },
            "access_count": len(access),
            "account_count": len(accounts)
        }
    
    def analyze_violation(self, violation_id: str, identity_id: str, access: List[Dict]) -> Dict:
        """Analyze violation details"""
        violations = self.sailpoint.get_violations(identity_id=identity_id)
        current_violation = next((v for v in violations if v.get('id') == violation_id), None)
        
        return {
            "violation_type": current_violation.get('policy', {}).get('type') if current_violation else 'Unknown',
            "total_violations": len(violations),
            "access_items": len(access),
            "violation_severity": self.determine_severity(current_violation) if current_violation else 'medium'
        }
    
    def assess_risk(self, identity_info: Dict, access: List[Dict], analysis: Dict) -> int:
        """Assess risk score (0-10)"""
        risk = 0
        
        # Check violation type
        if analysis.get('violation_type') == 'SEGREGATION_OF_DUTY':
            risk += 4
        elif analysis.get('violation_type') == 'PRIVILEGED_ACCESS':
            risk += 3
        
        # Check for many violations
        if analysis.get('total_violations', 0) > 5:
            risk += 2
        
        # Check for excessive access
        if analysis.get('access_items', 0) > 20:
            risk += 2
        
        return min(risk, 10)
    
    def generate_recommendations(self, risk_score: int, analysis: Dict) -> str:
        """Generate recommendations based on risk score"""
        recommendations = []
        
        if risk_score >= 8:
            recommendations.append("1. IMMEDIATE: Revoke conflicting access")
            recommendations.append("2. Review all identity access")
            recommendations.append("3. Escalate to access governance team")
        elif risk_score >= 5:
            recommendations.append("1. Review violation details")
            recommendations.append("2. Verify access requirements")
            recommendations.append("3. Consider access reduction")
        else:
            recommendations.append("1. Review violation")
            recommendations.append("2. Update access if needed")
        
        return "\n".join(recommendations)
```

---

# SailPoint to Prisma Cloud Integration

# 4.1 SailPoint Access Data to Prisma Cloud CIEM

```python
#!/usr/bin/env python3
"""
SailPoint to Prisma Cloud CIEM Integration
Purpose: Sync SailPoint identity and access data to Prisma Cloud for identity governance
"""

from datetime import datetime
from typing import Dict, List, Optional
import os

class SailPointPrismaCloudIntegration:
    """Integrate SailPoint with Prisma Cloud CIEM"""
    
    def __init__(self, sailpoint_client, prisma_client):
        self.sailpoint = sailpoint_client
        self.prisma = prisma_client
    
    def sync_sailpoint_identities_to_prisma(self):
        """Sync SailPoint identities and their access to Prisma Cloud"""
        # Get all identities
        identities = self.sailpoint.get_identities(limit=1000)
        
        for identity in identities:
            identity_data = self.build_identity_access_data(identity)
            self.send_to_prisma_ciem(identity_data)
    
    def build_identity_access_data(self, identity: Dict) -> Dict:
        """Build identity access data structure for Prisma Cloud"""
        identity_id = identity.get('id')
        identity_name = identity.get('name', '')
        identity_email = identity.get('email', '')
        
        # Get identity access
        access = self.sailpoint.get_identity_access(identity_id)
        access_items = [item.get('name') for item in access]
        
        # Get accounts
        accounts = self.sailpoint.get_accounts(identity_id=identity_id)
        account_sources = [acc.get('source', {}).get('name') for acc in accounts]
        
        # Get entitlements
        entitlements = self.sailpoint.get_entitlements(identity_id=identity_id)
        entitlement_names = [ent.get('name') for ent in entitlements]
        
        return {
            "identity_id": f"sailpoint:{identity_id}",
            "identity_type": "user",
            "identity_name": identity_name or identity_email,
            "source": "SailPoint",
            "status": identity.get('status'),
            "access_items": access_items,
            "account_sources": account_sources,
            "entitlements": entitlement_names,
            "created_at": identity.get('created'),
            "metadata": {
                "sailpoint_identity_id": identity_id,
                "email": identity_email,
                "department": identity.get('department'),
                "title": identity.get('title')
            }
        }
    
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
    
    def sync_violations_to_prisma(self):
        """Sync SailPoint violations to Prisma Cloud"""
        violations = self.sailpoint.get_violations(status="OPEN")
        
        for violation in violations:
            violation_data = self.build_violation_data(violation)
            self.send_violation_to_prisma(violation_data)
    
    def build_violation_data(self, violation: Dict) -> Dict:
        """Build violation data structure for Prisma Cloud"""
        return {
            "violation_id": violation.get('id'),
            "violation_type": violation.get('policy', {}).get('type'),
            "policy_name": violation.get('policy', {}).get('name'),
            "identity_id": violation.get('identity', {}).get('id'),
            "status": violation.get('status'),
            "created": violation.get('created'),
            "severity": self.map_violation_severity(violation.get('policy', {}).get('type')),
            "source": "SailPoint",
            "raw_violation": violation
        }
    
    def map_violation_severity(self, violation_type: str) -> str:
        """Map SailPoint violation type to severity"""
        severity_map = {
            'SEGREGATION_OF_DUTY': 'high',
            'PRIVILEGED_ACCESS': 'high',
            'ORPHANED_ACCOUNT': 'medium',
            'INACTIVE_ACCOUNT': 'low',
            'EXCESSIVE_ACCESS': 'medium'
        }
        return severity_map.get(violation_type, 'low')
    
    def send_violation_to_prisma(self, violation_data: Dict):
        """Send violation to Prisma Cloud"""
        url = f"{self.prisma.api_url}/v2/event"
        
        response = requests.post(
            url,
            json=violation_data,
            headers=self.prisma._get_headers()
        )
        
        return response.status_code == 200
    
    def correlate_sailpoint_access_with_cloud_resources(self, identity_id: str):
        """Correlate SailPoint identity access with cloud resources in Prisma"""
        # Get identity from SailPoint
        identity = self.sailpoint.get_identity(identity_id)
        access = self.sailpoint.get_identity_access(identity_id)
        accounts = self.sailpoint.get_accounts(identity_id=identity_id)
        
        # Query Prisma Cloud for resources accessed by this identity
        # This would require mapping SailPoint access to cloud IAM roles
        
        correlation_data = {
            "sailpoint_identity": {
                "id": identity_id,
                "name": identity.get('name'),
                "email": identity.get('email'),
                "access_items": [item.get('name') for item in access],
                "accounts": [acc.get('source', {}).get('name') for acc in accounts]
            },
            "cloud_resources": self.find_cloud_resources_for_identity(identity_id, access, accounts)
        }
        
        return correlation_data
    
    def find_cloud_resources_for_identity(self, identity_id: str, access: List[Dict], accounts: List[Dict]) -> List[Dict]:
        """Find cloud resources accessible by identity based on SailPoint access"""
        cloud_resources = []
        
        # Map SailPoint access profiles to cloud IAM roles
        # This is a simplified example
        access_profile_to_role_mapping = {
            'AWS-Admin-Access': 'arn:aws:iam::123456789012:role/AdminRole',
            'AWS-Developer-Access': 'arn:aws:iam::123456789012:role/DeveloperRole'
        }
        
        for access_item in access:
            access_name = access_item.get('name')
            if access_name in access_profile_to_role_mapping:
                # Query Prisma Cloud for resources with this role
                resources = self.prisma.get_resources_by_iam_role(
                    access_profile_to_role_mapping[access_name]
                )
                cloud_resources.extend(resources)
        
        return cloud_resources

# Usage Example
if __name__ == "__main__":
    from sailpoint_client import SailPointClient
    from prisma_cloud_client import PrismaCloudClient
    
    sailpoint = SailPointClient(
        tenant=os.getenv("SAILPOINT_TENANT"),
        client_id=os.getenv("SAILPOINT_CLIENT_ID"),
        client_secret=os.getenv("SAILPOINT_CLIENT_SECRET")
    )
    
    prisma = PrismaCloudClient(
        api_url=os.getenv("PRISMA_API_URL"),
        access_key=os.getenv("PRISMA_ACCESS_KEY"),
        secret_key=os.getenv("PRISMA_SECRET_KEY")
    )
    
    integration = SailPointPrismaCloudIntegration(sailpoint, prisma)
    
    # Sync identities to Prisma Cloud
    integration.sync_sailpoint_identities_to_prisma()
    
    # Sync violations
    integration.sync_violations_to_prisma()
```

# 4.2 Prisma Cloud Alerts from SailPoint Violations

```python
#!/usr/bin/env python3
"""
Prisma Cloud Alert Creation from SailPoint Violations
Purpose: Create Prisma Cloud alerts based on SailPoint policy violations
"""

class SailPointPrismaAlertIntegration:
    """Create Prisma Cloud alerts from SailPoint violations"""
    
    def __init__(self, sailpoint_client, prisma_client):
        self.sailpoint = sailpoint_client
        self.prisma = prisma_client
    
    def create_prisma_alert_from_violation(self, violation: Dict) -> Dict:
        """Create Prisma Cloud alert from SailPoint violation"""
        violation_type = violation.get('policy', {}).get('type')
        identity_id = violation.get('identity', {}).get('id')
        policy_name = violation.get('policy', {}).get('name')
        
        # Determine if this should create an alert
        if not self.should_create_alert(violation_type):
            return None
        
        # Get identity details
        try:
            identity = self.sailpoint.get_identity(identity_id)
            identity_name = identity.get('name', identity_id)
        except:
            identity_name = identity_id
        
        # Build alert payload
        alert = {
            "policy": {
                "name": f"SailPoint Violation: {policy_name}",
                "policyType": "config",
                "cloudType": "sailpoint",
                "severity": self.map_severity(violation_type)
            },
            "resource": {
                "id": f"sailpoint-identity:{identity_id}",
                "name": identity_name,
                "cloudType": "sailpoint",
                "resourceType": "identity"
            },
            "alertTime": violation.get('created'),
            "description": f"""
            SailPoint Policy Violation Detected
            
            Violation Type: {violation_type}
            Policy: {policy_name}
            Identity: {identity_name}
            Status: {violation.get('status')}
            
            This alert was automatically created from SailPoint policy violation.
            """,
            "customFields": {
                "sailpoint_violation_id": violation.get('id'),
                "sailpoint_policy_name": policy_name,
                "sailpoint_violation_type": violation_type,
                "sailpoint_identity_id": identity_id
            }
        }
        
        # Create alert in Prisma Cloud
        return self.prisma.create_alert(alert)
    
    def should_create_alert(self, violation_type: str) -> bool:
        """Determine if violation should create an alert"""
        alert_worthy_types = [
            'SEGREGATION_OF_DUTY',
            'PRIVILEGED_ACCESS',
            'ORPHANED_ACCOUNT',
            'EXCESSIVE_ACCESS'
        ]
        return violation_type in alert_worthy_types
    
    def map_severity(self, violation_type: str) -> str:
        """Map violation type to Prisma Cloud severity"""
        severity_map = {
            'SEGREGATION_OF_DUTY': 'high',
            'PRIVILEGED_ACCESS': 'high',
            'ORPHANED_ACCOUNT': 'medium',
            'EXCESSIVE_ACCESS': 'medium'
        }
        return severity_map.get(violation_type, 'low')
```

---

# Webhook Integrations

# 5.1 SailPoint Event Triggers to XDR/XSOAR/Prisma

```python
#!/usr/bin/env python3
"""
SailPoint Event Triggers Integration
Purpose: Receive SailPoint webhooks and route to security platforms
"""

from flask import Flask, request, jsonify
import requests
import os

app = Flask(__name__)

# Initialize clients (would be done in production setup)
# sailpoint_client = SailPointClient(...)
# xdr_client = CortexXDRClient(...)
# xsoar_client = XSOARClient(...)
# prisma_client = PrismaCloudClient(...)

@app.route('/sailpoint/webhook', methods=['POST'])
def sailpoint_webhook():
    """Receive SailPoint Event Trigger"""
    try:
        # Verify webhook signature
        if not verify_sailpoint_webhook(request):
            return jsonify({"error": "Invalid signature"}), 401
        
        data = request.json
        event_type = data.get('type')
        
        # Route to appropriate handler
        if 'violation' in event_type.lower():
            handle_violation_event(data)
        elif 'access.request' in event_type.lower():
            handle_access_request_event(data)
        elif 'identity' in event_type.lower():
            handle_identity_event(data)
        elif 'certification' in event_type.lower():
            handle_certification_event(data)
        
        return jsonify({"status": "success"}), 200
    
    except Exception as e:
        print(f"Webhook error: {e}")
        return jsonify({"error": str(e)}), 500

def verify_sailpoint_webhook(request) -> bool:
    """Verify SailPoint webhook signature"""
    # Implementation would verify the webhook signature
    # using SailPoint's webhook verification method
    return True

def handle_violation_event(event: dict):
    """Handle violation events"""
    violation_id = event.get('violation', {}).get('id')
    violation = sailpoint_client.get_violations()[0]  # Simplified - would fetch by ID
    
    # Send to XDR
    xdr_integration = SailPointXDRIntegration(sailpoint_client, xdr_client)
    xdr_integration.process_violation(violation)
    
    # Send to XSOAR
    xsoar_integration = SailPointXSOARIntegration(sailpoint_client, xsoar_client)
    xsoar_integration.create_xsoar_incident_from_violation(violation)
    
    # Send to Prisma Cloud
    prisma_integration = SailPointPrismaAlertIntegration(sailpoint_client, prisma_client)
    prisma_integration.create_prisma_alert_from_violation(violation)

def handle_access_request_event(event: dict):
    """Handle access request events"""
    request_id = event.get('request', {}).get('id')
    access_request = sailpoint_client.get_access_requests()[0]  # Simplified
    
    # Check for suspicious requests
    xdr_integration = SailPointXDRIntegration(sailpoint_client, xdr_client)
    xdr_integration.sync_access_request_to_xdr(access_request)

def handle_identity_event(event: dict):
    """Handle identity lifecycle events"""
    identity_id = event.get('identity', {}).get('id')
    
    # Update Prisma Cloud CIEM
    prisma_integration = SailPointPrismaCloudIntegration(sailpoint_client, prisma_client)
    identity = sailpoint_client.get_identity(identity_id)
    identity_data = prisma_integration.build_identity_access_data(identity)
    prisma_integration.send_to_prisma_ciem(identity_data)

def handle_certification_event(event: dict):
    """Handle certification events"""
    certification_id = event.get('certification', {}).get('id')
    
    # Create XSOAR incident for overdue certifications
    xsoar_integration = SailPointXSOARIntegration(sailpoint_client, xsoar_client)
    xsoar_integration.sync_certification_to_xsoar(certification_id)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')
```

---

# Use Cases and Workflows

# 6.1 Complete Workflow: Segregation of Duty Violation

```python
#!/usr/bin/env python3
"""
Complete Workflow: Segregation of Duty Violation Detection and Response
Purpose: End-to-end workflow from detection to remediation
"""

class SODViolationWorkflow:
    """Complete workflow for SOD violation handling"""
    
    def __init__(self, sailpoint_client, xdr_client, xsoar_client, prisma_client):
        self.sailpoint = sailpoint_client
        self.xdr = xdr_client
        self.xsoar = xsoar_client
        self.prisma = prisma_client
    
    def execute_workflow(self, violation: Dict):
        """Execute complete SOD violation workflow"""
        
        violation_type = violation.get('policy', {}).get('type')
        if violation_type != 'SEGREGATION_OF_DUTY':
            return
        
        identity_id = violation.get('identity', {}).get('id')
        
        # Step 1: Gather intelligence
        intelligence = self.gather_intelligence(identity_id, violation)
        
        # Step 2: Create incidents in all platforms
        xdr_incident = self.create_xdr_incident(violation, intelligence)
        xsoar_incident = self.create_xsoar_incident(violation, intelligence)
        prisma_alert = self.create_prisma_alert(violation, intelligence)
        
        # Step 3: Automated response
        response_action = self.determine_response(intelligence)
        self.execute_response(identity_id, violation, response_action)
        
        # Step 4: Notify stakeholders
        self.notify_stakeholders(violation, intelligence, response_action)
        
        return {
            "xdr_incident": xdr_incident,
            "xsoar_incident": xsoar_incident,
            "prisma_alert": prisma_alert,
            "response_action": response_action
        }
    
    def gather_intelligence(self, identity_id: str, violation: Dict) -> Dict:
        """Gather intelligence about the identity and violation"""
        identity = self.sailpoint.get_identity(identity_id)
        access = self.sailpoint.get_identity_access(identity_id)
        violations = self.sailpoint.get_violations(identity_id=identity_id)
        
        return {
            "identity": identity,
            "access": access,
            "violations": violations,
            "risk_score": self.calculate_risk_score(identity, access, violations)
        }
    
    def calculate_risk_score(self, identity: Dict, access: List, violations: List) -> int:
        """Calculate risk score"""
        score = 0
        
        # SOD violation is critical
        score += 5
        
        # Multiple violations
        if len(violations) > 3:
            score += 2
        
        # Excessive access
        if len(access) > 15:
            score += 2
        
        return min(score, 10)
    
    def determine_response(self, intelligence: Dict) -> str:
        """Determine response action"""
        risk_score = intelligence.get('risk_score', 0)
        
        if risk_score >= 8:
            return 'revoke_conflicting_access'
        elif risk_score >= 5:
            return 'review_and_remediate'
        else:
            return 'monitor'
    
    def execute_response(self, identity_id: str, violation: Dict, action: str):
        """Execute response action"""
        if action == 'revoke_conflicting_access':
            # Identify conflicting access items
            access = self.sailpoint.get_identity_access(identity_id)
            conflicting_items = self.identify_conflicting_access(access, violation)
            
            for item in conflicting_items:
                self.sailpoint.revoke_access(
                    identity_id,
                    item.get('id'),
                    f"Revoked due to SOD violation: {violation.get('id')}"
                )
    
    def identify_conflicting_access(self, access: List[Dict], violation: Dict) -> List[Dict]:
        """Identify access items that conflict with SOD policy"""
        # Simplified - would use SailPoint's SOD analysis
        return access[:1]  # Return first item as example
    
    def notify_stakeholders(self, violation: Dict, intelligence: Dict, action: str):
        """Notify security team and stakeholders"""
        # Implementation would send notifications via Slack, email, etc.
        pass
```

---

# Configuration and Setup

# 7.1 Environment Variables

```bash
# SailPoint Configuration
export SAILPOINT_TENANT="yourtenant"
export SAILPOINT_CLIENT_ID="your-client-id"
export SAILPOINT_CLIENT_SECRET="your-client-secret"

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
# sailpoint_integrations_config.yaml
sailpoint:
  tenant: "${SAILPOINT_TENANT}"
  client_id: "${SAILPOINT_CLIENT_ID}"
  client_secret: "${SAILPOINT_CLIENT_SECRET}"
  
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
    sync_identities: true
    sync_violations: true

violation_routing:
  SEGREGATION_OF_DUTY:
    - cortex_xdr
    - xsoar
    - prisma_cloud
  PRIVILEGED_ACCESS:
    - cortex_xdr
    - xsoar
  ORPHANED_ACCOUNT:
    - xsoar
    - prisma_cloud
  EXCESSIVE_ACCESS:
    - xsoar

automated_responses:
  enabled: true
  actions:
    revoke_access:
      trigger_severity: "critical"
      require_approval: true
    create_certification_review:
      trigger_severity: "high"
      require_approval: false
```

---

# Troubleshooting

# Common Issues and Solutions

## 1. Authentication Failures

**Problem**: SailPoint API authentication fails

**Solutions**:
- Verify client ID and secret are correct
- Check OAuth token expiration (tokens expire after 1 hour)
- Ensure client has required scopes in SailPoint
- Verify tenant name is correct (format: `yourtenant`)

## 2. Rate Limiting

**Problem**: API rate limits exceeded

**Solutions**:
- Implement exponential backoff
- Use pagination for large result sets
- Cache frequently accessed data
- Batch requests when possible
- Respect SailPoint's rate limits (typically 100 requests per minute)

## 3. Webhook Delivery Failures

**Problem**: Webhooks not being received

**Solutions**:
- Verify webhook URL is publicly accessible
- Check firewall rules allow inbound connections
- Validate webhook signature verification
- Implement retry logic for failed deliveries
- Check Event Trigger configuration in SailPoint

## 4. Violation Filtering Issues

**Problem**: Too many or too few violations being processed

**Solutions**:
- Refine violation filters in `get_violations()` method
- Adjust severity thresholds in configuration
- Use more specific violation type filters
- Implement violation deduplication logic

## 5. Identity Lookup Failures

**Problem**: Cannot find identity by ID

**Solutions**:
- Verify identity exists and is active
- Check identity ID format
- Use search API for name/email lookups
- Handle case sensitivity in searches

---

# Best Practices

1. **OAuth Token Management**: Implement automatic token refresh (tokens expire after 1 hour)
2. **Error Handling**: Implement comprehensive error handling and logging
3. **Rate Limiting**: Respect SailPoint API rate limits
4. **Violation Deduplication**: Implement logic to prevent processing duplicate violations
5. **Monitoring**: Monitor integration health and API usage
6. **Testing**: Test integrations in non-production environments first
7. **Documentation**: Document custom mappings and configurations
8. **Audit Logging**: Log all actions taken via integrations

---

# API Reference

## SailPoint IdentityNow API Endpoints Used

- `GET /v3/identities` - List/search identities
- `GET /v3/identities/{id}` - Get identity details
- `GET /v3/identities/{id}/access` - Get identity access
- `GET /v3/accounts` - List accounts
- `GET /v3/access-profiles` - List access profiles
- `GET /v3/roles` - List roles
- `GET /v3/certifications` - List certification campaigns
- `GET /v3/access-requests` - List access requests
- `GET /v3/policy-violations` - List policy violations
- `GET /v3/events` - Get audit events
- `POST /v3/identities/{id}/access-items/{itemId}/revoke` - Revoke access
- `POST /v3/access-requests` - Create access request

## Required SailPoint OAuth Scopes

- `sp:scopes:default` - Default scope for API access
- `sp:identities:read` - Read identity information
- `sp:identities:manage` - Manage identity lifecycle
- `sp:access:read` - Read access information
- `sp:access:manage` - Manage access
- `sp:certifications:read` - Read certification data
- `sp:violations:read` - Read policy violations

---

Version: 1.0  
Last Updated: 2026-01-09  
Maintained By: SOC Team
