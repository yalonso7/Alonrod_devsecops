# AWS IAM Integrations Standard Operating Procedure (SOP)

# Table of Contents

1. [Overview](#overview)
2. [AWS IAM API Integration Basics](#aws-iam-api-integration-basics)
3. [AWS IAM to Cortex XDR Integration](#aws-iam-to-cortex-xdr-integration)
4. [AWS IAM to XSOAR Integration](#aws-iam-to-xsoar-integration)
5. [AWS IAM to Prisma Cloud Integration](#aws-iam-to-prisma-cloud-integration)
6. [CloudTrail Event Monitoring](#cloudtrail-event-monitoring)
7. [Webhook Integrations](#webhook-integrations)
8. [Use Cases and Workflows](#use-cases-and-workflows)
9. [Configuration and Setup](#configuration-and-setup)
10. [Troubleshooting](#troubleshooting)

---

# Overview

This SOP provides comprehensive integration code snippets and configuration examples for connecting AWS IAM (Identity and Access Management) with Palo Alto Networks security products (Cortex XDR, XSOAR, Prisma Cloud). These integrations enable automated identity-based security operations, incident response, compliance monitoring, and CIEM (Cloud Infrastructure Entitlement Management) for AWS cloud environments.

# Integration Use Cases

- IAM Threat Detection: Monitor AWS IAM events for suspicious access patterns and privilege escalations
- Automated Incident Response: Create security incidents in XDR/XSOAR based on AWS IAM security events
- Access Governance: Track IAM user and role access changes, policy modifications
- Compliance Monitoring: Monitor IAM compliance violations and policy changes
- Automated Remediation: Respond to IAM-based threats automatically (disable access keys, revoke sessions)
- CloudTrail Integration: Monitor CloudTrail logs for IAM-related security events
- CIEM Integration: Sync AWS IAM identity data to Prisma Cloud for identity governance and least privilege analysis

---

# AWS IAM API Integration Basics

# 1. AWS IAM Client (Python with boto3)

```python
#!/usr/bin/env python3
"""
AWS IAM API Integration Client
Purpose: Authenticate and interact with AWS IAM API using boto3
"""

import boto3
import json
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import os
from botocore.exceptions import ClientError

class AWSIAMClient:
    """AWS IAM API Client using boto3"""
    
    def __init__(self, 
                 aws_access_key_id: Optional[str] = None,
                 aws_secret_access_key: Optional[str] = None,
                 region_name: str = 'us-east-1',
                 session_token: Optional[str] = None):
        """
        Initialize AWS IAM client
        
        Args:
            aws_access_key_id: AWS access key ID (optional, can use IAM role)
            aws_secret_access_key: AWS secret access key (optional)
            region_name: AWS region name
            session_token: AWS session token for temporary credentials
        """
        self.iam_client = boto3.client(
            'iam',
            aws_access_key_id=aws_access_key_id or os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=aws_secret_access_key or os.getenv('AWS_SECRET_ACCESS_KEY'),
            region_name=region_name or os.getenv('AWS_REGION', 'us-east-1'),
            aws_session_token=session_token or os.getenv('AWS_SESSION_TOKEN')
        )
        
        # Initialize CloudTrail client for event monitoring
        self.cloudtrail_client = boto3.client(
            'cloudtrail',
            aws_access_key_id=aws_access_key_id or os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=aws_secret_access_key or os.getenv('AWS_SECRET_ACCESS_KEY'),
            region_name=region_name or os.getenv('AWS_REGION', 'us-east-1'),
            aws_session_token=session_token or os.getenv('AWS_SESSION_TOKEN')
        )
    
    def get_user(self, username: str) -> Dict:
        """Get IAM user details"""
        try:
            response = self.iam_client.get_user(UserName=username)
            return response.get('User', {})
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return {}
            raise
    
    def list_users(self, max_items: int = 100) -> List[Dict]:
        """List all IAM users"""
        users = []
        paginator = self.iam_client.get_paginator('list_users')
        
        for page in paginator.paginate(MaxItems=max_items):
            users.extend(page.get('Users', []))
        
        return users
    
    def get_user_policies(self, username: str) -> List[Dict]:
        """Get all policies attached to a user"""
        policies = []
        
        # Get inline policies
        try:
            inline_policies = self.iam_client.list_user_policies(UserName=username)
            for policy_name in inline_policies.get('PolicyNames', []):
                policy_doc = self.iam_client.get_user_policy(
                    UserName=username,
                    PolicyName=policy_name
                )
                policies.append({
                    'Type': 'Inline',
                    'PolicyName': policy_name,
                    'PolicyDocument': policy_doc.get('PolicyDocument', {})
                })
        except ClientError:
            pass
        
        # Get attached managed policies
        try:
            attached_policies = self.iam_client.list_attached_user_policies(UserName=username)
            for policy in attached_policies.get('AttachedPolicies', []):
                policies.append({
                    'Type': 'Managed',
                    'PolicyArn': policy.get('PolicyArn'),
                    'PolicyName': policy.get('PolicyName')
                })
        except ClientError:
            pass
        
        return policies
    
    def get_user_groups(self, username: str) -> List[Dict]:
        """Get groups for a user"""
        try:
            response = self.iam_client.get_groups_for_user(UserName=username)
            return response.get('Groups', [])
        except ClientError:
            return []
    
    def get_user_access_keys(self, username: str) -> List[Dict]:
        """Get access keys for a user"""
        try:
            response = self.iam_client.list_access_keys(UserName=username)
            access_keys = []
            
            for key_metadata in response.get('AccessKeyMetadata', []):
                key_info = self.iam_client.get_access_key_last_used(
                    AccessKeyId=key_metadata.get('AccessKeyId')
                )
                access_keys.append({
                    'AccessKeyId': key_metadata.get('AccessKeyId'),
                    'Status': key_metadata.get('Status'),
                    'CreateDate': key_metadata.get('CreateDate').isoformat() if key_metadata.get('CreateDate') else None,
                    'LastUsed': key_info.get('AccessKeyLastUsed', {})
                })
            
            return access_keys
        except ClientError:
            return []
    
    def get_role(self, role_name: str) -> Dict:
        """Get IAM role details"""
        try:
            response = self.iam_client.get_role(RoleName=role_name)
            return response.get('Role', {})
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return {}
            raise
    
    def list_roles(self, max_items: int = 100) -> List[Dict]:
        """List all IAM roles"""
        roles = []
        paginator = self.iam_client.get_paginator('list_roles')
        
        for page in paginator.paginate(MaxItems=max_items):
            roles.extend(page.get('Roles', []))
        
        return roles
    
    def get_role_policies(self, role_name: str) -> List[Dict]:
        """Get all policies attached to a role"""
        policies = []
        
        # Get inline policies
        try:
            inline_policies = self.iam_client.list_role_policies(RoleName=role_name)
            for policy_name in inline_policies.get('PolicyNames', []):
                policy_doc = self.iam_client.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
                policies.append({
                    'Type': 'Inline',
                    'PolicyName': policy_name,
                    'PolicyDocument': policy_doc.get('PolicyDocument', {})
                })
        except ClientError:
            pass
        
        # Get attached managed policies
        try:
            attached_policies = self.iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in attached_policies.get('AttachedPolicies', []):
                policies.append({
                    'Type': 'Managed',
                    'PolicyArn': policy.get('PolicyArn'),
                    'PolicyName': policy.get('PolicyName')
                })
        except ClientError:
            pass
        
        return policies
    
    def deactivate_access_key(self, username: str, access_key_id: str) -> Dict:
        """Deactivate an access key"""
        try:
            self.iam_client.update_access_key(
                UserName=username,
                AccessKeyId=access_key_id,
                Status='Inactive'
            )
            return {"status": "success", "message": f"Access key {access_key_id} deactivated"}
        except ClientError as e:
            return {"status": "error", "message": str(e)}
    
    def delete_access_key(self, username: str, access_key_id: str) -> Dict:
        """Delete an access key"""
        try:
            self.iam_client.delete_access_key(
                UserName=username,
                AccessKeyId=access_key_id
            )
            return {"status": "success", "message": f"Access key {access_key_id} deleted"}
        except ClientError as e:
            return {"status": "error", "message": str(e)}
    
    def attach_user_policy(self, username: str, policy_arn: str) -> Dict:
        """Attach a managed policy to a user"""
        try:
            self.iam_client.attach_user_policy(
                UserName=username,
                PolicyArn=policy_arn
            )
            return {"status": "success", "message": f"Policy {policy_arn} attached to {username}"}
        except ClientError as e:
            return {"status": "error", "message": str(e)}
    
    def detach_user_policy(self, username: str, policy_arn: str) -> Dict:
        """Detach a managed policy from a user"""
        try:
            self.iam_client.detach_user_policy(
                UserName=username,
                PolicyArn=policy_arn
            )
            return {"status": "success", "message": f"Policy {policy_arn} detached from {username}"}
        except ClientError as e:
            return {"status": "error", "message": str(e)}
    
    def get_cloudtrail_events(self,
                             start_time: Optional[datetime] = None,
                             end_time: Optional[datetime] = None,
                             event_names: Optional[List[str]] = None) -> List[Dict]:
        """
        Get CloudTrail events related to IAM
        
        Args:
            start_time: Start time for event query
            end_time: End time for event query
            event_names: List of event names to filter (e.g., ['CreateUser', 'AttachUserPolicy'])
        """
        if not start_time:
            start_time = datetime.now() - timedelta(hours=1)
        if not end_time:
            end_time = datetime.now()
        
        # Default IAM-related event names
        if not event_names:
            event_names = [
                'CreateUser', 'DeleteUser', 'UpdateUser',
                'CreateAccessKey', 'DeleteAccessKey', 'UpdateAccessKey',
                'AttachUserPolicy', 'DetachUserPolicy', 'PutUserPolicy',
                'CreateRole', 'DeleteRole', 'UpdateRole',
                'AttachRolePolicy', 'DetachRolePolicy', 'PutRolePolicy',
                'CreateGroup', 'DeleteGroup', 'AddUserToGroup', 'RemoveUserFromGroup',
                'AssumeRole', 'GetSessionToken'
            ]
        
        events = []
        
        try:
            for event_name in event_names:
                response = self.cloudtrail_client.lookup_events(
                    LookupAttributes=[
                        {
                            'AttributeKey': 'EventName',
                            'AttributeValue': event_name
                        }
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    MaxResults=50
                )
                
                for event in response.get('Events', []):
                    cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
                    events.append({
                        'EventId': event.get('EventId'),
                        'EventName': event.get('EventName'),
                        'EventTime': event.get('EventTime').isoformat() if event.get('EventTime') else None,
                        'Username': event.get('Username'),
                        'CloudTrailEvent': cloud_trail_event,
                        'Resources': event.get('Resources', [])
                    })
        except ClientError as e:
            print(f"Error getting CloudTrail events: {e}")
        
        return events
    
    def get_security_events(self,
                           start_time: Optional[datetime] = None,
                           limit: int = 100) -> List[Dict]:
        """Get security-related IAM events from CloudTrail"""
        security_event_names = [
            'CreateUser', 'DeleteUser',
            'CreateAccessKey', 'DeleteAccessKey',
            'AttachUserPolicy', 'DetachUserPolicy',
            'CreateRole', 'DeleteRole',
            'AttachRolePolicy', 'DetachRolePolicy',
            'AssumeRole', 'GetSessionToken',
            'PutUserPolicy', 'PutRolePolicy'
        ]
        
        return self.get_cloudtrail_events(
            start_time=start_time,
            event_names=security_event_names
        )

# Usage Example
if __name__ == "__main__":
    client = AWSIAMClient(
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION", "us-east-1")
    )
    
    # Get recent security events
    events = client.get_security_events(
        start_time=datetime.now() - timedelta(hours=24)
    )
    print(f"Found {len(events)} security events")
    
    # Get user details
    user = client.get_user("testuser")
    if user:
        print(f"User: {user.get('UserName')}")
        print(f"Created: {user.get('CreateDate')}")
        
        # Get user access keys
        access_keys = client.get_user_access_keys("testuser")
        print(f"Access Keys: {len(access_keys)}")
```

---

# AWS IAM to Cortex XDR Integration

# 2.1 AWS IAM Events to XDR Incidents

```python
#!/usr/bin/env python3
"""
AWS IAM to Cortex XDR Integration
Purpose: Create XDR incidents from AWS IAM security events
"""

from datetime import datetime, timedelta
from typing import Dict, List
import os
import time
import json

class AWSIAMXDRIntegration:
    """Integrate AWS IAM with Cortex XDR"""
    
    def __init__(self, iam_client, xdr_client):
        self.iam = iam_client
        self.xdr = xdr_client
    
    def monitor_iam_events(self, check_interval_minutes: int = 15):
        """Continuously monitor AWS IAM events and create XDR incidents"""
        last_check = datetime.now() - timedelta(minutes=check_interval_minutes)
        
        while True:
            try:
                # Get security events since last check
                events = self.iam.get_security_events(start_time=last_check)
                
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
        event_name = event.get('EventName')
        severity = self.determine_severity(event_name)
        
        # Only create incidents for high-severity events
        if severity in ['high', 'critical']:
            incident_data = self.create_xdr_incident_from_event(event)
            self.xdr.create_incident(incident_data)
    
    def determine_severity(self, event_name: str) -> str:
        """Determine severity based on event type"""
        critical_events = [
            'DeleteUser',
            'DeleteRole',
            'AttachUserPolicy',
            'AttachRolePolicy',
            'PutUserPolicy',
            'PutRolePolicy'
        ]
        
        high_events = [
            'CreateUser',
            'CreateRole',
            'CreateAccessKey',
            'AssumeRole',
            'DetachUserPolicy',
            'DetachRolePolicy'
        ]
        
        if event_name in critical_events:
            return 'critical'
        elif event_name in high_events:
            return 'high'
        else:
            return 'medium'
    
    def create_xdr_incident_from_event(self, event: Dict) -> Dict:
        """Create XDR incident payload from IAM event"""
        event_id = event.get('EventId')
        event_name = event.get('EventName')
        username = event.get('Username', 'Unknown')
        event_time = event.get('EventTime', datetime.now().isoformat())
        cloudtrail_event = event.get('CloudTrailEvent', {})
        
        # Extract additional details from CloudTrail event
        source_ip = cloudtrail_event.get('sourceIPAddress', 'Unknown')
        user_agent = cloudtrail_event.get('userAgent', 'Unknown')
        aws_region = cloudtrail_event.get('awsRegion', 'Unknown')
        request_params = cloudtrail_event.get('requestParameters', {})
        
        # Build incident description
        description = f"""
        AWS IAM Security Event Detected
        
        Event Type: {event_name}
        Event ID: {event_id}
        User: {username}
        Timestamp: {event_time}
        AWS Region: {aws_region}
        Source IP: {source_ip}
        User Agent: {user_agent}
        
        Request Parameters:
        {json.dumps(request_params, indent=2)}
        
        Full Event Details:
        {json.dumps(event, indent=2)}
        """
        
        return {
            "incident_name": f"AWS IAM: {event_name} - {username}",
            "severity": self.determine_severity(event_name),
            "description": description,
            "labels": [
                {"key": "source", "value": "AWS IAM"},
                {"key": "event_type", "value": event_name},
                {"key": "username", "value": username},
                {"key": "aws_region", "value": aws_region}
            ],
            "custom_fields": {
                "aws_event_id": event_id,
                "aws_event_name": event_name,
                "aws_username": username,
                "aws_region": aws_region,
                "aws_source_ip": source_ip,
                "aws_timestamp": event_time,
                "aws_request_parameters": json.dumps(request_params)
            }
        }
    
    def sync_suspicious_access_to_xdr(self, username: str, event: Dict):
        """Create XDR incident for suspicious IAM access"""
        user = self.iam.get_user(username)
        user_policies = self.iam.get_user_policies(username)
        user_groups = self.iam.get_user_groups(username)
        access_keys = self.iam.get_user_access_keys(username)
        
        # Check for suspicious patterns
        is_suspicious = self.detect_suspicious_pattern(event, user, user_policies, user_groups, access_keys)
        
        if is_suspicious:
            incident = {
                "incident_name": f"AWS IAM: Suspicious Access - {username}",
                "severity": "high",
                "description": f"""
                Suspicious IAM access detected for user: {username}
                
                User Details:
                - Username: {username}
                - Created: {user.get('CreateDate') if user else 'Unknown'}
                - Policies: {len(user_policies)}
                - Groups: {len(user_groups)}
                - Access Keys: {len(access_keys)}
                
                Event Details:
                - Event Type: {event.get('EventName')}
                - Source IP: {event.get('CloudTrailEvent', {}).get('sourceIPAddress', 'Unknown')}
                - AWS Region: {event.get('CloudTrailEvent', {}).get('awsRegion', 'Unknown')}
                - Timestamp: {event.get('EventTime', '')}
                
                Risk Indicators:
                - Unusual policy attachment
                - Access from unknown location
                - Privilege escalation attempt
                - Multiple access keys
                """,
                "labels": [
                    {"key": "source", "value": "AWS IAM"},
                    {"key": "event_type", "value": "suspicious_access"},
                    {"key": "threat_type", "value": "privilege_escalation"}
                ]
            }
            
            xdr_incident = self.xdr.create_incident(incident)
            
            # Add comment with remediation steps
            self.xdr.add_incident_comment(
                xdr_incident.get('incident_id'),
                "Recommended Actions:\n1. Review user permissions\n2. Check for unauthorized policy changes\n3. Consider deactivating access keys\n4. Review recent user activity"
            )
            
            return xdr_incident
    
    def detect_suspicious_pattern(self, event: Dict, user: Dict, policies: List[Dict], groups: List[Dict], access_keys: List[Dict]) -> bool:
        """Detect suspicious IAM access patterns"""
        event_name = event.get('EventName', '')
        cloudtrail_event = event.get('CloudTrailEvent', {})
        request_params = cloudtrail_event.get('requestParameters', {})
        
        # Check for privilege escalation
        if event_name in ['AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy', 'PutRolePolicy']:
            policy_arn = request_params.get('policyArn') or request_params.get('policyName', '')
            # Check if policy grants admin permissions
            if 'AdministratorAccess' in policy_arn or 'PowerUserAccess' in policy_arn:
                return True
        
        # Check for multiple access keys
        if len(access_keys) > 2:
            return True
        
        # Check for access from unusual location (would need IP reputation service)
        source_ip = cloudtrail_event.get('sourceIPAddress', '')
        # This is a placeholder - in production, use threat intelligence
        
        # Check for AssumeRole from unusual source
        if event_name == 'AssumeRole':
            # Check if role assumption is from unusual source
            return True
        
        return False
    
    def create_incident_for_unused_access_key(self, username: str, access_key: Dict):
        """Create XDR incident for unused or old access key"""
        access_key_id = access_key.get('AccessKeyId')
        create_date = access_key.get('CreateDate')
        last_used = access_key.get('LastUsed', {})
        
        # Check if key is old (90+ days) and unused
        if create_date:
            create_dt = datetime.fromisoformat(create_date.replace('Z', '+00:00'))
            age_days = (datetime.now(create_dt.tzinfo) - create_dt).days
            
            if age_days > 90 and not last_used.get('LastUsedDate'):
                incident = {
                    "incident_name": f"AWS IAM: Unused Access Key - {username}",
                    "severity": "medium",
                    "description": f"""
                    Unused access key detected for user: {username}
                    
                    Access Key: {access_key_id}
                    Created: {create_date}
                    Age: {age_days} days
                    Last Used: Never
                    Status: {access_key.get('Status')}
                    
                    Recommendation: Delete or deactivate this access key as it may be a security risk.
                    """,
                    "labels": [
                        {"key": "source", "value": "AWS IAM"},
                        {"key": "event_type", "value": "unused_access_key"},
                        {"key": "compliance", "value": "access_key_rotation"}
                    ]
                }
                
                return self.xdr.create_incident(incident)
        
        return None

# Usage Example
if __name__ == "__main__":
    from aws_iam_client import AWSIAMClient
    from cortex_xdr_client import CortexXDRClient
    
    # Initialize clients
    iam = AWSIAMClient(
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION", "us-east-1")
    )
    
    xdr = CortexXDRClient(
        api_key=os.getenv("XDR_API_KEY"),
        api_key_id=os.getenv("XDR_API_KEY_ID")
    )
    
    # Create integration
    integration = AWSIAMXDRIntegration(iam, xdr)
    
    # Monitor events
    integration.monitor_iam_events(check_interval_minutes=15)
```

# 2.2 Automated Response to XDR Incidents

```python
#!/usr/bin/env python3
"""
Automated Response: XDR Incident → AWS IAM Actions
Purpose: Automatically respond to XDR incidents by taking AWS IAM actions
"""

class XDRAWSIAMResponse:
    """Automated response to XDR incidents using AWS IAM"""
    
    def __init__(self, xdr_client, iam_client):
        self.xdr = xdr_client
        self.iam = iam_client
    
    def handle_xdr_incident(self, incident_id: str):
        """Handle XDR incident and take AWS IAM actions"""
        incident = self.xdr.get_incident(incident_id)
        
        # Check if incident is related to AWS IAM
        if self.is_iam_related(incident):
            username = self.extract_username(incident)
            access_key_id = self.extract_access_key_id(incident)
            
            if username:
                # Determine response action
                action = self.determine_response_action(incident)
                
                if action == 'deactivate_access_key' and access_key_id:
                    result = self.iam.deactivate_access_key(username, access_key_id)
                    self.xdr.add_incident_comment(
                        incident_id,
                        f"Automated Response: {result.get('message', 'Action completed')}"
                    )
                elif action == 'delete_access_key' and access_key_id:
                    result = self.iam.delete_access_key(username, access_key_id)
                    self.xdr.add_incident_comment(
                        incident_id,
                        f"Automated Response: {result.get('message', 'Action completed')}"
                    )
                elif action == 'detach_policy':
                    policy_arn = self.extract_policy_arn(incident)
                    if policy_arn:
                        result = self.iam.detach_user_policy(username, policy_arn)
                        self.xdr.add_incident_comment(
                            incident_id,
                            f"Automated Response: {result.get('message', 'Action completed')}"
                        )
    
    def is_iam_related(self, incident: Dict) -> bool:
        """Check if incident is AWS IAM-related"""
        labels = incident.get('labels', [])
        for label in labels:
            if label.get('key') == 'source' and label.get('value') == 'AWS IAM':
                return True
            if label.get('key') == 'threat_type') and 'privilege' in label.get('value', '').lower():
                return True
        return False
    
    def extract_username(self, incident: Dict) -> Optional[str]:
        """Extract username from incident"""
        custom_fields = incident.get('custom_fields', {})
        return custom_fields.get('aws_username')
    
    def extract_access_key_id(self, incident: Dict) -> Optional[str]:
        """Extract access key ID from incident"""
        custom_fields = incident.get('custom_fields', {})
        return custom_fields.get('aws_access_key_id')
    
    def extract_policy_arn(self, incident: Dict) -> Optional[str]:
        """Extract policy ARN from incident"""
        custom_fields = incident.get('custom_fields', {})
        request_params = custom_fields.get('aws_request_parameters', '{}')
        if isinstance(request_params, str):
            import json
            request_params = json.loads(request_params)
        return request_params.get('policyArn')
    
    def determine_response_action(self, incident: Dict) -> str:
        """Determine appropriate response action"""
        severity = incident.get('severity', 'medium')
        event_name = incident.get('custom_fields', {}).get('aws_event_name', '')
        
        if severity == 'critical':
            if 'AccessKey' in event_name:
                return 'delete_access_key'
            elif 'Policy' in event_name:
                return 'detach_policy'
        elif severity == 'high':
            if 'AccessKey' in event_name:
                return 'deactivate_access_key'
        
        return 'monitor'
```

---

# AWS IAM to XSOAR Integration

# 3.1 AWS IAM Events to XSOAR Incidents

```python
#!/usr/bin/env python3
"""
AWS IAM to XSOAR Integration
Purpose: Create XSOAR incidents from AWS IAM security events and automate playbooks
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
import os
import json

class AWSIAMXSOARIntegration:
    """Integrate AWS IAM with Cortex XSOAR"""
    
    def __init__(self, iam_client, xsoar_client):
        self.iam = iam_client
        self.xsoar = xsoar_client
    
    def create_xsoar_incident_from_event(self, event: Dict) -> Dict:
        """Create XSOAR incident from AWS IAM event"""
        event_id = event.get('EventId')
        event_name = event.get('EventName')
        username = event.get('Username', 'Unknown')
        cloudtrail_event = event.get('CloudTrailEvent', {})
        request_params = cloudtrail_event.get('requestParameters', {})
        
        # Determine incident type and severity
        incident_type, severity = self.map_event_to_incident_type(event_name)
        
        # Create incident
        incident = self.xsoar.create_incident(
            name=f"AWS IAM: {event_name} - {username}",
            severity=severity,
            type=incident_type,
            labels=[
                {"type": "source", "value": "AWS IAM"},
                {"type": "event_type", "value": event_name},
                {"type": "username", "value": username},
                {"type": "aws_region", "value": cloudtrail_event.get('awsRegion', 'Unknown')}
            ],
            custom_fields={
                "aws_event_id": event_id,
                "aws_event_name": event_name,
                "aws_username": username,
                "aws_region": cloudtrail_event.get('awsRegion', 'Unknown'),
                "aws_source_ip": cloudtrail_event.get('sourceIPAddress', 'Unknown'),
                "aws_timestamp": event.get('EventTime', ''),
                "aws_request_parameters": json.dumps(request_params)
            }
        )
        
        # Add detailed description
        description = self.build_incident_description(event, username, cloudtrail_event)
        self.xsoar.add_incident_entry(
            incident.get('id'),
            description,
            entry_type="note"
        )
        
        return incident
    
    def map_event_to_incident_type(self, event_name: str) -> tuple:
        """Map AWS IAM event type to XSOAR incident type and severity"""
        mapping = {
            'DeleteUser': ('Identity Access Management', 4),  # Critical
            'DeleteRole': ('Identity Access Management', 4),
            'AttachUserPolicy': ('Access', 4),
            'AttachRolePolicy': ('Access', 4),
            'PutUserPolicy': ('Access', 4),
            'PutRolePolicy': ('Access', 4),
            'CreateUser': ('Identity Access Management', 3),  # High
            'CreateRole': ('Identity Access Management', 3),
            'CreateAccessKey': ('Authentication', 3),
            'AssumeRole': ('Access', 3),
            'DetachUserPolicy': ('Access', 2),  # Medium
            'DetachRolePolicy': ('Access', 2),
            'DeleteAccessKey': ('Authentication', 2),
            'UpdateUser': ('Identity Access Management', 1),  # Low
            'UpdateRole': ('Identity Access Management', 1)
        }
        
        return mapping.get(event_name, ('Unclassified', 1))
    
    def build_incident_description(self, event: Dict, username: str, cloudtrail_event: Dict) -> str:
        """Build detailed incident description"""
        return f"""
# AWS IAM Security Event

# Event Information
- Event Type: {event.get('EventName')}
- Event ID: {event.get('EventId')}
- Timestamp: {event.get('EventTime', '')}
- AWS Region: {cloudtrail_event.get('awsRegion', 'Unknown')}
- Source IP: {cloudtrail_event.get('sourceIPAddress', 'Unknown')}
- User Agent: {cloudtrail_event.get('userAgent', 'Unknown')}

# User Information
- Username: {username}

# Request Parameters
```json
{json.dumps(cloudtrail_event.get('requestParameters', {}), indent=2)}
```

# Event Details
```json
{json.dumps(event, indent=2)}
```

# Recommended Actions
1. Verify user identity and authorization
2. Review recent IAM activity for this user
3. Check for related security events
4. Review user permissions and policies
5. Consider additional access controls
        """
    
    def trigger_playbook_for_event(self, event: Dict):
        """Trigger XSOAR playbook based on event type"""
        event_name = event.get('EventName')
        
        # Create incident first
        incident = self.create_xsoar_incident_from_event(event)
        
        # Trigger appropriate playbook
        if event_name in ['DeleteUser', 'DeleteRole']:
            playbook_name = "Investigate IAM User/Role Deletion"
        elif event_name in ['AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy', 'PutRolePolicy']:
            playbook_name = "Investigate IAM Policy Change"
        elif event_name == 'CreateAccessKey':
            playbook_name = "Investigate Access Key Creation"
        elif event_name == 'AssumeRole':
            playbook_name = "Investigate Role Assumption"
        else:
            playbook_name = "Generic IAM Investigation"
        
        # Execute playbook
        self.xsoar.execute_command(
            command="executePlaybook",
            arguments={
                "incidentId": incident.get('id'),
                "playbookName": playbook_name
            }
        )
    
    def sync_iam_users_to_xsoar(self):
        """Sync AWS IAM user data to XSOAR for reference"""
        users = self.iam.list_users(max_items=100)
        
        for user in users[:100]:  # Limit to first 100
            user_data = {
                "name": f"AWS IAM User: {user.get('UserName')}",
                "type": "Identity",
                "rawJSON": json.dumps(user),
                "labels": [
                    {"type": "source", "value": "AWS IAM"},
                    {"type": "user_id", "value": user.get('UserId')},
                    {"type": "username", "value": user.get('UserName')}
                ]
            }
            
            # Create or update indicator in XSOAR
            self.xsoar.execute_command(
                command="createIndicator",
                arguments=user_data
            )

# Usage Example
if __name__ == "__main__":
    from aws_iam_client import AWSIAMClient
    from xsoar_client import XSOARClient
    
    iam = AWSIAMClient(
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION", "us-east-1")
    )
    
    xsoar = XSOARClient(
        base_url=os.getenv("XSOAR_URL"),
        api_key=os.getenv("XSOAR_API_KEY")
    )
    
    integration = AWSIAMXSOARIntegration(iam, xsoar)
    
    # Get recent security events
    events = iam.get_security_events(
        start_time=datetime.now() - timedelta(hours=1)
    )
    
    # Create incidents for high-severity events
    for event in events:
        event_name = event.get('EventName')
        if event_name in ['DeleteUser', 'AttachUserPolicy', 'CreateAccessKey']:
            integration.trigger_playbook_for_event(event)
```

# 3.2 XSOAR Playbook Integration with AWS IAM

```python
#!/usr/bin/env python3
"""
XSOAR Playbook: AWS IAM User Investigation
Purpose: Automated playbook for investigating AWS IAM user events
"""

class AWSIAMInvestigationPlaybook:
    """XSOAR playbook for AWS IAM investigations"""
    
    def __init__(self, xsoar_client, iam_client):
        self.xsoar = xsoar_client
        self.iam = iam_client
    
    def execute_investigation(self, incident_id: str):
        """Execute full investigation playbook"""
        incident = self.xsoar.get_incident(incident_id)
        
        # Step 1: Extract user information
        username = incident.get('customFields', {}).get('aws_username')
        if not username:
            self.xsoar.add_incident_entry(
                incident_id,
                "Error: Could not extract username from incident",
                entry_type="note"
            )
            return
        
        # Step 2: Gather user details
        user_info = self.gather_user_information(username)
        self.xsoar.add_incident_entry(
            incident_id,
            f"User Information:\n{json.dumps(user_info, indent=2)}",
            entry_type="note"
        )
        
        # Step 3: Check user policies and groups
        policies = self.iam.get_user_policies(username)
        groups = self.iam.get_user_groups(username)
        
        self.xsoar.add_incident_entry(
            incident_id,
            f"User Policies: {len(policies)}\nUser Groups: {len(groups)}",
            entry_type="note"
        )
        
        # Step 4: Get access keys
        access_keys = self.iam.get_user_access_keys(username)
        self.xsoar.add_incident_entry(
            incident_id,
            f"Access Keys: {len(access_keys)}",
            entry_type="note"
        )
        
        # Step 5: Get recent activity
        recent_events = self.iam.get_cloudtrail_events(
            event_names=['CreateUser', 'UpdateUser', 'AttachUserPolicy', 'CreateAccessKey'],
            start_time=datetime.now() - timedelta(days=7)
        )
        user_events = [e for e in recent_events if e.get('Username') == username]
        
        self.xsoar.add_incident_entry(
            incident_id,
            f"Recent Activity: {len(user_events)} events found",
            entry_type="note"
        )
        
        # Step 6: Risk assessment
        risk_score = self.assess_risk(user_info, policies, groups, access_keys, user_events)
        
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
    
    def gather_user_information(self, username: str) -> Dict:
        """Gather comprehensive user information"""
        user = self.iam.get_user(username)
        policies = self.iam.get_user_policies(username)
        groups = self.iam.get_user_groups(username)
        access_keys = self.iam.get_user_access_keys(username)
        
        return {
            "user": {
                "username": user.get('UserName'),
                "user_id": user.get('UserId'),
                "arn": user.get('Arn'),
                "created": user.get('CreateDate').isoformat() if user.get('CreateDate') else None,
                "path": user.get('Path')
            },
            "policies": len(policies),
            "groups": [g.get('GroupName') for g in groups],
            "access_keys": len(access_keys)
        }
    
    def assess_risk(self, user_info: Dict, policies: List, groups: List, access_keys: List, events: List) -> int:
        """Assess risk score (0-10)"""
        risk = 0
        
        # Check for many policies
        if len(policies) > 5:
            risk += 2
        
        # Check for admin policies
        admin_policies = [p for p in policies if 'Administrator' in str(p.get('PolicyArn', ''))]
        if admin_policies:
            risk += 3
        
        # Check for multiple access keys
        if len(access_keys) > 2:
            risk += 2
        
        # Check for recent policy changes
        policy_events = [e for e in events if 'Policy' in e.get('EventName', '')]
        if len(policy_events) > 3:
            risk += 3
        
        return min(risk, 10)
    
    def generate_recommendations(self, risk_score: int, incident: Dict) -> str:
        """Generate recommendations based on risk score"""
        recommendations = []
        
        if risk_score >= 8:
            recommendations.append("1. IMMEDIATE: Review all user permissions")
            recommendations.append("2. Deactivate unused access keys")
            recommendations.append("3. Review recent policy changes")
            recommendations.append("4. Consider removing unnecessary permissions")
            recommendations.append("5. Notify security team")
        elif risk_score >= 5:
            recommendations.append("1. Review user policies")
            recommendations.append("2. Check for unused access keys")
            recommendations.append("3. Implement least privilege principles")
            recommendations.append("4. Monitor user activity")
        else:
            recommendations.append("1. Monitor user activity")
            recommendations.append("2. Review access patterns")
        
        return "\n".join(recommendations)
```

---

# AWS IAM to Prisma Cloud Integration

# 4.1 AWS IAM Identity Data to Prisma Cloud CIEM

```python
#!/usr/bin/env python3
"""
AWS IAM to Prisma Cloud CIEM Integration
Purpose: Sync AWS IAM user and role access data to Prisma Cloud for identity governance
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
import os
import json
import requests

class AWSIAMPrismaCloudIntegration:
    """Integrate AWS IAM with Prisma Cloud CIEM"""
    
    def __init__(self, iam_client, prisma_client):
        self.iam = iam_client
        self.prisma = prisma_client
    
    def sync_iam_users_to_prisma(self):
        """Sync AWS IAM users and their access to Prisma Cloud"""
        # Get all IAM users
        users = self.iam.list_users(max_items=1000)
        
        for user in users:
            user_data = self.build_user_access_data(user)
            self.send_to_prisma_ciem(user_data)
    
    def build_user_access_data(self, user: Dict) -> Dict:
        """Build user access data structure for Prisma Cloud"""
        username = user.get('UserName')
        user_id = user.get('UserId')
        user_arn = user.get('Arn')
        
        # Get user policies
        policies = self.iam.get_user_policies(username)
        policy_arns = [p.get('PolicyArn') for p in policies if p.get('Type') == 'Managed']
        inline_policies = [p.get('PolicyName') for p in policies if p.get('Type') == 'Inline']
        
        # Get user groups
        groups = self.iam.get_user_groups(username)
        group_names = [g.get('GroupName') for g in groups]
        
        # Get access keys
        access_keys = self.iam.get_user_access_keys(username)
        active_keys = [k for k in access_keys if k.get('Status') == 'Active']
        
        # Calculate effective permissions
        effective_permissions = self.calculate_effective_permissions(policies, groups)
        
        return {
            "identity_id": user_arn,
            "identity_type": "user",
            "identity_name": username,
            "source": "AWS IAM",
            "status": "ACTIVE",  # AWS IAM users don't have explicit status
            "arn": user_arn,
            "user_id": user_id,
            "policies": {
                "managed": policy_arns,
                "inline": inline_policies,
                "count": len(policies)
            },
            "groups": group_names,
            "access_keys": {
                "total": len(access_keys),
                "active": len(active_keys),
                "inactive": len(access_keys) - len(active_keys)
            },
            "effective_permissions": effective_permissions,
            "created_at": user.get('CreateDate').isoformat() if user.get('CreateDate') else None,
            "metadata": {
                "aws_user_id": user_id,
                "aws_username": username,
                "path": user.get('Path', '/'),
                "password_last_used": user.get('PasswordLastUsed').isoformat() if user.get('PasswordLastUsed') else None
            }
        }
    
    def sync_iam_roles_to_prisma(self):
        """Sync AWS IAM roles and their access to Prisma Cloud"""
        # Get all IAM roles
        roles = self.iam.list_roles(max_items=1000)
        
        for role in roles:
            role_data = self.build_role_access_data(role)
            self.send_to_prisma_ciem(role_data)
    
    def build_role_access_data(self, role: Dict) -> Dict:
        """Build role access data structure for Prisma Cloud"""
        role_name = role.get('RoleName')
        role_id = role.get('RoleId')
        role_arn = role.get('Arn')
        
        # Get role policies
        policies = self.iam.get_role_policies(role_name)
        policy_arns = [p.get('PolicyArn') for p in policies if p.get('Type') == 'Managed']
        inline_policies = [p.get('PolicyName') for p in policies if p.get('Type') == 'Inline']
        
        # Get trust policy (who can assume this role)
        trust_policy = role.get('AssumeRolePolicyDocument', {})
        
        # Calculate effective permissions
        effective_permissions = self.calculate_effective_permissions(policies, [])
        
        return {
            "identity_id": role_arn,
            "identity_type": "role",
            "identity_name": role_name,
            "source": "AWS IAM",
            "status": "ACTIVE",
            "arn": role_arn,
            "role_id": role_id,
            "policies": {
                "managed": policy_arns,
                "inline": inline_policies,
                "count": len(policies)
            },
            "trust_policy": trust_policy,
            "effective_permissions": effective_permissions,
            "created_at": role.get('CreateDate').isoformat() if role.get('CreateDate') else None,
            "metadata": {
                "aws_role_id": role_id,
                "aws_role_name": role_name,
                "path": role.get('Path', '/'),
                "max_session_duration": role.get('MaxSessionDuration'),
                "description": role.get('Description')
            }
        }
    
    def calculate_effective_permissions(self, policies: List[Dict], groups: List[Dict]) -> Dict:
        """Calculate effective permissions from policies"""
        # This is a simplified version
        # In production, you would parse policy documents and calculate actual permissions
        
        permissions = {
            "actions": [],
            "resources": [],
            "admin_access": False,
            "s3_access": False,
            "ec2_access": False,
            "rds_access": False
        }
        
        for policy in policies:
            policy_arn = policy.get('PolicyArn', '')
            policy_name = policy.get('PolicyName', '')
            
            # Check for admin access
            if 'AdministratorAccess' in policy_arn or 'AdministratorAccess' in policy_name:
                permissions["admin_access"] = True
            
            # Check for service-specific access
            if 'S3' in policy_arn or 's3' in policy_name.lower():
                permissions["s3_access"] = True
            if 'EC2' in policy_arn or 'ec2' in policy_name.lower():
                permissions["ec2_access"] = True
            if 'RDS' in policy_arn or 'rds' in policy_name.lower():
                permissions["rds_access"] = True
        
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
    
    def sync_iam_events_to_prisma(self, hours: int = 24):
        """Sync AWS IAM security events to Prisma Cloud"""
        start_time = datetime.now() - timedelta(hours=hours)
        events = self.iam.get_security_events(start_time=start_time)
        
        for event in events:
            event_data = self.build_event_data(event)
            self.send_event_to_prisma(event_data)
    
    def build_event_data(self, event: Dict) -> Dict:
        """Build event data structure for Prisma Cloud"""
        cloudtrail_event = event.get('CloudTrailEvent', {})
        
        return {
            "event_id": event.get('EventId'),
            "event_type": event.get('EventName'),
            "timestamp": event.get('EventTime'),
            "source": "AWS IAM",
            "user_id": event.get('Username'),
            "ip_address": cloudtrail_event.get('sourceIPAddress'),
            "aws_region": cloudtrail_event.get('awsRegion'),
            "severity": self.map_event_severity(event.get('EventName')),
            "raw_event": event
        }
    
    def map_event_severity(self, event_name: str) -> str:
        """Map AWS IAM event type to severity"""
        severity_map = {
            'DeleteUser': 'high',
            'DeleteRole': 'high',
            'AttachUserPolicy': 'high',
            'AttachRolePolicy': 'high',
            'PutUserPolicy': 'high',
            'PutRolePolicy': 'high',
            'CreateAccessKey': 'medium',
            'DeleteAccessKey': 'medium',
            'AssumeRole': 'low',
            'CreateUser': 'low',
            'CreateRole': 'low'
        }
        return severity_map.get(event_name, 'low')
    
    def send_event_to_prisma(self, event_data: Dict):
        """Send event to Prisma Cloud"""
        url = f"{self.prisma.api_url}/v2/event"
        
        response = requests.post(
            url,
            json=event_data,
            headers=self.prisma._get_headers()
        )
        
        return response.status_code == 200
    
    def correlate_iam_access_with_cloud_resources(self, username: str):
        """Correlate AWS IAM user access with cloud resources in Prisma"""
        # Get user from IAM
        user = self.iam.get_user(username)
        policies = self.iam.get_user_policies(username)
        groups = self.iam.get_user_groups(username)
        
        # Query Prisma Cloud for resources accessible by this user
        # This uses the user's effective permissions
        
        correlation_data = {
            "iam_user": {
                "username": username,
                "arn": user.get('Arn') if user else None,
                "policies": [p.get('PolicyArn') for p in policies if p.get('Type') == 'Managed'],
                "groups": [g.get('GroupName') for g in groups]
            },
            "cloud_resources": self.find_cloud_resources_for_user(username, policies)
        }
        
        return correlation_data
    
    def find_cloud_resources_for_user(self, username: str, policies: List[Dict]) -> List[Dict]:
        """Find cloud resources accessible by user based on IAM policies"""
        cloud_resources = []
        
        # Extract resource ARNs from policies
        resource_arns = []
        for policy in policies:
            policy_doc = policy.get('PolicyDocument', {})
            if isinstance(policy_doc, str):
                policy_doc = json.loads(policy_doc)
            
            # Extract resources from policy statements
            statements = policy_doc.get('Statement', [])
            for statement in statements:
                resources = statement.get('Resource', [])
                if isinstance(resources, str):
                    resources = [resources]
                resource_arns.extend(resources)
        
        # Query Prisma Cloud for these resources
        for resource_arn in resource_arns:
            if resource_arn != '*':
                # Query Prisma Cloud API for resource details
                resources = self.prisma.get_resources_by_arn(resource_arn)
                cloud_resources.extend(resources)
        
        return cloud_resources

# Usage Example
if __name__ == "__main__":
    from aws_iam_client import AWSIAMClient
    from prisma_cloud_client import PrismaCloudClient
    
    iam = AWSIAMClient(
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION", "us-east-1")
    )
    
    prisma = PrismaCloudClient(
        api_url=os.getenv("PRISMA_API_URL"),
        access_key=os.getenv("PRISMA_ACCESS_KEY"),
        secret_key=os.getenv("PRISMA_SECRET_KEY")
    )
    
    integration = AWSIAMPrismaCloudIntegration(iam, prisma)
    
    # Sync users to Prisma Cloud
    integration.sync_iam_users_to_prisma()
    
    # Sync roles to Prisma Cloud
    integration.sync_iam_roles_to_prisma()
    
    # Sync recent events
    integration.sync_iam_events_to_prisma(hours=24)
```

# 4.2 Prisma Cloud Alerts from AWS IAM Events

```python
#!/usr/bin/env python3
"""
Prisma Cloud Alert Creation from AWS IAM Events
Purpose: Create Prisma Cloud alerts based on AWS IAM security events
"""

class AWSIAMPrismaAlertIntegration:
    """Create Prisma Cloud alerts from AWS IAM events"""
    
    def __init__(self, iam_client, prisma_client):
        self.iam = iam_client
        self.prisma = prisma_client
    
    def create_prisma_alert_from_event(self, event: Dict) -> Dict:
        """Create Prisma Cloud alert from AWS IAM event"""
        event_name = event.get('EventName')
        username = event.get('Username', 'Unknown')
        cloudtrail_event = event.get('CloudTrailEvent', {})
        
        # Determine if this should create an alert
        if not self.should_create_alert(event_name):
            return None
        
        # Build alert payload
        alert = {
            "policy": {
                "name": f"AWS IAM Security Event: {event_name}",
                "policyType": "config",
                "cloudType": "aws",
                "severity": self.map_severity(event_name)
            },
            "resource": {
                "id": f"aws-iam-user:{username}",
                "name": username,
                "cloudType": "aws",
                "resourceType": "iam_user"
            },
            "alertTime": event.get('EventTime'),
            "description": f"""
            AWS IAM Security Event Detected
            
            Event Type: {event_name}
            User: {username}
            AWS Region: {cloudtrail_event.get('awsRegion', 'Unknown')}
            Source IP: {cloudtrail_event.get('sourceIPAddress', 'Unknown')}
            Timestamp: {event.get('EventTime', '')}
            
            This alert was automatically created from AWS IAM CloudTrail event.
            """,
            "customFields": {
                "aws_event_id": event.get('EventId'),
                "aws_event_name": event_name,
                "aws_username": username,
                "aws_region": cloudtrail_event.get('awsRegion', 'Unknown')
            }
        }
        
        # Create alert in Prisma Cloud
        return self.prisma.create_alert(alert)
    
    def create_prisma_alert_for_unused_access_key(self, username: str, access_key: Dict) -> Dict:
        """Create Prisma Cloud alert for unused access key"""
        access_key_id = access_key.get('AccessKeyId')
        create_date = access_key.get('CreateDate')
        
        if create_date:
            create_dt = datetime.fromisoformat(create_date.replace('Z', '+00:00'))
            age_days = (datetime.now(create_dt.tzinfo) - create_dt).days
            
            if age_days > 90 and not access_key.get('LastUsed', {}).get('LastUsedDate'):
                alert = {
                    "policy": {
                        "name": "AWS IAM: Unused Access Key",
                        "policyType": "config",
                        "cloudType": "aws",
                        "severity": "medium"
                    },
                    "resource": {
                        "id": f"aws-iam-access-key:{access_key_id}",
                        "name": f"{username}/{access_key_id}",
                        "cloudType": "aws",
                        "resourceType": "iam_access_key"
                    },
                    "alertTime": datetime.now().isoformat(),
                    "description": f"""
                    Unused AWS IAM Access Key Detected
                    
                    User: {username}
                    Access Key: {access_key_id}
                    Age: {age_days} days
                    Last Used: Never
                    
                    Recommendation: Delete or deactivate this access key.
                    """,
                    "customFields": {
                        "aws_username": username,
                        "aws_access_key_id": access_key_id,
                        "key_age_days": age_days,
                        "compliance_issue": "access_key_rotation"
                    }
                }
                
                return self.prisma.create_alert(alert)
        
        return None
    
    def create_prisma_alert_for_excessive_permissions(self, username: str, policies: List[Dict]) -> Dict:
        """Create Prisma Cloud alert for user with excessive permissions"""
        # Check for admin access
        admin_policies = [p for p in policies if 'Administrator' in str(p.get('PolicyArn', ''))]
        
        if admin_policies:
            alert = {
                "policy": {
                    "name": "AWS IAM: Excessive Permissions",
                    "policyType": "config",
                    "cloudType": "aws",
                    "severity": "high"
                },
                "resource": {
                    "id": f"aws-iam-user:{username}",
                    "name": username,
                    "cloudType": "aws",
                    "resourceType": "iam_user"
                },
                "alertTime": datetime.now().isoformat(),
                "description": f"""
                AWS IAM User with Excessive Permissions Detected
                
                User: {username}
                Admin Policies: {len(admin_policies)}
                
                Recommendation: Review and apply least privilege principles.
                """,
                "customFields": {
                    "aws_username": username,
                    "admin_policy_count": len(admin_policies),
                    "compliance_issue": "least_privilege"
                }
            }
            
            return self.prisma.create_alert(alert)
        
        return None
    
    def should_create_alert(self, event_name: str) -> bool:
        """Determine if event should create an alert"""
        alert_worthy_events = [
            'DeleteUser',
            'DeleteRole',
            'AttachUserPolicy',
            'AttachRolePolicy',
            'PutUserPolicy',
            'PutRolePolicy',
            'CreateAccessKey'
        ]
        return event_name in alert_worthy_events
    
    def map_severity(self, event_name: str) -> str:
        """Map event type to Prisma Cloud severity"""
        severity_map = {
            'DeleteUser': 'high',
            'DeleteRole': 'high',
            'AttachUserPolicy': 'high',
            'AttachRolePolicy': 'high',
            'PutUserPolicy': 'high',
            'PutRolePolicy': 'high',
            'CreateAccessKey': 'medium'
        }
        return severity_map.get(event_name, 'low')
```

# 4.3 Least Privilege Analysis with Prisma Cloud

```python
#!/usr/bin/env python3
"""
Least Privilege Analysis with Prisma Cloud
Purpose: Analyze AWS IAM permissions and generate least privilege recommendations
"""

class AWSIAMLeastPrivilegeAnalysis:
    """Analyze IAM permissions for least privilege compliance"""
    
    def __init__(self, iam_client, prisma_client):
        self.iam = iam_client
        self.prisma = prisma_client
    
    def analyze_user_permissions(self, username: str) -> Dict:
        """Analyze user permissions and generate recommendations"""
        user = self.iam.get_user(username)
        policies = self.iam.get_user_policies(username)
        groups = self.iam.get_user_groups(username)
        access_keys = self.iam.get_user_access_keys(username)
        
        # Get usage data from Prisma Cloud
        usage_data = self.prisma.get_identity_usage_data(user.get('Arn'))
        
        # Analyze permissions
        analysis = {
            "user": username,
            "arn": user.get('Arn'),
            "current_permissions": self.analyze_permissions(policies),
            "used_permissions": usage_data.get('used_permissions', []),
            "unused_permissions": [],
            "recommendations": []
        }
        
        # Find unused permissions
        analysis["unused_permissions"] = self.find_unused_permissions(
            analysis["current_permissions"],
            analysis["used_permissions"]
        )
        
        # Generate recommendations
        analysis["recommendations"] = self.generate_recommendations(analysis)
        
        # Send to Prisma Cloud
        self.send_analysis_to_prisma(analysis)
        
        return analysis
    
    def analyze_permissions(self, policies: List[Dict]) -> List[str]:
        """Extract permissions from policies"""
        permissions = []
        
        for policy in policies:
            policy_doc = policy.get('PolicyDocument', {})
            if isinstance(policy_doc, str):
                policy_doc = json.loads(policy_doc)
            
            statements = policy_doc.get('Statement', [])
            for statement in statements:
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                permissions.extend(actions)
        
        return list(set(permissions))  # Remove duplicates
    
    def find_unused_permissions(self, current: List[str], used: List[str]) -> List[str]:
        """Find permissions that are granted but not used"""
        return [p for p in current if p not in used]
    
    def generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate least privilege recommendations"""
        recommendations = []
        
        unused_count = len(analysis.get('unused_permissions', []))
        if unused_count > 0:
            recommendations.append(f"Remove {unused_count} unused permissions")
        
        # Check for wildcard permissions
        wildcard_perms = [p for p in analysis.get('current_permissions', []) if '*' in p]
        if wildcard_perms:
            recommendations.append(f"Replace {len(wildcard_perms)} wildcard permissions with specific actions")
        
        # Check for admin access
        admin_perms = [p for p in analysis.get('current_permissions', []) if 'Administrator' in p or '*:*' in p]
        if admin_perms:
            recommendations.append("Consider replacing admin access with specific permissions")
        
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
    from aws_iam_client import AWSIAMClient
    from prisma_cloud_client import PrismaCloudClient
    
    iam = AWSIAMClient(
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION", "us-east-1")
    )
    
    prisma = PrismaCloudClient(
        api_url=os.getenv("PRISMA_API_URL"),
        access_key=os.getenv("PRISMA_ACCESS_KEY"),
        secret_key=os.getenv("PRISMA_SECRET_KEY")
    )
    
    analyzer = AWSIAMLeastPrivilegeAnalysis(iam, prisma)
    
    # Analyze user permissions
    analysis = analyzer.analyze_user_permissions("testuser")
    print(f"Unused permissions: {len(analysis.get('unused_permissions', []))}")
    print(f"Recommendations: {analysis.get('recommendations', [])}")
```

---

# CloudTrail Event Monitoring

# 4.1 Real-time CloudTrail Event Processing

```python
#!/usr/bin/env python3
"""
Real-time CloudTrail Event Processing
Purpose: Process CloudTrail events in real-time for IAM monitoring
"""

from datetime import datetime
from typing import Dict, List
import json

class CloudTrailEventProcessor:
    """Process CloudTrail events for IAM monitoring"""
    
    def __init__(self, iam_client, xdr_client, xsoar_client):
        self.iam = iam_client
        self.xdr = xdr_client
        self.xsoar = xsoar_client
    
    def process_cloudtrail_event(self, event: Dict):
        """Process a single CloudTrail event"""
        event_name = event.get('detail', {}).get('eventName', '')
        event_source = event.get('detail', {}).get('eventSource', '')
        
        # Only process IAM events
        if event_source != 'iam.amazonaws.com':
            return
        
        # Check if this is a security-relevant event
        if self.is_security_event(event_name):
            # Create incidents in both XDR and XSOAR
            self.create_incidents_from_event(event)
    
    def is_security_event(self, event_name: str) -> bool:
        """Check if event is security-relevant"""
        security_events = [
            'CreateUser', 'DeleteUser', 'UpdateUser',
            'CreateAccessKey', 'DeleteAccessKey', 'UpdateAccessKey',
            'AttachUserPolicy', 'DetachUserPolicy', 'PutUserPolicy',
            'CreateRole', 'DeleteRole', 'UpdateRole',
            'AttachRolePolicy', 'DetachRolePolicy', 'PutRolePolicy',
            'AssumeRole', 'GetSessionToken'
        ]
        return event_name in security_events
    
    def create_incidents_from_event(self, event: Dict):
        """Create incidents in XDR and XSOAR from CloudTrail event"""
        detail = event.get('detail', {})
        event_name = detail.get('eventName')
        username = detail.get('userIdentity', {}).get('userName', 'Unknown')
        
        # Create XDR incident
        xdr_integration = AWSIAMXDRIntegration(self.iam, self.xdr)
        xdr_event = {
            'EventId': detail.get('eventID'),
            'EventName': event_name,
            'Username': username,
            'EventTime': detail.get('eventTime'),
            'CloudTrailEvent': detail
        }
        xdr_integration.process_iam_event(xdr_event)
        
        # Create XSOAR incident
        xsoar_integration = AWSIAMXSOARIntegration(self.iam, self.xsoar)
        xsoar_integration.create_xsoar_incident_from_event(xdr_event)

# Usage with AWS EventBridge
"""
This processor can be used with AWS EventBridge to process CloudTrail events in real-time.
Configure EventBridge rule to forward CloudTrail events to Lambda function that calls this processor.
"""
```

---

# Webhook Integrations

# 5.1 AWS EventBridge to XDR/XSOAR Webhook

```python
#!/usr/bin/env python3
"""
AWS EventBridge Webhook Integration
Purpose: Receive AWS EventBridge events and route to XDR/XSOAR
"""

from flask import Flask, request, jsonify
import os
import json

app = Flask(__name__)

# Initialize clients (would be done in production setup)
# iam_client = AWSIAMClient(...)
# xdr_client = CortexXDRClient(...)
# xsoar_client = XSOARClient(...)

@app.route('/aws/eventbridge', methods=['POST'])
def eventbridge_webhook():
    """Receive AWS EventBridge webhook"""
    try:
        # Verify webhook signature (implement AWS signature verification)
        if not verify_aws_signature(request):
            return jsonify({"error": "Invalid signature"}), 401
        
        data = request.json
        event_source = data.get('source', '')
        detail = data.get('detail', {})
        event_name = detail.get('eventName', '')
        
        # Only process IAM events
        if event_source == 'aws.iam' or detail.get('eventSource') == 'iam.amazonaws.com':
            handle_iam_event(data)
        
        return jsonify({"status": "success"}), 200
    
    except Exception as e:
        print(f"Webhook error: {e}")
        return jsonify({"error": str(e)}), 500

def verify_aws_signature(request) -> bool:
    """Verify AWS webhook signature"""
    # Implementation would verify the webhook signature
    # using AWS's signature verification method
    return True

def handle_iam_event(event: dict):
    """Handle IAM-related events"""
    detail = event.get('detail', {})
    event_name = detail.get('eventName', '')
    
    # Route to appropriate handler
    if event_name in ['CreateUser', 'DeleteUser', 'UpdateUser']:
        handle_user_lifecycle_event(event)
    elif event_name in ['CreateAccessKey', 'DeleteAccessKey', 'UpdateAccessKey']:
        handle_access_key_event(event)
    elif 'Policy' in event_name:
        handle_policy_event(event)
    elif event_name in ['AssumeRole', 'GetSessionToken']:
        handle_authentication_event(event)

def handle_user_lifecycle_event(event: dict):
    """Handle user lifecycle events"""
    # Send to XDR
    xdr_integration = AWSIAMXDRIntegration(iam_client, xdr_client)
    xdr_integration.process_iam_event(convert_to_xdr_format(event))
    
    # Send to XSOAR
    xsoar_integration = AWSIAMXSOARIntegration(iam_client, xsoar_client)
    xsoar_integration.create_xsoar_incident_from_event(convert_to_xdr_format(event))

def handle_access_key_event(event: dict):
    """Handle access key events"""
    # Send to XDR
    xdr_integration = AWSIAMXDRIntegration(iam_client, xdr_client)
    xdr_integration.process_iam_event(convert_to_xdr_format(event))
    
    # Send to XSOAR
    xsoar_integration = AWSIAMXSOARIntegration(iam_client, xsoar_client)
    xsoar_integration.create_xsoar_incident_from_event(convert_to_xdr_format(event))
    
    # Trigger playbook for access key creation
    if event.get('detail', {}).get('eventName') == 'CreateAccessKey':
        xsoar_integration.trigger_playbook_for_event(convert_to_xdr_format(event))

def handle_policy_event(event: dict):
    """Handle policy events"""
    # Send to XDR
    xdr_integration = AWSIAMXDRIntegration(iam_client, xdr_client)
    xdr_integration.process_iam_event(convert_to_xdr_format(event))
    
    # Send to XSOAR
    xsoar_integration = AWSIAMXSOARIntegration(iam_client, xsoar_client)
    xsoar_integration.trigger_playbook_for_event(convert_to_xdr_format(event))

def handle_authentication_event(event: dict):
    """Handle authentication events"""
    # Check for suspicious patterns
    if is_suspicious_assume_role(event):
        xdr_integration = AWSIAMXDRIntegration(iam_client, xdr_client)
        username = event.get('detail', {}).get('userIdentity', {}).get('userName', '')
        xdr_integration.sync_suspicious_access_to_xdr(username, convert_to_xdr_format(event))

def convert_to_xdr_format(event: dict) -> dict:
    """Convert EventBridge event to XDR format"""
    detail = event.get('detail', {})
    return {
        'EventId': detail.get('eventID'),
        'EventName': detail.get('eventName'),
        'Username': detail.get('userIdentity', {}).get('userName', 'Unknown'),
        'EventTime': detail.get('eventTime'),
        'CloudTrailEvent': detail
    }

def is_suspicious_assume_role(event: dict) -> bool:
    """Determine if AssumeRole is suspicious"""
    # Check for unusual source IP, time, etc.
    detail = event.get('detail', {})
    source_ip = detail.get('sourceIPAddress', '')
    # Add more sophisticated checks
    return False

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
    
    def __init__(self, iam_client, xdr_client, xsoar_client):
        self.iam = iam_client
        self.xdr = xdr_client
        self.xsoar = xsoar_client
    
    def execute_workflow(self, event: Dict):
        """Execute complete privilege escalation workflow"""
        
        # Step 1: Detect privilege escalation
        if not self.is_privilege_escalation(event):
            return
        
        username = event.get('Username', 'Unknown')
        
        # Step 2: Gather intelligence
        intelligence = self.gather_intelligence(username, event)
        
        # Step 3: Create incidents in all platforms
        xdr_incident = self.create_xdr_incident(event, intelligence)
        xsoar_incident = self.create_xsoar_incident(event, intelligence)
        
        # Step 4: Automated response
        response_action = self.determine_response(intelligence)
        self.execute_response(username, response_action, xdr_incident.get('incident_id'))
        
        # Step 5: Notify stakeholders
        self.notify_stakeholders(event, intelligence, response_action)
        
        return {
            "xdr_incident": xdr_incident,
            "xsoar_incident": xsoar_incident,
            "response_action": response_action
        }
    
    def is_privilege_escalation(self, event: Dict) -> bool:
        """Determine if event indicates privilege escalation"""
        event_name = event.get('EventName', '')
        cloudtrail_event = event.get('CloudTrailEvent', {})
        request_params = cloudtrail_event.get('requestParameters', {})
        
        # Check for policy attachment that grants admin access
        if event_name in ['AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy', 'PutRolePolicy']:
            policy_arn = request_params.get('policyArn') or request_params.get('policyName', '')
            if 'AdministratorAccess' in policy_arn or 'PowerUserAccess' in policy_arn:
                return True
        
        return False
    
    def gather_intelligence(self, username: str, event: Dict) -> Dict:
        """Gather intelligence about the user and event"""
        user = self.iam.get_user(username)
        policies = self.iam.get_user_policies(username)
        groups = self.iam.get_user_groups(username)
        access_keys = self.iam.get_user_access_keys(username)
        recent_events = self.iam.get_cloudtrail_events(
            event_names=['AttachUserPolicy', 'PutUserPolicy', 'CreateAccessKey'],
            start_time=datetime.now() - timedelta(days=7)
        )
        user_events = [e for e in recent_events if e.get('Username') == username]
        
        return {
            "user": user,
            "policies": policies,
            "groups": groups,
            "access_keys": access_keys,
            "recent_events": user_events,
            "risk_score": self.calculate_risk_score(user, policies, user_events)
        }
    
    def calculate_risk_score(self, user: Dict, policies: List, events: List) -> int:
        """Calculate risk score"""
        score = 0
        
        # Admin policies
        admin_policies = [p for p in policies if 'Administrator' in str(p.get('PolicyArn', ''))]
        score += len(admin_policies) * 3
        
        # Recent policy changes
        if len(events) > 2:
            score += 3
        
        return min(score, 10)
    
    def determine_response(self, intelligence: Dict) -> str:
        """Determine response action"""
        risk_score = intelligence.get('risk_score', 0)
        
        if risk_score >= 8:
            return 'detach_policy'
        elif risk_score >= 5:
            return 'deactivate_access_key'
        else:
            return 'monitor'
    
    def execute_response(self, username: str, action: str, incident_id: str):
        """Execute response action"""
        if action == 'detach_policy':
            # Detach admin policies
            policies = self.iam.get_user_policies(username)
            admin_policies = [p for p in policies if 'Administrator' in str(p.get('PolicyArn', ''))]
            for policy in admin_policies:
                if policy.get('Type') == 'Managed':
                    self.iam.detach_user_policy(username, policy.get('PolicyArn'))
                    self.xdr.add_incident_comment(
                        incident_id,
                        f"Automated Response: Detached policy {policy.get('PolicyArn')}"
                    )
        elif action == 'deactivate_access_key':
            # Deactivate access keys
            access_keys = self.iam.get_user_access_keys(username)
            for key in access_keys:
                if key.get('Status') == 'Active':
                    self.iam.deactivate_access_key(username, key.get('AccessKeyId'))
                    self.xdr.add_incident_comment(
                        incident_id,
                        f"Automated Response: Deactivated access key {key.get('AccessKeyId')}"
                    )
    
    def create_xdr_incident(self, event: Dict, intelligence: Dict) -> Dict:
        """Create XDR incident"""
        xdr_integration = AWSIAMXDRIntegration(self.iam, self.xdr)
        return xdr_integration.create_xdr_incident_from_event(event)
    
    def create_xsoar_incident(self, event: Dict, intelligence: Dict) -> Dict:
        """Create XSOAR incident"""
        xsoar_integration = AWSIAMXSOARIntegration(self.iam, self.xsoar)
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
# AWS Configuration
export AWS_ACCESS_KEY_ID="your-aws-access-key-id"
export AWS_SECRET_ACCESS_KEY="your-aws-secret-access-key"
export AWS_REGION="us-east-1"
export AWS_SESSION_TOKEN=""  # Optional, for temporary credentials

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
# aws_iam_integrations_config.yaml
aws:
  access_key_id: "${AWS_ACCESS_KEY_ID}"
  secret_access_key: "${AWS_SECRET_ACCESS_KEY}"
  region: "${AWS_REGION}"
  
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
    sync_roles: true
    sync_events: true
    enable_least_privilege_analysis: true

event_routing:
  DeleteUser:
    - cortex_xdr
    - xsoar
    - prisma_cloud
  AttachUserPolicy:
    - cortex_xdr
    - xsoar
    - prisma_cloud
  CreateAccessKey:
    - cortex_xdr
    - xsoar
    - prisma_cloud
  AssumeRole:
    - xsoar  # Only if suspicious
    - prisma_cloud  # For CIEM analysis

automated_responses:
  enabled: true
  actions:
    deactivate_access_key:
      trigger_severity: "high"
      require_approval: false
    detach_policy:
      trigger_severity: "critical"
      require_approval: true
    delete_access_key:
      trigger_severity: "critical"
      require_approval: true
```

# 7.3 AWS IAM Permissions Required

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetUser",
        "iam:ListUsers",
        "iam:GetUserPolicy",
        "iam:ListUserPolicies",
        "iam:ListAttachedUserPolicies",
        "iam:GetGroup",
        "iam:GetGroupsForUser",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:GetRole",
        "iam:ListRoles",
        "iam:GetRolePolicy",
        "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:UpdateAccessKey",
        "iam:DeleteAccessKey",
        "iam:DetachUserPolicy"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "iam:PermissionsBoundary": "arn:aws:iam::*:policy/SecurityAutomation"
        }
      }
    }
  ]
}
```

---

# Troubleshooting

# Common Issues and Solutions

# 1. Authentication Failures

Problem: AWS API authentication fails

Solutions:
- Verify AWS credentials are correct and not expired
- Check IAM user/role has required permissions
- Ensure AWS region is correct
- For temporary credentials, verify session token is valid
- Check AWS credentials file (~/.aws/credentials) if using default profile

# 2. CloudTrail Not Enabled

Problem: Cannot retrieve CloudTrail events

Solutions:
- Verify CloudTrail is enabled in the AWS account
- Check CloudTrail trail is configured correctly
- Ensure CloudTrail has appropriate S3 bucket permissions
- Verify CloudTrail is logging IAM events
- Check CloudTrail region matches integration region

# 3. Rate Limiting

Problem: AWS API rate limits exceeded

Solutions:
- Implement exponential backoff
- Use pagination for large result sets
- Cache frequently accessed data
- Batch requests when possible
- Respect AWS API rate limits (varies by service)

# 4. Event Filtering Issues

Problem: Too many or too few events being processed

Solutions:
- Refine event filters in `get_security_events()` method
- Adjust severity thresholds in configuration
- Use more specific event name filters
- Implement event deduplication logic
- Use CloudTrail event filtering

# 5. Access Key Management

Problem: Cannot manage access keys

Solutions:
- Verify IAM permissions include access key management
- Check user exists and is active
- Ensure access key ID is correct format
- Handle case where user has no access keys
- Verify access key belongs to specified user

# 6. Policy Analysis

Problem: Cannot analyze IAM policies

Solutions:
- Verify IAM permissions to read policies
- Handle both inline and managed policies
- Check policy document format is valid JSON
- Handle pagination for users/roles with many policies
- Verify policy ARN format is correct

---

# Best Practices

1. Credential Security: Use IAM roles instead of access keys when possible
2. Least Privilege: Grant only minimum required IAM permissions
3. Error Handling: Implement comprehensive error handling and logging
4. Rate Limiting: Respect AWS API rate limits and implement backoff
5. Event Deduplication: Implement logic to prevent processing duplicate events
6. Monitoring: Monitor integration health and API usage
7. Testing: Test integrations in non-production AWS accounts first
8. Documentation: Document custom mappings and configurations
9. Audit Logging: Log all actions taken via integrations
10. CloudTrail: Ensure CloudTrail is enabled and properly configured
11. Encryption: Use encrypted connections (HTTPS) for all API calls
12. Rotation: Regularly rotate AWS access keys

---

# API Reference

# AWS IAM API Methods Used

- `get_user()` - Get user details
- `list_users()` - List all users
- `get_user_policy()` - Get inline user policy
- `list_user_policies()` - List inline user policies
- `list_attached_user_policies()` - List managed policies attached to user
- `get_groups_for_user()` - Get user groups
- `list_access_keys()` - List user access keys
- `get_access_key_last_used()` - Get access key last used information
- `get_role()` - Get role details
- `list_roles()` - List all roles
- `update_access_key()` - Update access key status
- `delete_access_key()` - Delete access key
- `attach_user_policy()` - Attach managed policy to user
- `detach_user_policy()` - Detach managed policy from user

# CloudTrail API Methods Used

- `lookup_events()` - Lookup CloudTrail events

# Required AWS IAM Permissions

- `iam:GetUser`
- `iam:ListUsers`
- `iam:GetUserPolicy`
- `iam:ListUserPolicies`
- `iam:ListAttachedUserPolicies`
- `iam:GetGroupsForUser`
- `iam:ListAccessKeys`
- `iam:GetAccessKeyLastUsed`
- `iam:GetRole`
- `iam:ListRoles`
- `iam:GetRolePolicy`
- `iam:ListRolePolicies`
- `iam:ListAttachedRolePolicies`
- `iam:UpdateAccessKey` (for remediation)
- `iam:DeleteAccessKey` (for remediation)
- `iam:DetachUserPolicy` (for remediation)
- `cloudtrail:LookupEvents`

---

Version: 1.0  
Last Updated: 2026-01-09  
Maintained By: SOC Team
