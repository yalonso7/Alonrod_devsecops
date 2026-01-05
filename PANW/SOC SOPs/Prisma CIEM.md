Prisma Cloud CIEM (Cloud Infrastructure Entitlement Management) Configuration Guide

Comprehensive Step-by-Step SOP for Identity Security

1\. CIEM ARCHITECTURE & FUNDAMENTALS

1.1 CIEM Core Components

\`\`\`  
Prisma Cloud CIEM \= Identity Discovery \+ Permission Analysis \+ Risk Assessment \+ Remediation  
                   ↓  
├── \*\*Identity Graph\*\*  
│   ├── Users (Human/Service)  
│   ├── Roles & Groups  
│   ├── Policies & Permissions  
│   └── Resources & Entitlements  
├── \*\*Risk Engine\*\*  
│   ├── Over-permissioning Detection  
│   ├── Privilege Escalation Paths  
│   └── Anomaly Detection (UEBA)  
└── \*\*Remediation Engine\*\*  
    ├── JIT Access  
    ├── Permission Revocation  
    └── Policy Recommendations  
\`\`\`

1.2 Supported Cloud Providers

\`\`\`  
✅ AWS: IAM Users, Roles, Policies, SSO, Organizations  
✅ Azure: AD Users, Service Principals, Managed Identities, RBAC  
✅ GCP: Service Accounts, IAM Roles, Organization Policies  
✅ Multi-Cloud: Cross-account trust analysis  
\`\`\`

2\. PRE-IMPLEMENTATION PLANNING

Step 1: Prerequisites Checklist

\`\`\`  
☐ Prisma Cloud Enterprise License with CIEM module  
☐ Required Permissions:  
   \- AWS: SecurityAudit, IAMReadOnlyAccess, Organizations:List\*  
   \- Azure: Directory Readers, Privileged Role Administrator  
   \- GCP: Security Reviewer, IAM Role Viewer  
☐ Network Access:  
   \- Outbound: TCP 443 to \<tenant\>.prismacloud.io  
   \- Inbound: None required  
☐ Data Requirements:  
   \- 30+ days of cloud activity logs (for baseline)  
   \- Organization structure documentation  
   \- Critical resource inventory  
\`\`\`

Step 2: Business Context Mapping

\`\`\`yaml  
\# business-context.yaml  
business\_units:  
  \- name: "Finance"  
    critical\_assets:  
      \- "arn:aws:s3:::financial-data-\*"  
      \- "arn:aws:rds:us-east-1:\*:cluster/prod-finance-db"  
    owners:  
      \- "finance-security@company.com"  
    compliance\_requirements:  
      \- "SOX"  
      \- "PCI-DSS"  
        
  \- name: "Engineering"  
    critical\_assets:  
      \- "arn:aws:ec2:\*:\*:instance/\*tag/Environment=Prod"  
      \- "arn:aws:eks:\*:\*:cluster/prod-\*"  
        
identity\_classes:  
  \- human\_users:  
      classification: "Employee"  
      mfa\_required: true  
      max\_session: "8h"  
        
  \- service\_accounts:  
      classification: "Application"  
      rotation\_required: "90d"  
        
  \- privileged\_identities:  
      classification: "Administrator"  
      jit\_required: true  
      logging\_required: true  
\`\`\`

3\. INITIAL CIEM CONFIGURATION

Step 3: Enable CIEM Module

\`\`\`  
1\. Navigate: Settings → Subscription → Features  
2\. Verify CIEM License: Active  
3\. Enable CIEM Module:  
   \- Toggle: Cloud Infrastructure Entitlement Management  
   \- Save Changes  
4\. Configure Data Collection:  
   \- Settings → Data Collection → Identity Data  
   \- Collection Frequency: 6 hours (standard), 1 hour (continuous)  
   \- Retention Period: 90 days (minimum for compliance)  
5\. Enable Advanced Features:  
   \- UEBA (User Entity Behavior Analytics): ✓  
   \- Permission Analytics: ✓  
   \- Risk-based Scoring: ✓  
\`\`\`

Step 4: Cloud Account Configuration for CIEM

AWS Organization-wide Setup:

\`\`\`bash  
\# 1\. Create CIEM IAM Role in Management Account  
aws iam create-role \\  
  \--role-name PrismaCloud-CIEM-Org-Role \\  
  \--assume-role-policy-document '{  
    "Version": "2012-10-17",  
    "Statement": \[{  
      "Effect": "Allow",  
      "Principal": {  
        "AWS": "arn:aws:iam::\<prisma-account-id\>:root"  
      },  
      "Action": "sts:AssumeRole",  
      "Condition": {  
        "StringEquals": {  
          "sts:ExternalId": "\<unique-external-id\>"  
        }  
      }  
    }\]  
  }'

\# 2\. Attach Required Policies  
aws iam attach-role-policy \\  
  \--role-name PrismaCloud-CIEM-Org-Role \\  
  \--policy-arn arn:aws:iam::aws:policy/SecurityAudit

aws iam attach-role-policy \\  
  \--role-name PrismaCloud-CIEM-Org-Role \\  
  \--policy-arn arn:aws:iam::aws:policy/IAMReadOnlyAccess

\# 3\. Enable AWS Organization Integration  
aws organizations enable-aws-service-access \\  
  \--service-principal config-multiaccountsetup.amazonaws.com  
\`\`\`

Azure Tenant Configuration:

\`\`\`powershell  
\# 1\. Register Prisma Cloud Enterprise App  
Connect-AzureAD  
New-AzureADServicePrincipal \-DisplayName "PrismaCloud-CIEM"

\# 2\. Assign Required Roles  
\# Tenant-wide Reader  
New-AzureADDirectoryRoleMember \`  
  \-ObjectId (Get-AzureADDirectoryRole | Where-Object {$\_.DisplayName \-eq "Directory Readers"}).ObjectId \`  
  \-RefObjectId (Get-AzureADServicePrincipal \-SearchString "PrismaCloud-CIEM").ObjectId

\# Security Reader  
New-AzureADDirectoryRoleMember \`  
  \-ObjectId (Get-AzureADDirectoryRole | Where-Object {$\_.DisplayName \-eq "Security Reader"}).ObjectId \`  
  \-RefObjectId (Get-AzureADServicePrincipal \-SearchString "PrismaCloud-CIEM").ObjectId

\# 3\. Enable Azure AD Audit Logs  
Set-AzureADAuditDirectoryLogs \-Enable $true  
\`\`\`

Step 5: Configure Identity Discovery

\`\`\`  
1\. Navigate: Monitor → Identity Security → Settings  
2\. Discovery Settings:  
   \- Auto-discovery: Enabled  
   \- Scan Frequency: 6 hours  
   \- Discovery Scope:  
     ✓ IAM Users & Roles  
     ✓ Groups & Policies  
     ✓ Service Accounts  
     ✓ Federated Identities  
     ✓ Resource-based Policies  
3\. Identity Resolution:  
   \- Cross-account identity correlation: Enabled  
   \- SSO integration: Configure (if using Okta/Azure AD)  
   \- HRIS integration: Optional (for employee lifecycle)  
4\. Data Enrichment:  
   \- Tag identities with business context  
   \- Classify: Human vs. Service  
   \- Risk categorization  
\`\`\`

4\. IDENTITY INVENTORY & BASELINE

Step 6: Initial Identity Inventory Scan

\`\`\`bash  
\# Manual Scan Trigger via API  
curl \-X POST \\  
  \-H "Authorization: Bearer $PRISMA\_TOKEN" \\  
  \-H "Content-Type: application/json" \\  
  https://\<tenant\>.prismacloud.io/api/v1/identity/discovery/scan \\  
  \-d '{  
    "cloudType": \["aws", "azure", "gcp"\],  
    "scope": "full",  
    "priority": "high"  
  }'

\# Monitor Scan Progress  
curl \-H "Authorization: Bearer $PRISMA\_TOKEN" \\  
  "https://\<tenant\>.prismacloud.io/api/v1/identity/discovery/status"  
\`\`\`

Step 7: Establish Permission Baseline

\`\`\`  
1\. Navigate: Monitor → Identity Security → Analytics → Permission Analytics  
2\. Configure Baseline Period:  
   \- Minimum: 30 days of activity logs  
   \- Recommended: 90 days for seasonal patterns  
3\. Generate Baseline Report:  
   \- Normal access patterns  
   \- Typical permission usage  
   \- Geographic/Time patterns  
4\. Set Thresholds:  
   \- Anomaly detection sensitivity: Medium  
   \- Permission usage threshold: 10% (alert if \<10% used)  
   \- Stale identity threshold: 90 days  
5\. Export Baseline:  
   \- JSON format for audit trail  
   \- CSV for manual review  
\`\`\`

5\. RISK POLICY CONFIGURATION

Step 8: Configure Built-in CIEM Risk Policies

\`\`\`  
1\. Navigate: Policies → Compliance Standards → CIEM  
2\. Enable Framework Policies:  
   \- CIS IAM Benchmark  
   \- NIST 800-53 Identity Controls  
   \- PCI DSS Requirement 8  
   \- GDPR Article 32  
3\. Risk Categories to Enable:

A. \*\*Excessive Permissions:\*\*  
   \- Over-permissioned IAM roles (\>20 permissions)  
   \- Admin-equivalent privileges without business need  
   \- Wildcard permissions (\*) on sensitive services

B. \*\*Identity Hygiene:\*\*  
   \- Stale identities (\>90 days inactive)  
   \- Service accounts without rotation (\>1 year)  
   \- Users without MFA enabled  
   \- Password policies non-compliant

C. \*\*Access Risk:\*\*  
   \- Cross-account trust with external parties  
   \- Federated identities with excessive privileges  
   \- Resource-based policies with public access

D. \*\*Privilege Escalation:\*\*  
   \- IAM roles with iam:\* permissions  
   \- Ability to modify identity policies  
   \- PassRole permissions to privileged roles  
\`\`\`

Step 9: Custom Risk Policy Creation

\`\`\`sql  
\-- Custom Policy: Detect Privilege Escalation Paths  
POLICY: "Privilege Escalation via PassRole"  
SEVERITY: Critical  
RQL:   
config where cloud.type \= 'aws' and  
api.name \= 'aws-iam-get-policy-version' and  
json.rule \= "statement\[?any(  
  effect \== 'Allow' and  
  action \== 'iam:PassRole' and  
  resource contains 'arn:aws:iam::\*:role/admin' and  
  principal \== '\*'  
)\]"

\-- Custom Policy: Detect External Federation Risks  
POLICY: "External IdP with Excessive Permissions"  
SEVERITY: High  
RQL:  
config where cloud.type \= 'aws' and  
api.name \= 'aws-iam-get-role' and  
json.rule \= "$.assumeRolePolicyDocument.statement\[?(  
  effect \== 'Allow' and  
  principal.Federated contains 'accounts.google.com' and  
  action \== 'sts:AssumeRoleWithWebIdentity' and  
  condition.StringEquals\['accounts.google.com:aud'\] \!= '\<approved-client-id\>'  
)\]"  
\`\`\`

Step 10: Configure Risk Scoring Model

\`\`\`yaml  
\# risk-scoring-config.yaml  
risk\_scoring:  
  enabled: true  
  model: "weighted"  
  factors:  
      
    permission\_risk:  
      weight: 0.4  
      subfactors:  
        \- wildcard\_permissions: 0.3  
        \- sensitive\_service\_access: 0.4  
        \- unused\_permissions: 0.3  
          
    identity\_risk:  
      weight: 0.3  
      subfactors:  
        \- stale\_credentials: 0.25  
        \- no\_mfa: 0.35  
        \- service\_account\_age: 0.2  
        \- excessive\_sessions: 0.2  
          
    access\_pattern\_risk:  
      weight: 0.2  
      subfactors:  
        \- anomalous\_access: 0.4  
        \- cross\_account\_trust: 0.3  
        \- external\_access: 0.3  
          
    business\_context\_risk:  
      weight: 0.1  
      subfactors:  
        \- critical\_asset\_access: 0.6  
        \- compliance\_scope: 0.4  
          
  thresholds:  
    critical: 80  
    high: 60  
    medium: 40  
    low: 20  
\`\`\`

6\. PERMISSION ANALYTICS CONFIGURATION

Step 11: Configure Permission Usage Analytics

\`\`\`  
1\. Navigate: Monitor → Identity Security → Analytics → Permission Usage  
2\. Enable Data Collection:  
   \- CloudTrail integration (AWS)  
   \- Azure Activity Logs  
   \- GCP Audit Logs  
3\. Configure Analysis:  
   \- Permission usage tracking: Enabled  
   \- Unused permission detection: \>30 days  
   \- Permission correlation: By identity type  
4\. Set Thresholds:  
   \- Unused permission alert: \>90% unused  
   \- Permission churn alert: \>20% weekly change  
   \- Anomalous usage alert: 3 sigma deviation  
\`\`\`

Step 12: Configure Least Privilege Recommendations

\`\`\`python  
\# least-privilege-recommendations.py  
import prismacloud.ciem as ciem

client \= ciem.CIEMClient(tenant='\<tenant\>.prismacloud.io')

\# Generate recommendations for IAM role  
recommendations \= client.generate\_least\_privilege\_recommendations(  
    identity\_arn='arn:aws:iam::123456789012:role/EC2-Admin',  
    analysis\_period='30d',  
    confidence\_threshold=0.95,  
    include\_suggested\_policy=True  
)

\# Review and approve recommendations  
for rec in recommendations:  
    print(f"Current Permissions: {rec.current\_permissions\_count}")  
    print(f"Recommended Permissions: {rec.recommended\_permissions\_count}")  
    print(f"Reduction: {rec.reduction\_percentage}%")  
    print(f"Suggested Policy:\\n{rec.suggested\_policy}")  
      
\# Apply recommendations (after approval)  
if recommendations.approved:  
    client.apply\_least\_privilege\_policy(  
        identity\_arn='arn:aws:iam::123456789012:role/EC2-Admin',  
        new\_policy=recommendations.suggested\_policy,  
        dry\_run=False  
    )  
\`\`\`

7\. UEBA (USER ENTITY BEHAVIOR ANALYTICS) SETUP

Step 13: Configure Anomaly Detection

\`\`\`  
1\. Navigate: Monitor → Identity Security → UEBA → Settings  
2\. Enable Machine Learning Models:  
   \- Access Pattern Analysis: ✓  
   \- Geographic Anomalies: ✓  
   \- Time-based Anomalies: ✓  
   \- Permission Usage Changes: ✓  
3\. Learning Period Configuration:  
   \- Initial Baseline: 30 days  
   \- Continuous Learning: Enabled  
   \- Seasonality Detection: Enabled  
4\. Anomaly Detection Rules:

   A. \*\*Geographic Anomalies:\*\*  
      \- New country access  
      \- Simultaneous logins from distant locations  
      \- Unusual travel patterns  
        
   B. \*\*Time-based Anomalies:\*\*  
      \- Off-hours access (outside 9-5)  
      \- Weekend/holiday access  
      \- Rapid succession access  
        
   C. \*\*Behavioral Anomalies:\*\*  
      \- New resource type access  
      \- Unusual API call patterns  
      \- Permission escalation attempts  
        
   D. \*\*Volume Anomalies:\*\*  
      \- Spike in API calls  
      \- Mass resource enumeration  
      \- Brute-force patterns  
\`\`\`

Step 14: Configure Risk-based Adaptive Access

\`\`\`yaml  
\# adaptive-access-rules.yaml  
adaptive\_access:  
  enabled: true  
  rules:  
      
    \- name: "high\_risk\_session\_validation"  
      conditions:  
        \- risk\_score \> 70  
        \- new\_geographic\_location \= true  
        \- off\_hours\_access \= true  
      actions:  
        \- require\_step\_up\_auth: true  
        \- mfa\_challenge: true  
        \- session\_timeout: "15m"  
        \- notify\_security\_team: true  
          
    \- name: "privileged\_access\_monitoring"  
      conditions:  
        \- identity\_class \= "privileged"  
        \- critical\_asset\_access \= true  
        \- risk\_score \> 50  
      actions:  
        \- session\_recording: true  
        \- real\_time\_alerting: true  
        \- peer\_review\_required: true  
          
    \- name: "service\_account\_anomaly"  
      conditions:  
        \- identity\_class \= "service\_account"  
        \- human\_like\_behavior \= true  
        \- access\_pattern\_change \> 80%  
      actions:  
        \- auto\_isolate: true  
        \- credential\_rotation: true  
        \- security\_review\_required: true  
\`\`\`

8\. JIT (JUST-IN-TIME) ACCESS CONFIGURATION

Step 15: Configure JIT Access Workflows

\`\`\`  
1\. Navigate: Monitor → Identity Security → JIT Access → Settings  
2\. Enable JIT Access Module:  
   \- Toggle: Enable JIT Access Management  
   \- Approval Workflow: Multi-level  
3\. Configure JIT Policies:

   A. \*\*Privileged Role Access:\*\*  
      \- Max duration: 4 hours  
      \- Approval required: Security \+ Manager  
      \- Session recording: Enabled  
        
   B. \*\*Emergency Access:\*\*  
      \- Max duration: 1 hour  
      \- Approval required: Security only  
      \- Post-access review: Required  
        
   C. \*\*Developer Access:\*\*  
      \- Max duration: 8 hours  
      \- Approval required: Manager only  
      \- Scope: Non-production only  
        
4\. Integration Settings:  
   \- Slack/Teams approval workflows  
   \- Email notifications  
   \- ServiceNow ticket creation  
\`\`\`

Step 16: Configure Access Request Portal

\`\`\`yaml  
\# access-portal-config.yaml  
access\_portal:  
  enabled: true  
  url: "https://access.company.com"  
  authentication:  
    provider: "okta"  
    sso\_enabled: true  
      
  request\_catalog:  
    \- name: "Production Database Access"  
      roles:  
        \- "arn:aws:iam::\*:role/DB-Admin"  
      justification\_required: true  
      max\_duration: "2h"  
        
    \- name: "S3 Bucket Write Access"  
      roles:  
        \- "arn:aws:iam::\*:role/S3-Writer"  
      auto\_approve: true  
      max\_duration: "8h"  
        
    \- name: "Emergency Admin Access"  
      roles:  
        \- "arn:aws:iam::\*:role/Administrator"  
      break\_glass: true  
      max\_duration: "1h"  
      post\_approval\_review: required  
        
  approval\_workflows:  
    \- name: "standard"  
      approvers:  
        \- manager  
        \- security\_analyst  
      timeout: "4h"  
        
    \- name: "emergency"  
      approvers:  
        \- security\_lead  
      timeout: "30m"  
\`\`\`

9\. REMEDIATION AUTOMATION

Step 17: Configure Auto-Remediation Policies

\`\`\`sql  
\-- Auto-remediation Policy: Revoke Unused Permissions  
POLICY: "Auto-Remove Unused Permissions"  
CONDITIONS:  
  \- permission\_usage \< 5%  
  \- unused\_days \> 90  
  \- risk\_score \> 60  
ACTIONS:  
  \- Notify owner: 7 days before  
  \- Auto-revoke: After notification period  
  \- Create ticket: For tracking  
    
\-- Auto-remediation Policy: Rotate Old Credentials  
POLICY: "Auto-Rotate Service Account Keys"  
CONDITIONS:  
  \- key\_age \> 90 days  
  \- identity\_type \= "service\_account"  
  \- access\_frequency \> "daily"  
ACTIONS:  
  \- Generate new key: Automatic  
  \- Notify application owner: 24 hours before  
  \- Grace period: 7 days for transition  
  \- Revoke old key: After grace period  
\`\`\`

Step 18: Configure Remediation Playbooks

\`\`\`yaml  
\# remediation-playbooks.yaml  
playbooks:  
    
  \- name: "over\_permissioned\_role"  
    triggers:  
      \- risk\_category \= "excessive\_permissions"  
      \- severity \= "high"  
    steps:  
      1\. Notify role owner  
      2\. Generate least privilege recommendations  
      3\. Schedule remediation window  
      4\. Apply new policy (after approval)  
      5\. Verify access still works  
      6\. Close remediation ticket  
        
  \- name: "stale\_identity\_cleanup"  
    triggers:  
      \- last\_access \> 90 days  
      \- no\_mfa \= true  
    steps:  
      1\. Check for dependencies  
      2\. Notify manager  
      3\. 30-day grace period  
      4\. Disable (not delete) identity  
      5\. Archive for 30 days  
      6\. Permanent deletion  
        
  \- name: "privilege\_escalation\_response"  
    triggers:  
      \- iam\_passrole\_detected  
      \- risk\_score \> 80  
    steps:  
      1\. Immediate alert to SOC  
      2\. Temporary role suspension  
      3\. Forensic analysis  
      4\. Identity compromise check  
      5\. Permanent policy fix  
      6\. Post-incident review  
\`\`\`

10\. COMPLIANCE & REPORTING

Step 19: Configure Compliance Dashboards

\`\`\`  
1\. Navigate: Dashboards → Identity Security → Compliance  
2\. Create Executive Dashboard:  
   \- Widget 1: Overall Identity Risk Score  
   \- Widget 2: Compliance by Framework  
   \- Widget 3: Top Risky Identities  
   \- Widget 4: Permission Reduction Progress  
   \- Widget 5: JIT Access Utilization  
3\. Create Operational Dashboard:  
   \- Widget 1: Active Alerts by Severity  
   \- Widget 2: Remediation Backlog  
   \- Widget 3: Permission Analysis Status  
   \- Widget 4: UEBA Anomalies Detected  
4\. Create Audit Dashboard:  
   \- Widget 1: Access History by Resource  
   \- Widget 2: Policy Change History  
   \- Widget 3: Failed Access Attempts  
   \- Widget 4: Privilege Escalation Attempts  
\`\`\`

Step 20: Automated Compliance Reporting

\`\`\`python  
\# compliance-reporting-automation.py  
from prismacloud.ciem import ComplianceReporter  
from datetime import datetime, timedelta

reporter \= ComplianceReporter(  
    tenant='\<tenant\>.prismacloud.io',  
    api\_key='\<api-key\>'  
)

\# Generate quarterly compliance report  
report \= reporter.generate\_report(  
    period\_start=datetime.now() \- timedelta(days=90),  
    period\_end=datetime.now(),  
    frameworks=\['cis', 'nist', 'pci', 'gdpr', 'hipaa'\],  
    sections=\[  
        'executive\_summary',  
        'risk\_assessment',  
        'policy\_violations',  
        'remediation\_progress',  
        'recommendations'  
    \],  
    format='pdf'  
)

\# Distribute to stakeholders  
report.distribute(  
    recipients=\[  
        'ciso@company.com',  
        'compliance@company.com',  
        'audit@company.com'  
    \],  
    channels=\['email', 'sharepoint', 'confluence'\],  
    schedule='quarterly'  
)

\# Schedule automated reports  
reporter.create\_schedule(  
    name='Monthly Identity Compliance Report',  
    frequency='monthly',  
    day\_of\_month=1,  
    recipients=\['security-team@company.com'\]  
)  
\`\`\`

11\. INTEGRATION CONFIGURATION

Step 21: SIEM Integration

\`\`\`yaml  
\# siem-integration.yaml  
siem\_integrations:  
    
  splunk:  
    enabled: true  
    endpoint: "https://splunk.company.com:8088"  
    token: "\<hec-token\>"  
    log\_types:  
      \- identity\_risk\_events  
      \- access\_events  
      \- policy\_changes  
      \- remediation\_actions  
    format: "cef"  
      
  qradar:  
    enabled: true  
    endpoint: "https://qradar.company.com"  
    token: "\<dsm-token\>"  
    log\_types:  
      \- anomaly\_detection  
      \- privilege\_escalation  
      \- compliance\_violations  
        
  elastic:  
    enabled: true  
    endpoint: "https://elastic.company.com:9200"  
    index: "prisma-ciem-logs"  
    pipeline: "ciem-processor"  
\`\`\`

Step 22: IAM Governance Platform Integration

\`\`\`  
1\. \*\*Okta Integration:\*\*  
   \- SCIM provisioning  
   \- Lifecycle management  
   \- Access request workflows  
     
2\. \*\*SailPoint Integration:\*\*  
   \- Identity governance  
   \- Certification campaigns  
   \- Access reviews  
     
3\. \*\*Saviynt Integration:\*\*  
   \- Privileged access management  
   \- Role-based access control  
   \- Compliance reporting  
     
4\. \*\*ServiceNow Integration:\*\*  
   \- CMDB synchronization  
   \- Incident management  
   \- Change management  
\`\`\`

12\. OPERATIONAL PROCEDURES

Daily CIEM Operations Checklist:

\`\`\`  
✅ Identity Health Check:  
   \- Data collection status  
   \- Scanner connectivity  
   \- API rate limit monitoring  
     
✅ Alert Triage:  
   \- Critical risk alerts (\<15m response)  
   \- Privilege escalation attempts  
   \- Anomalous access patterns  
     
✅ UEBA Monitoring:  
   \- New anomaly detection  
   \- False positive analysis  
   \- Model performance check  
     
✅ JIT Access Review:  
   \- Pending requests  
   \- Active elevated sessions  
   \- Expired access cleanup  
\`\`\`

Weekly CIEM Operations:

\`\`\`  
📊 Risk Review Meeting:  
   \- Top 10 risky identities  
   \- Permission usage trends  
   \- Anomaly pattern analysis  
     
🔧 Policy Optimization:  
   \- New risk patterns  
   \- Threshold adjustments  
   \- Custom policy creation  
     
📝 Compliance Status:  
   \- Framework compliance scores  
   \- Exception management  
   \- Audit preparation  
     
🔄 Remediation Tracking:  
   \- Open remediation items  
   \- Aging violations  
   \- Auto-remediation success rate  
\`\`\`

Monthly CIEM Operations:

\`\`\`  
📋 Access Certification:  
   \- Privileged identity review  
   \- Service account validation  
   \- Permission attestation  
     
📈 Metrics & Reporting:  
   \- Risk score trends  
   \- Reduction in permissions  
   \- ROI calculations  
     
🎓 Training & Awareness:  
   \- New feature training  
   \- Security awareness  
   \- Process improvements  
     
🔍 Deep Dive Analysis:  
   \- Permission creep analysis  
   \- Attack path simulation  
   \- Red team exercise review  
\`\`\`

13\. ADVANCED FEATURES CONFIGURATION

Step 23: Configure Attack Path Analysis for Identities

\`\`\`yaml  
\# attack-path-config.yaml  
attack\_path\_analysis:  
  enabled: true  
  scope:  
    \- aws\_accounts: all  
    \- critical\_assets: predefined  
    \- entry\_points: \["public\_users", "federation", "service\_accounts"\]  
      
  simulation\_frequency: "weekly"  
  report\_recipients: \["soc@company.com", "identity-team@company.com"\]  
    
  scenarios:  
    \- name: "privilege\_escalation\_from\_lambda"  
      description: "Lambda with excessive permissions"  
      starting\_point: "arn:aws:lambda:\*:\*:function/\*"  
      target: "arn:aws:iam::\*:role/Admin"  
        
    \- name: "cross\_account\_trust\_exploit"  
      description: "External account trust chain"  
      starting\_point: "arn:aws:iam::\*:role/CrossAccountAccess"  
      target: "arn:aws:s3:::financial-data-\*"  
\`\`\`

Step 24: Configure Machine Learning Models

\`\`\`python  
\# ml-model-configuration.py  
from prismacloud.ciem.ml import ModelManager

manager \= ModelManager(tenant='\<tenant\>.prismacloud.io')

\# Configure permission usage prediction  
manager.configure\_model(  
    model\_name="permission\_usage\_predictor",  
    features=\[  
        "identity\_type",  
        "business\_unit",  
        "job\_function",  
        "historical\_usage\_patterns",  
        "similar\_identities\_behavior"  
    \],  
    training\_data\_days=90,  
    retraining\_frequency="monthly",  
    confidence\_threshold=0.85  
)

\# Configure anomaly detection model  
manager.configure\_model(  
    model\_name="access\_anomaly\_detector",  
    algorithm="isolation\_forest",  
    features=\[  
        "access\_time",  
        "geographic\_location",  
        "resource\_type",  
        "action\_type",  
        "success\_rate"  
    \],  
    contamination=0.01,  \# 1% expected anomalies  
    ensemble\_count=3  
)  
\`\`\`

14\. PERFORMANCE OPTIMIZATION

Step 25: Tune CIEM Performance

\`\`\`yaml  
\# performance-tuning.yaml  
performance:  
    
  scanning:  
    concurrency:  
      aws: 10  
      azure: 5  
      gcp: 8  
    batch\_size:  
      identities: 1000  
      policies: 500  
        
  data\_processing:  
    cache\_ttl: "1h"  
    compression: true  
    incremental\_updates: true  
      
  api\_optimization:  
    rate\_limit\_buffer: 0.8  \# Use 80% of available rate limit  
    retry\_strategy:  
      max\_attempts: 3  
      backoff\_factor: 2  
        
  storage:  
    hot\_storage: "30d"  
    warm\_storage: "90d"  
    cold\_storage: "1y"  
\`\`\`

Step 26: Scalability Configuration

\`\`\`bash  
\# Scale CIEM components based on environment size  
SMALL\_ENV (\< 1,000 identities):  
  \- Scanning frequency: 12h  
  \- Concurrency: Low  
  \- Data retention: 90d

MEDIUM\_ENV (1,000 \- 10,000 identities):  
  \- Scanning frequency: 6h  
  \- Concurrency: Medium  
  \- Data retention: 180d  
  \- Enable UEBA: Yes

LARGE\_ENV (\> 10,000 identities):  
  \- Scanning frequency: 1h  
  \- Concurrency: High  
  \- Data retention: 365d  
  \- Enable UEBA: Yes  
  \- Enable ML models: Yes  
  \- Distributed processing: Yes  
\`\`\`

15\. DISASTER RECOVERY & BACKUP

Step 27: CIEM Configuration Backup

\`\`\`bash  
\#\!/bin/bash  
\# ciem-backup-script.sh  
BACKUP\_DIR="/backups/prisma-ciem"  
DATE=$(date \+%Y%m%d\_%H%M%S)

\# Backup CIEM configuration  
curl \-H "Authorization: Bearer $TOKEN" \\  
  "https://\<tenant\>.prismacloud.io/api/v1/identity/settings" \\  
  \-o "$BACKUP\_DIR/settings\_$DATE.json"

\# Backup risk policies  
curl \-H "Authorization: Bearer $TOKEN" \\  
  "https://\<tenant\>.prismacloud.io/api/v1/identity/policies" \\  
  \-o "$BACKUP\_DIR/policies\_$DATE.json"

\# Backup JIT configurations  
curl \-H "Authorization: Bearer $TOKEN" \\  
  "https://\<tenant\>.prismacloud.io/api/v1/identity/jit/config" \\  
  \-o "$BACKUP\_DIR/jit\_config\_$DATE.json"

\# Backup business context  
curl \-H "Authorization: Bearer $TOKEN" \\  
  "https://\<tenant\>.prismacloud.io/api/v1/identity/context" \\  
  \-o "$BACKUP\_DIR/business\_context\_$DATE.json"

\# Create backup manifest  
echo "{  
  \\"backup\_date\\": \\"$DATE\\",  
  \\"components\\": \[\\"settings\\", \\"policies\\", \\"jit\_config\\", \\"business\_context\\"\],  
  \\"version\\": \\"$(curl \-s \-H \\"Authorization: Bearer $TOKEN\\" https://\<tenant\>.prismacloud.io/api/v1/version)\\"  
}" \> "$BACKUP\_DIR/manifest\_$DATE.json"

\# Encrypt backup  
gpg \--encrypt \--recipient security@company.com "$BACKUP\_DIR/manifest\_$DATE.json"  
\`\`\`

Step 28: Disaster Recovery Runbook

\`\`\`  
PHASE 1: IMMEDIATE RESPONSE (0-1 hour)  
1\. Identify CIEM service disruption  
2\. Check Prisma Cloud status page  
3\. Verify API connectivity  
4\. Activate backup console (if available)

PHASE 2: SERVICE RESTORATION (1-4 hours)  
1\. Restore from latest backup  
2\. Re-establish cloud connections  
3\. Verify identity data synchronization  
4\. Resume scanning operations

PHASE 3: DATA RECOVERY (4-24 hours)  
1\. Backfill missing identity data  
2\. Rebuild ML model baselines  
3\. Verify UEBA functionality  
4\. Test JIT access workflows

PHASE 4: VALIDATION & TESTING (24-48 hours)  
1\. Complete functional testing  
2\. Validate risk scoring accuracy  
3\. Test alerting and notifications  
4\. Document recovery process  
\`\`\`

16\. MONITORING & ALERTING

Step 29: Configure CIEM Health Monitoring

\`\`\`yaml  
\# health-monitoring.yaml  
monitoring:  
    
  metrics:  
    \- name: "identity\_discovery\_success\_rate"  
      threshold: 95%  
      alert\_severity: "high"  
        
    \- name: "permission\_analysis\_completion\_time"  
      threshold: "2h"  
      alert\_severity: "medium"  
        
    \- name: "ueba\_anomaly\_detection\_latency"  
      threshold: "15m"  
      alert\_severity: "medium"  
        
    \- name: "jit\_access\_request\_processing\_time"  
      threshold: "5m"  
      alert\_severity: "low"  
        
  alerts:  
    \- name: "ciem\_scanner\_down"  
      condition: "last\_scan\_age \> 12h"  
      actions:  
        \- page\_oncall\_security  
        \- create\_service\_now\_incident  
          
    \- name: "high\_false\_positive\_rate"  
      condition: "false\_positive\_rate \> 20%"  
      actions:  
        \- notify\_data\_science\_team  
        \- adjust\_model\_thresholds  
          
    \- name: "permission\_analysis\_backlog"  
      condition: "pending\_analysis \> 1000"  
      actions:  
        \- scale\_analysis\_workers  
        \- notify\_operations\_team  
\`\`\`

APPENDIX: CIEM QUICK REFERENCE

CIEM API Reference:

\`\`\`python  
\# Key CIEM API Endpoints  
ENDPOINTS \= {  
    \# Identity Discovery  
    "discover\_identities": "/api/v1/identity/discover",  
    "get\_identity": "/api/v1/identity/{id}",  
    "list\_identities": "/api/v1/identity",  
      
    \# Risk Analysis  
    "calculate\_risk": "/api/v1/identity/risk/calculate",  
    "get\_risk\_score": "/api/v1/identity/{id}/risk",  
    "list\_risky\_identities": "/api/v1/identity/risk/top",  
      
    \# Permission Analytics  
    "analyze\_permissions": "/api/v1/identity/permissions/analyze",  
    "get\_permission\_usage": "/api/v1/identity/{id}/permissions/usage",  
    "generate\_recommendations": "/api/v1/identity/permissions/recommend",  
      
    \# JIT Access  
    "request\_access": "/api/v1/identity/jit/request",  
    "approve\_access": "/api/v1/identity/jit/approve",  
    "revoke\_access": "/api/v1/identity/jit/revoke",  
      
    \# UEBA  
    "detect\_anomalies": "/api/v1/identity/ueba/detect",  
    "get\_anomalies": "/api/v1/identity/ueba/anomalies",  
}  
\`\`\`

CIEM CLI Commands:

\`\`\`bash  
\# Install CIEM CLI  
curl \-o prisma-ciem https://\<tenant\>.prismacloud.io/download/ciem-cli  
chmod \+x prisma-ciem

\# Common commands  
prisma-ciem identities list \--cloud aws \--format json  
prisma-ciem risk analyze \--identity arn:aws:iam::\*:role/Admin  
prisma-ciem permissions unused \--days 90 \--output report.csv  
prisma-ciem jit request \--role Admin \--duration 2h \--reason "Emergency fix"  
prisma-ciem ueba anomalies \--last 24h \--severity high  
\`\`\`

CIEM KPIs & Metrics:

\`\`\`  
Identity Security Metrics:  
  \- Identities with excessive permissions: \<5%  
  \- Identities without MFA: 0%  
  \- Stale identities (\>90d): \<2%  
  \- Permission usage rate: \>70%  
  \- JIT access utilization: \>90%  
  \- Mean time to revoke access: \<1h  
  \- False positive rate: \<10%  
  \- Risk score reduction: 20% quarterly  
\`\`\`

Troubleshooting Guide:

Issue Symptoms Resolution  
Identity discovery failing No new identities found Verify IAM permissions, check API rate limits  
High false positives Too many risk alerts Adjust risk thresholds, refine business context  
Performance degradation Slow scans, timeouts Increase concurrency, optimize queries  
Data inconsistency Mismatched permission counts Force full rescan, clear cache  
Integration failures SIEM not receiving logs Verify webhook configuration, check firewall rules

\---

CIEM IMPLEMENTATION SIGN-OFF

Implementation Checklist:

· Prerequisites validated  
· Cloud accounts configured  
· Identity discovery completed  
· Risk policies configured  
· UEBA baseline established  
· JIT access workflows tested  
· Integrations validated  
· Team training completed  
· Documentation updated  
· DR procedures tested

Approval Matrix:

Role Responsibilities Sign-off  
CISO Overall security strategy   
IAM Architect Identity governance   
Cloud Security Engineer Technical implementation   
Compliance Officer Regulatory requirements   
SOC Manager Operational readiness 

Go-Live Criteria:

· ✅ All critical identities discovered  
· ✅ Risk scoring accuracy \>95%  
· ✅ Alerting tested and validated  
· ✅ Team trained on procedures  
· ✅ DR plan documented and tested  
· ✅ Performance meets SLAs

\---

Document Control:

· Version: 2.0  
· Last Updated: \[Date\]  
· Next Review: \[Date \+ 90 days\]  
· Owner: Cloud Security Team  
· Classification: Internal Use Only

This CIEM SOP should be reviewed quarterly. Regular updates required based on new cloud provider features, regulatory changes, and organizational evolution.