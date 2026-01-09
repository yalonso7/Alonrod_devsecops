Prisma Cloud CSPM Configuration Guide

Comprehensive Step-by-Step SOP

1\. PRE-IMPLEMENTATION PLANNING

1.1 Prerequisites Checklist

\`\`\`  
☐ Prisma Cloud Enterprise Edition License  
☐ Admin/Account Owner privileges  
☐ Network connectivity to cloud APIs  
☐ Required cloud permissions/roles  
☐ Asset inventory documentation  
☐ Compliance framework requirements  
\`\`\`

1.2 CSPM Architecture Overview

\`\`\`  
Prisma Cloud Console → Cloud APIs → Data Collection → Policy Engine → Alerting  
                    ↓  
               Compliance Dashboard  
\`\`\`

2\. INITIAL CONFIGURATION STEPS

Step 1: Access Prisma Cloud Console

1\. Navigate to https://\<tenant\>.prismacloud.io  
2\. Login with administrator credentials  
3\. Verify tenant is in CSPM Mode (Settings → General)

Step 2: Configure Cloud Accounts

AWS Configuration:

\`\`\`yaml  
1\. Console → Cloud Accounts → Add Account → AWS  
2\. Authentication Method:   
   \- Recommended: Assume Role  
   \- Alternative: Access Keys  
3\. Configure Assume Role:  
   \- AWS Account ID: \[Your AWS Account\]  
   \- External ID: \[Generate Unique ID\]  
   \- Role Name: PrismaCloudRole  
4\. Attach AWS Managed Policy:  
   \- "PrismaCloudReadOnly"  
5\. Enable Account: ✓  
6\. Scanning Mode: Standard/Topology  
\`\`\`

Azure Configuration:

\`\`\`yaml  
1\. Console → Cloud Accounts → Add Account → Azure  
2\. Select: Service Principal  
3\. Collect from: Entire Tenant (recommended)  
4\. Enter:  
   \- Tenant ID  
   \- Application ID  
   \- Application Secret  
5\. Assign Roles:  
   \- Reader (tenant scope)  
   \- Security Reader  
6\. Enable Account: ✓  
\`\`\`

GCP Configuration:

\`\`\`yaml  
1\. Console → Cloud Accounts → Add Account → GCP  
2\. Select: Service Account JSON  
3\. Create Service Account in GCP:  
   \- Roles: Viewer, Security Reviewer  
   \- Cloud Asset Viewer  
4\. Upload JSON Key  
5\. Enable Account: ✓  
\`\`\`

Step 3: Configure Data Collection

\`\`\`  
1\. Navigate: Settings → Data Collection  
2\. Set Collection Frequency:  
   \- Standard: 6-12 hours  
   \- Continuous: Real-time (requires additional setup)  
3\. Enable Resource Discovery: ✓  
4\. Enable Flow Log Analysis: ✓ (if using network features)  
5\. Save Configuration  
\`\`\`

3\. POLICY CONFIGURATION SOP

Step 4: Enable Built-in Policies

\`\`\`  
1\. Navigate: Policies → Compliance Standards  
2\. Select Framework:  
   \- CIS v1.4/v2.0  
   \- NIST 800-53  
   \- PCI DSS  
   \- HIPAA  
   \- GDPR  
3\. Click "Enable All" for selected framework  
4\. Repeat for additional frameworks  
\`\`\`

Step 5: Custom Policy Creation

Procedure: Create Custom CSPM Policy

\`\`\`  
1\. Policies → Add Policy → Compliance  
2\. Fill Details:  
   \- Policy Name: \[Descriptive Name\]  
   \- Severity: High/Medium/Low/Informational  
   \- Cloud Type: AWS/Azure/GCP  
   \- Category: \[Security/Compliance/Cost\]  
3\. Define Logic (RQL):  
   Example: config where api.name \= 'aws-ec2-describe-instances'   
           and $.state.name \= 'running'   
           and $.publicIpAddress \!= null   
           and tags.Production \= 'true'  
4\. Set Remediation:  
   \- Alert Only  
   \- Auto-remediate (if licensed)  
5\. Configure Notification:  
   \- Email  
   \- Slack  
   \- Webhook  
   \- SIEM Integration  
6\. Save & Enable Policy  
\`\`\`

Step 6: Policy Exceptions Management

\`\`\`  
1\. Policies → Exceptions → Add Exception  
2\. Select Policy  
3\. Set Scope:  
   \- Account/Region/Resource ID  
   \- Time-bound (if temporary)  
4\. Provide Justification  
5\. Approver Workflow (if configured)  
6\. Submit for Approval  
\`\`\`

4\. COMPLIANCE DASHBOARD SETUP

Step 7: Configure Compliance Dashboards

\`\`\`  
1\. Navigate: Monitor → Compliance  
2\. Select Dashboard Template:  
   \- Cloud Security Posture  
   \- Industry Compliance  
   \- Custom Dashboard  
3\. Add Widgets:  
   \- Compliance Overview  
   \- Policy Violations Trend  
   \- Resource Compliance by Account  
   \- Top Violated Policies  
4\. Set Filters:  
   \- Time Range  
   \- Accounts/Regions  
   \- Severity Levels  
5\. Save Dashboard  
\`\`\`

Step 8: Scheduled Reports

\`\`\`  
1\. Monitor → Reports → Create Report  
2\. Configure:  
   \- Report Name: "Weekly CSPM Compliance"  
   \- Format: PDF/CSV  
   \- Schedule: Weekly/Monthly  
   \- Recipients: \[Security Team Emails\]  
3\. Content Sections:  
   \- Executive Summary  
   \- Compliance Status  
   \- Top Risks  
   \- Remediation Tracking  
4\. Save & Activate  
\`\`\`

5\. ALERTING & NOTIFICATION CONFIGURATION

Step 9: Configure Alert Rules

\`\`\`  
1\. Alerts → Alert Rules → Add Rule  
2\. Rule Criteria:  
   \- Policy Severity: High/Medium  
   \- Policy Category: Compliance/Security  
   \- Resource Types: \[Select relevant\]  
3\. Notification Channels:  
   \- Primary: Email Security Team  
   \- Secondary: Slack Channel  
   \- Critical: PagerDuty/SIEM  
4\. Suppression Rules:  
   \- Business Hours Only  
   \- Exclude Test Resources  
5\. Save & Enable Rule  
\`\`\`

Step 10: SIEM Integration (Optional)

\`\`\`  
1\. Settings → Integrations → SIEM  
2\. Select: Splunk/QRadar/ArcSight/etc.  
3\. Configure:  
   \- SIEM Server Details  
   \- API Token/Keys  
   \- Log Format: CEF/LEEF/JSON  
4\. Test Connection  
5\. Enable Forwarding  
\`\`\`

6\. ADVANCED CONFIGURATIONS

Step 11: Resource Query Language (RQL) Optimization

\`\`\`sql  
\-- Example RQL for CSPM monitoring  
config from cloud.resource where   
cloud.type \= 'aws' AND   
api.name \= 'aws-ec2-describe-instances' AND   
json.rule \= 'securityGroups\[\*\].groupName does not contain "bastion"' AND   
tags.Environment \= 'production'  
\`\`\`

Step 12: Custom Compliance Frameworks

\`\`\`  
1\. Policies → Compliance Standards → Custom  
2\. Create Framework:  
   \- Name: "Internal Security Standard"  
   \- Add Controls  
   \- Map Policies to Controls  
3\. Weight Controls (if scoring needed)  
4\. Generate Compliance Reports  
\`\`\`

Step 13: Tag-Based Governance

\`\`\`  
1\. Configure mandatory tags:  
   \- Environment  
   \- Owner  
   \- CostCenter  
   \- DataClassification  
2\. Create policies to enforce tagging  
3\. Set up alerts for non-compliance  
\`\`\`

7\. VALIDATION & TESTING

Step 14: Post-Configuration Validation

\`\`\`  
✅ Validation Checklist:  
1\. All cloud accounts show "Connected" status  
2\. Data collection timestamp is recent (\<24 hours)  
3\. Policies are enabled and showing results  
4\. Test alerts are received  
5\. Dashboards display data  
6\. API access verified  
7\. User permissions validated  
\`\`\`

Step 15: Generate Test Violations

\`\`\`bash  
\# AWS Test (creates policy violation)  
aws ec2 run-instances \\  
    \--image-id ami-12345678 \\  
    \--instance-type t2.micro \\  
    \--no-associate-public-ip-address

\# Verify in Prisma Cloud within 6-12 hours  
\`\`\`

8\. OPERATIONAL PROCEDURES

Daily Operations:

\`\`\`  
1\. Review Dashboard: Compliance posture  
2\. Check Alerts: New critical/high violations  
3\. Monitor Collections: Last successful scan  
4\. Review Exceptions: Expiring/needing renewal  
\`\`\`

Weekly Operations:

\`\`\`  
1\. Run Compliance Reports  
2\. Review Policy Effectiveness  
3\. Update Policies based on new threats  
4\. Clean up stale exceptions  
\`\`\`

Monthly Operations:

\`\`\`  
1\. Review User Access  
2\. Audit Configuration Changes  
3\. Update Compliance Frameworks  
4\. Performance Tuning  
\`\`\`

9\. TROUBLESHOOTING GUIDE

Issue Possible Cause Resolution  
No data in console Collection failed Check cloud account permissions  
Policies not triggering RQL incorrect Validate query in RQL editor  
Alerts not sending Notification misconfigured Test notification channel  
High latency Large environment Adjust collection schedule

10\. DOCUMENTATION & HANDOVER

Required Documentation:

\`\`\`  
1\. Account Configuration Details  
2\. Policy Inventory  
3\. Exception Register  
4\. Compliance Reports Archive  
5\. Contact List  
6\. Escalation Matrix  
\`\`\`

\---

APPENDIX: QUICK REFERENCE

API Endpoints for Automation:

\`\`\`bash  
\# Get compliance posture  
GET /v2/compliance

\# List policies  
GET /v2/policy

\# Trigger scan  
POST /v2/cloud/{cloudType}/scan  
\`\`\`

Support Resources:

· Prisma Cloud Docs: https://docs.paloaltonetworks.com/prisma-cloud  
· RQL Guide: https://docs.paloaltonetworks.com/prisma-cloud/prisma-cloud-rql-reference  
· API Reference: https://api.prismacloud.io

\---

Change Record:

Date Version Changes Author  
Initial 1.0 Initial Release \[Your Name\]

Approvals:

· Security Architect: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
· Cloud Operations: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
· Compliance Officer: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

Note: This SOP should be reviewed quarterly and updated based on Prisma Cloud feature releases and organizational changes.