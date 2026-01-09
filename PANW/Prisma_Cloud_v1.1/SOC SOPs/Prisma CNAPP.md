Prisma Cloud CNAPP Configuration Guide

 Step-by-Step SOP for Cloud-Native Application Protection Platform

1\. CNAPP ARCHITECTURE OVERVIEW

1.1 CNAPP Integration Matrix

\`\`\`  
Prisma Cloud CNAPP \= CSPM \+ CWPP \+ CIEM \+ DSPM \+ API Security  
                    ↓  
          Unified Risk Management  
                    ↓  
├── Infrastructure Security (CSPM)  
├── Workload Security (CWPP)  
├── Identity Security (CIEM)  
├── Data Security (DSPM)  
├── API Security (WAAS)  
└── Threat Detection (XDR)  
\`\`\`

1.2 CNAPP Components Mapping

Component Module Protection Layer  
Code Security IDE Plugins, CI/CD Shift Left  
Infrastructure Security CSPM, IaC Scan Build  
Registry Security Image Scan Deploy  
Runtime Security CWPP, WAAS Run  
Data Security DSPM, DLP Data  
Identity Security CIEM, RBAC Identity

2\. PRE-DEPLOYMENT ASSESSMENT

Step 1: Environment Discovery & Inventory

\`\`\`  
1\. Navigate: Dashboards → Cloud Resources  
2\. Run Discovery:  
   \- Compute → Manage → Discovery → Scan All  
   \- Settings → Data Collection → Full Inventory  
3\. Generate Inventory Report:  
   \- Assets by cloud  
   \- Assets by environment  
   \- Unprotected assets  
4\. Risk Assessment:  
   \- Prisma Cloud → Risk Spotlight  
   \- Export risk assessment report  
\`\`\`

Step 2: License & Feature Enablement

\`\`\`  
1\. Verify CNAPP License:  
   \- Settings → Subscription  
   \- Required: Enterprise \+ Compute  
2\. Enable Features:  
   \- CIEM: Settings → Identity Security → Enable  
   \- DSPM: Settings → Data Security → Enable  
   \- API Security: Compute → WAAS → Enable  
   \- IaC Security: Build Security → Enable  
3\. Configure Data Retention:  
   \- Settings → Data Management  
   \- Recommended: 90 days for compliance  
\`\`\`

3\. UNIFIED DEFENDER DEPLOYMENT

Step 3: Deploy Unified CNAPP Agent

\`\`\`yaml  
\# values-cnapp.yaml \- Helm Chart for Unified Deployment  
global:  
  consoleUrl: "https://\<tenant\>.prismacloud.io"  
  clusterName: "cnapp-prod-cluster"  
  namespace: "prisma-cloud"

\# Unified Defender Configuration  
defender:  
  type: "unified"  
  capabilities:  
    \- runtime  
    \- waas  
    \- network  
    \- filesystem  
  token: "\<UNIFIED\_TOKEN\>"  
    
\# CSPM Integration  
cspm:  
  enabled: true  
  cloudAccounts:  
    \- aws  
    \- azure  
    \- gcp  
  scanningMode: "continuous"

\# CIEM Configuration  
ciem:  
  enabled: true  
  identityDiscovery: true  
  permissionAnalysis: true

\# Deploy with Helm  
helm upgrade \--install prisma-cnapp prismacloud/prisma-cloud \\  
  \-n prisma-cloud \--create-namespace \\  
  \-f values-cnapp.yaml  
\`\`\`

Step 4: Multi-Cloud Integration Setup

AWS Organization Integration:

\`\`\`bash  
\# Enable AWS Organization Integration  
1\. Console → Settings → Cloud Accounts → AWS → Organization  
2\. Create StackSet in AWS Management Account:  
   \- Template: Prisma Cloud Organization Template  
   \- Deploy to: All accounts/Select OUs  
3\. Enable:  
   \- CSPM for all accounts  
   \- CIEM for IAM analysis  
   \- GuardDuty integration  
\`\`\`

Azure Tenant Integration:

\`\`\`bash  
\# Configure Azure Tenant-wide  
1\. Azure Portal → Enterprise Apps  
2\. Add Prisma Cloud Enterprise App  
3\. Assign roles:  
   \- Reader (tenant-wide)  
   \- Security Reader  
   \- Storage Blob Data Reader  
4\. Enable Azure Security Center integration  
\`\`\`

4\. SHIFT-LEFT SECURITY CONFIGURATION

Step 5: Infrastructure as Code Security

Terraform Scanning Setup:

\`\`\`hcl  
\# terraform-prisma.tf  
terraform {  
  required\_providers {  
    prismacloud \= {  
      source \= "PaloAltoNetworks/prismacloud"  
    }  
  }  
}

\# Scan configuration  
resource "prismacloud\_policy" "iac\_scan" {  
  policy\_type \= "config"  
  cloud\_type  \= "aws"  
  rule {  
    name \= "terraform-compliance"  
    rule\_type \= "Config"  
  }  
}

\# CI/CD Integration  
resource "prismacloud\_integration" "ci\_cd" {  
  name \= "github-actions"  
  integration\_type \= "github"  
}  
\`\`\`

GitHub Actions Workflow:

\`\`\`yaml  
name: CNAPP Security Scan  
on: \[push, pull\_request\]

jobs:  
  security-scan:  
    runs-on: ubuntu-latest  
    steps:  
    \- name: Checkout  
      uses: actions/checkout@v3  
        
    \- name: IaC Scan  
      uses: prismacloud/iac-scan-action@v1  
      with:  
        template-type: "terraform"  
        token: ${{ secrets.PRISMA\_TOKEN }}  
          
    \- name: Container Scan  
      uses: prismacloud/container-scan-action@v1  
      with:  
        image: ${{ secrets.REGISTRY }}/app:${{ github.sha }}  
          
    \- name: Secrets Scan  
      uses: prismacloud/secrets-scan-action@v1  
\`\`\`

Step 6: IDE Plugin Configuration

VS Code Configuration:

\`\`\`json  
{  
  "prisma.cloud.enabled": true,  
  "prisma.cloud.tenant": "https://\<tenant\>.prismacloud.io",  
  "prisma.cloud.token": "\<IDE\_TOKEN\>",  
  "prisma.cloud.scanOnSave": true,  
  "prisma.cloud.scanTypes": \[  
    "secrets",  
    "iac",  
    "vulnerabilities"  
  \]  
}  
\`\`\`

5\. IDENTITY SECURITY (CIEM) CONFIGURATION

Step 7: Configure CIEM Risk Policies

\`\`\`  
1\. Navigate: Monitor → Identity Security  
2\. Configure Discovery:  
   \- Enable auto-discovery: ✓  
   \- Scan frequency: 6 hours  
   \- Include: Users, Roles, Policies, Groups  
3\. Risk Policies:  
   \- Over-permissioned roles  
   \- Stale credentials (\>90 days)  
   \- Cross-account trust risks  
   \- Privilege escalation paths  
4\. Remediation Workflows:  
   \- Auto-revoke unused credentials  
   \- JIT access requests  
   \- Permission boundary enforcement  
\`\`\`

Step 8: Identity Governance Workflows

\`\`\`yaml  
\# JIT Access Configuration  
accessManagement:  
  enabled: true  
  approvalWorkflow:  
    \- manager\_approval  
    \- security\_review  
  maxDuration: "8h"  
  entitlements:  
    \- aws:PowerUserAccess  
    \- azure:Contributor  
    
\# Permission Analytics  
permissionAnalytics:  
  baselinePeriod: "30d"  
  anomalyDetection: true  
  outlierThreshold: "2"  
\`\`\`

6\. DATA SECURITY (DSPM) CONFIGURATION

Step 9: Data Classification & Discovery

\`\`\`  
1\. Navigate: Monitor → Data Security  
2\. Configure Data Discovery:  
   \- Storage Types: S3, RDS, Blob Storage, BigQuery  
   \- Scan Schedule: Daily  
   \- Sample Size: 1000 records  
3\. Classification Engines:  
   \- Built-in: PII, PCI, PHI  
   \- Custom: Regex patterns  
   \- ML-based: Contextual classification  
4\. Data Flow Mapping:  
   \- Source → Processing → Storage  
   \- Enable data lineage tracking  
\`\`\`

Step 10: Data Protection Policies

\`\`\`sql  
\-- Example DSPM Policy Configuration  
Policy: "S3 Bucket with PII Data"  
Conditions:  
  \- resource.type \= 'aws-s3'  
  \- data.classification CONTAINS 'PII'  
  \- encryption.status \!= 'enabled'  
  \- access.public \= true  
Actions:  
  \- Alert: High severity  
  \- Auto-remediate: Enable encryption  
  \- Notify: Data Protection Officer  
\`\`\`

7\. API SECURITY CONFIGURATION

Step 11: WAAS Advanced Configuration

\`\`\`yaml  
\# WAAS Configuration for Microservices  
waas:  
  enabled: true  
  applications:  
    \- name: "payment-service"  
      host: "api.payments.example.com"  
      protectionMode: "prevention"  
      apiDiscovery:  
        enabled: true  
        mode: "learning"  
        duration: "14d"  
      securityRules:  
        \- rule: "sql-injection"  
          action: "block"  
        \- rule: "broken-authentication"  
          action: "alert"  
        \- rule: "sensitive-data-exposure"  
          action: "block"  
            
    \- name: "inventory-service"  
      host: "api.inventory.example.com"  
      protectionMode: "detection"  
\`\`\`

Step 12: API Inventory & Risk Assessment

\`\`\`  
1\. Compute → WAAS → API Security  
2\. Run API Discovery:  
   \- Traffic analysis period: 7 days  
   \- Include: Swagger/OpenAPI specs  
   \- Classify: Internal/External APIs  
3\. Risk Assessment:  
   \- Unauthenticated endpoints  
   \- Deprecated API versions  
   \- Excessive data exposure  
4\. Generate API Catalog:  
   \- Export to Swagger  
   \- Sync with API Gateway  
\`\`\`

8\. UNIFIED POLICY MANAGEMENT

Step 13: Create Cross-Layer Policies

\`\`\`  
Policy: "Full Stack Compliance Policy"  
Scope: Payment Processing Application  
Components:  
1\. Infrastructure (CSPM):  
   \- VPC flow logs enabled  
   \- Encryption at rest  
   \- Security groups restrictive  
     
2\. Workload (CWPP):  
   \- No critical vulnerabilities  
   \- Runtime protection enabled  
   \- File integrity monitoring  
     
3\. Identity (CIEM):  
   \- Least privilege principles  
   \- MFA enforced  
   \- Session timeout \< 1 hour  
     
4\. Data (DSPM):  
   \- PCI data encrypted  
   \- Access logging enabled  
   \- Data residency compliance  
     
5\. API (WAAS):  
   \- WAF protection enabled  
   \- Rate limiting configured  
   \- Input validation  
\`\`\`

Step 14: Policy-as-Code Configuration

\`\`\`yaml  
\# policies/cnapp-policies.yaml  
apiVersion: prismacloud.io/v1  
kind: PolicySet  
metadata:  
  name: production-compliance  
spec:  
  policies:  
    \- name: pci-dss-full-stack  
      type: compliance  
      cloudType: all  
      rules:  
        \- rule: "infrastructure.pci.encryption"  
          severity: "high"  
        \- rule: "workload.pci.vulnerability"  
          severity: "critical"  
            
    \- name: gdpr-data-protection  
      type: data  
      rules:  
        \- rule: "data.pii.encryption"  
          action: "auto-remediate"  
\`\`\`

9\. THREAT DETECTION & RESPONSE

Step 15: Configure Unified Threat Detection

\`\`\`  
1\. Navigate: Monitor → Alerts → Threat Detection  
2\. Enable ML-based Detection:  
   \- Anomaly detection: ✓  
   \- UEBA for identities: ✓  
   \- Threat intelligence feeds: ✓  
3\. Configure Correlation Rules:  
   \- Alert \+ Vulnerability \= Threat  
   \- Unusual access \+ Data exfiltration \= Incident  
   \- Network anomaly \+ Crypto mining \= Critical  
4\. Automated Response:  
   \- Isolate compromised workloads  
   \- Revoke suspicious identities  
   \- Quarantine sensitive data  
\`\`\`

Step 16: XDR Integration Setup

\`\`\`yaml  
\# XDR Configuration  
xdr:  
  enabled: true  
  integrations:  
    \- siem: splunk  
      endpoint: https://splunk.company.com:8088  
      token: \<SPLUNK\_TOKEN\>  
        
    \- edr: crowdstrike  
      endpoint: https://api.crowdstrike.com  
      client\_id: \<CS\_CLIENT\_ID\>  
        
    \- ticketing: servicenow  
      instance: company.service-now.com  
      username: prisma\_integration  
        
  playbooks:  
    \- name: "ransomware-response"  
      triggers:  
        \- "file.encryption.pattern"  
        \- "unusual.file.access"  
      actions:  
        \- isolate\_host  
        \- snapshot\_forensics  
        \- alert\_soc  
\`\`\`

10\. UNIFIED DASHBOARD & REPORTING

Step 17: CNAPP Executive Dashboard

\`\`\`  
1\. Create Dashboard: Dashboards → New → CNAPP Executive  
2\. Add Widgets:  
   \- Overall Risk Score  
   \- Compliance Posture by Framework  
   \- Top Risks by Business Unit  
   \- Security Debt Trend  
   \- MTTR Metrics  
   \- Cost of Security Issues  
3\. Configure Business Context:  
   \- Map resources to business units  
   \- Assign risk owners  
   \- Set SLA expectations  
\`\`\`

Step 18: Automated Compliance Reporting

\`\`\`python  
\# compliance-report-automation.py  
import prismacloud.api as pc

\# Initialize client  
client \= pc.PrismaCloudClient(  
    tenant='\<tenant\>.prismacloud.io',  
    username='api-user',  
    password='\<api-key\>'  
)

\# Generate comprehensive report  
report \= client.compliance.generate\_report(  
    frameworks=\['cis', 'nist', 'pci', 'gdpr'\],  
    format='pdf',  
    include=\['executive\_summary', 'detailed\_findings', 'remediation\_plan'\]  
)

\# Distribute automatically  
report.distribute(  
    emails=\['ciso@company.com', 'compliance@company.com'\],  
    slack\_channel='\#security-compliance',  
    sharepoint\_path='/Compliance/Reports/'  
)  
\`\`\`

11\. OPERATIONAL PROCEDURES

Daily CNAPP Operations:

\`\`\`  
1\. Unified Alert Review:  
   \- Priority 1 incidents (\<15 min response)  
   \- Cross-layer correlations  
   \- False positive analysis  
     
2\. Health Check:  
   \- Agent connectivity  
   \- Data collection status  
   \- License utilization  
     
3\. Risk Review:  
   \- New critical vulnerabilities  
   \- Identity permission drift  
   \- Data exposure incidents  
\`\`\`

Weekly CNAPP Operations:

\`\`\`  
1\. Compliance Status Review:  
   \- Framework compliance scores  
   \- Policy violation trends  
   \- Exception management  
     
2\. Threat Hunting:  
   \- Proactive threat queries  
   \- Attack path analysis  
   \- Red team exercise review  
     
3\. Optimization:  
   \- Policy tuning  
   \- Alert noise reduction  
   \- Resource optimization  
\`\`\`

Monthly CNAPP Operations:

\`\`\`  
1\. Board Reporting:  
   \- Risk metrics compilation  
   \- ROI calculation  
   \- Security program effectiveness  
     
2\. Architecture Review:  
   \- Coverage gaps  
   \- New feature adoption  
   \- Integration enhancements  
     
3\. Training & Enablement:  
   \- Team skill assessment  
   \- New feature training  
   \- Process optimization  
\`\`\`

12\. INCIDENT RESPONSE PLAYBOOKS

Playbook: Data Breach Response

\`\`\`  
1\. Detection Phase:  
   \- DSPM alert: Sensitive data access anomaly  
   \- CIEM alert: Privilege escalation  
   \- CWPP alert: Data exfiltration process  
     
2\. Containment Phase:  
   \- Auto-isolate affected workloads  
   \- Revoke compromised identities  
   \- Block exfiltration channels  
     
3\. Investigation Phase:  
   \- Unified timeline reconstruction  
   \- Data lineage trace  
   \- Attacker TTP analysis  
     
4\. Recovery Phase:  
   \- Data restoration from backups  
   \- Credential rotation  
   \- Policy hardening  
\`\`\`

Playbook: Ransomware Attack

\`\`\`  
Triggers:  
  \- CWPP: Mass file encryption  
  \- Network: C2 communication  
  \- DSPM: Unusual file access patterns

Response:  
  1\. Immediate isolation of affected systems  
  2\. Network segmentation  
  3\. Forensic snapshot capture  
  4\. Threat intelligence correlation  
  5\. Recovery orchestration  
\`\`\`

13\. ADVANCED FEATURES CONFIGURATION

Step 19: Attack Path Analysis

\`\`\`  
1\. Navigate: Monitor → Attack Path  
2\. Configure Analysis:  
   \- Include: All cloud resources  
   \- Critical assets: Define crown jewels  
   \- Attack simulations: Weekly  
3\. Remediation Prioritization:  
   \- Risk-based scoring  
   \- Effort vs. impact analysis  
   \- Automated remediation plans  
\`\`\`

Step 20: Security Orchestration Automation

\`\`\`yaml  
\# soar-configuration.yaml  
orchestration:  
  enabled: true  
  playbooks:  
    \- name: "vulnerability-remediation"  
      trigger: "critical\_vulnerability"  
      actions:  
        \- create\_jira\_ticket  
        \- notify\_owner  
        \- schedule\_patching  
          
    \- name: "permission-cleanup"  
      trigger: "over\_permissioned\_role"  
      actions:  
        \- request\_review  
        \- auto\_revoke\_if\_expired  
        \- audit\_log  
\`\`\`

14\. INTEGRATIONS ECOSYSTEM

Step 21: CI/CD Pipeline Integration

\`\`\`groovy  
// Jenkins Pipeline with CNAPP  
pipeline {  
    agent any  
    stages {  
        stage('CNAPP Security Gates') {  
            parallel {  
                stage('IaC Security') {  
                    steps { sh 'prisma iac-scan \--dir ./terraform' }  
                }  
                stage('Container Security') {  
                    steps { sh 'prisma image-scan myapp:$BUILD\_ID' }  
                }  
                stage('Secrets Detection') {  
                    steps { sh 'prisma secrets-scan \--dir .' }  
                }  
            }  
        }  
        stage('Deployment Security') {  
            steps {  
                sh 'prisma deploy-scan \--manifest k8s.yaml'  
            }  
        }  
    }  
}  
\`\`\`

Step 22: ServiceNow Integration

\`\`\`  
1\. Settings → Integrations → ServiceNow  
2\. Configure:  
   \- Instance URL  
   \- API credentials  
   \- CMDB mapping  
3\. Sync Configuration:  
   \- Assets → CMDB  
   \- Vulnerabilities → Incidents  
   \- Compliance → Audit items  
4\. Automated Workflows:  
   \- Vulnerability management  
   \- Access certification  
   \- Policy exception requests  
\`\`\`

15\. PERFORMANCE OPTIMIZATION

Step 23: Scaling Configuration

\`\`\`yaml  
\# Production Scaling Configuration  
resources:  
  defender:  
    replicas: "auto"  
    scaling:  
      min: 10  
      max: 100  
      metrics:  
        \- type: cpu  
          target: 70%  
        \- type: memory  
          target: 80%  
            
  scanner:  
    replicas: 3  
    queueManagement:  
      maxConcurrentScans: 10  
      priorityQueuing: true  
        
  console:  
    cache:  
      size: "10Gi"  
      ttl: "1h"  
\`\`\`

Step 24: Cost Optimization

\`\`\`  
1\. Data Management:  
   \- Compression: Enable  
   \- Retention: Tiered (90d hot, 1y cold)  
   \- Archival: Automate old data  
     
2\. Scanning Optimization:  
   \- Smart scheduling  
   \- Incremental scanning  
   \- Resource limits  
     
3\. License Optimization:  
   \- Right-size subscriptions  
   \- Usage monitoring  
   \- Capacity planning  
\`\`\`

16\. BACKUP & DISASTER RECOVERY

CNAPP Backup Procedure:

\`\`\`bash  
\#\!/bin/bash  
\# Backup CNAPP Configuration  
BACKUP\_DIR="/backups/prisma-cnapp"  
DATE=$(date \+%Y%m%d)

\# Backup configurations  
curl \-H "Authorization: Bearer $TOKEN" \\  
  https://\<tenant\>.prismacloud.io/api/v1/settings \\  
  \-o $BACKUP\_DIR/settings\_$DATE.json

\# Backup policies  
curl \-H "Authorization: Bearer $TOKEN" \\  
  https://\<tenant\>.prismacloud.io/api/v1/policies \\  
  \-o $BACKUP\_DIR/policies\_$DATE.json

\# Backup compliance frameworks  
curl \-H "Authorization: Bearer $TOKEN" \\  
  https://\<tenant\>.prismacloud.io/api/v1/compliance \\  
  \-o $BACKUP\_DIR/compliance\_$DATE.json  
\`\`\`

Disaster Recovery Runbook:

\`\`\`  
1\. Infrastructure Recovery:  
   \- Restore console from backup  
   \- Re-deploy agents  
   \- Verify connectivity  
     
2\. Data Recovery:  
   \- Restore configuration  
   \- Sync historical data  
   \- Validate integrity  
     
3\. Business Continuity:  
   \- Failover to secondary region  
   \- Minimum viable monitoring  
   \- Gradual feature enablement  
\`\`\`

\---

APPENDIX: CNAPP QUICK REFERENCE

CNAPP API Examples:

\`\`\`python  
\# Unified Risk Query  
GET /api/v1/risk/query  
{  
  "filters": {  
    "timeRange": {"relative": "LAST\_7\_DAYS"},  
    "severity": \["critical", "high"\],  
    "resourceTypes": \["compute", "storage", "identity"\]  
  }  
}

\# Cross-layer Alert Correlation  
POST /api/v1/alerts/correlate  
{  
  "alertTypes": \["vulnerability", "compliance", "runtime"\],  
  "timeWindow": "1h",  
  "resourceId": "resource-123"  
}  
\`\`\`

CNAPP CLI Commands:

\`\`\`bash  
\# Install CNAPP CLI  
curl \-o prisma-cnapp https://\<tenant\>.prismacloud.io/download/cnapp-cli  
chmod \+x prisma-cnapp

\# Export full security posture  
prisma-cnapp export posture \--format json \--output security-posture.json

\# Generate executive report  
prisma-cnapp report executive \--period Q1-2024 \--output report.pdf  
\`\`\`

CNAPP Metrics & KPIs:

\`\`\`yaml  
Key Performance Indicators:  
  \- Mean Time to Detect (MTTD): \<1 hour  
  \- Mean Time to Respond (MTTR): \<4 hours  
  \- Critical Vulnerability Age: \<7 days  
  \- Policy Compliance Rate: \>95%  
  \- Agent Health Score: \>99%  
  \- False Positive Rate: \<5%  
\`\`\`

Support & Resources:

· CNAPP Documentation: https://docs.paloaltonetworks.com/prisma-cloud  
· API Reference: https://api.docs.prismacloud.io  
· Community: https://live.paloaltonetworks.com/prisma-cloud  
· Training: https://www.paloaltonetworks.com/services/education

\---

CNAPP Configuration Sign-off:

Phase Completed By Date Verified By  
Pre-deployment Assessment     
Unified Defender Deployment     
Shift-Left Configuration     
CIEM & DSPM Setup     
Policy Configuration     
Integration & Testing     
Production Cutover   

Final Approvals:

· CISO: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
· Cloud Architecture: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
· Compliance Officer: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
· DevOps Lead: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

This CNAPP SOP should be reviewed quarterly and updated based on new feature releases, organizational changes, and evolving threat landscape.