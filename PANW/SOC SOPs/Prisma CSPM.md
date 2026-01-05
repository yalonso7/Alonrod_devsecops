Prisma Cloud CWPP (Compute) Configuration Guide

Comprehensive Step-by-Step SOP for Workload Protection

1\. PRE-DEPLOYMENT PLANNING

1.1 CWPP Architecture Overview

\`\`\`  
Prisma Cloud Console  
├── Defenders (Agents)  
│   ├── Container Defender (DaemonSet/Sidecar)  
│   ├── Host Defender (Linux/Windows)  
│   └── Serverless Defender (Lambda Extension)  
├── Scanner (Image Registry)  
└── Runtime Protection Engine  
\`\`\`

1.2 Prerequisites Checklist

\`\`\`  
☐ Prisma Cloud Compute Edition License  
☐ Network Requirements:  
   \- Defender → Console: TCP 443 (outbound)  
   \- Console → Defender: TCP 8084 (optional, for reverse connection)  
   \- Scanner → Registry: Registry-specific ports  
☐ Supported Platforms:  
   \- Linux: Ubuntu, RHEL, CentOS, Amazon Linux  
   \- Windows: Server 2016/2019/2022  
   \- Kubernetes: 1.18+  
   \- Container Runtimes: Docker, containerd, CRI-O  
   \- Cloud: ECS, EKS, AKS, GKE, OpenShift  
\`\`\`

2\. DEFENDER DEPLOYMENT SOP

Step 1: Access Compute Console

\`\`\`  
1\. Navigate: https://\<tenant\>.prismacloud.io/compute  
2\. Login with credentials  
3\. Verify Compute license is active  
\`\`\`

Step 2: Generate Defender Daemon Token

\`\`\`  
1\. Compute → Manage → Defenders → Deploy  
2\. Click "Add Daemon Set" (for Kubernetes)  
3\. Generate unique token:  
   \- Token Name: "prod-cluster-token"  
   \- Description: "Production EKS cluster"  
   \- Expiration: 90 days (recommended)  
4\. Copy token securely (will not be shown again)  
\`\`\`

Step 3: Deploy Container Defender (Kubernetes)

Method A: Using Helm (Recommended)

\`\`\`bash  
\# Add Prisma Cloud repo  
helm repo add prismacloud https://prismacloud.github.io/helm-charts  
helm repo update

\# Create values.yaml  
cat \> values.yaml \<\< EOF  
consoleUrl: https://\<tenant\>.prismacloud.io  
namespace: twistlock  
clusterName: "prod-eks-01"  
orchestration: kubernetes

\# Defender configuration  
defender:  
  enabled: true  
  type: daemonset  
  token: "\<DAEMON\_TOKEN\>"  
  port: 8084  
  listenAddr: "0.0.0.0"  
    
\# Scanner configuration  
scanner:   
  enabled: true  
  replicas: 2  
  token: "\<SCANNER\_TOKEN\>"  
EOF

\# Deploy  
helm upgrade \--install twistlock prismacloud/twistlock \\  
  \--namespace twistlock \--create-namespace \\  
  \-f values.yaml  
\`\`\`

Method B: Using Manifest (Operator)

\`\`\`bash  
\# Download deployment script  
curl \-k \-o deploy.sh \\  
  https://\<tenant\>.prismacloud.io/api/v1/defenders/deploy.sh

\# Make executable and run  
chmod \+x deploy.sh  
./deploy.sh \--type daemonset \\  
  \--token "\<DAEMON\_TOKEN\>" \\  
  \--namespace twistlock  
\`\`\`

Step 4: Deploy Host Defender (Linux VM/Instance)

\`\`\`bash  
\# Download defender  
curl \-k \-o defender.tar.gz \\  
  https://\<tenant\>.prismacloud.io/api/v1/defenders/image/defender.tar.gz

\# Extract and install  
tar \-xzvf defender.tar.gz  
cd defender\_install

\# Install with token  
sudo ./install.sh \\  
  \--type host \\  
  \--token "\<HOST\_TOKEN\>" \\  
  \--cluster "\<CLUSTER\_NAME\>"  
\`\`\`

Step 5: Deploy Serverless Defender (AWS Lambda)

\`\`\`yaml  
\# serverless.yml configuration  
provider:  
  name: aws  
  runtime: nodejs14.x

functions:  
  myFunction:  
    handler: handler.hello  
    layers:  
      \- arn:aws:lambda:us-east-1:{{PRISMA\_ACCOUNT}}:layer:prisma-lambda-extension:1  
    environment:  
      PRISMA\_TOKEN: \<LAMBDA\_TOKEN\>  
      PRISMA\_CONSOLE: https://\<tenant\>.prismacloud.io  
\`\`\`

3\. REGISTRY INTEGRATION & VULNERABILITY SCANNING

Step 6: Configure Image Registry Scanning

\`\`\`  
1\. Compute → Manage → Registries → Add Registry  
2\. Select Registry Type:  
   \- AWS ECR  
   \- Docker Hub  
   \- Azure Container Registry  
   \- Google Container Registry  
   \- Harbor  
   \- JFrog Artifactory  
3\. Configure Credentials:  
   \- Access Key/Secret  
   \- Service Account  
   \- IAM Role (for ECR)  
4\. Set Scan Settings:  
   \- Scan on Push: ✓  
   \- Scan Layers: ✓  
   \- CVSS Threshold: 7.0  
5\. Test Connection → Save  
\`\`\`

Step 7: Configure CI/CD Pipeline Scanning

Jenkins Pipeline Example:

\`\`\`groovy  
pipeline {  
    agent any  
      
    stages {  
        stage('Build & Scan') {  
            steps {  
                // Build image  
                sh 'docker build \-t myapp:${BUILD\_ID} .'  
                  
                // Scan with Prisma Cloud  
                sh '''  
                docker run \--rm \\  
                  \-v /var/run/docker.sock:/var/run/docker.sock \\  
                  prismacloud/scan:latest \\  
                  scan \--token \<SCAN\_TOKEN\> \\  
                  \--console https://\<tenant\>.prismacloud.io \\  
                  \--image myapp:${BUILD\_ID}  
                '''  
            }  
        }  
    }  
}  
\`\`\`

GitHub Actions Example:

\`\`\`yaml  
name: Container Security Scan  
on: \[push\]

jobs:  
  security-scan:  
    runs-on: ubuntu-latest  
    steps:  
    \- uses: actions/checkout@v2  
      
    \- name: Build Docker image  
      run: docker build \-t myapp:${{ github.sha }} .  
        
    \- name: Prisma Cloud Scan  
      uses: prismacloud/action-scan@v1  
      with:  
        image: myapp:${{ github.sha }}  
        token: ${{ secrets.PRISMA\_TOKEN }}  
        console: https://\<tenant\>.prismacloud.io  
\`\`\`

4\. RUNTIME POLICY CONFIGURATION

Step 8: Configure Runtime Policies

\`\`\`  
1\. Compute → Policies → Runtime → Add Rule  
2\. Rule Configuration:  
   \- Rule Name: "Block crypto miners"  
   \- Severity: Critical  
   \- Scope: All containers/hosts  
3\. Process Rules:  
   \- Block: /usr/bin/minerd  
   \- Block: xmrig, cpuminer  
4\. File Rules:  
   \- Monitor: /etc/passwd modifications  
   \- Block: /tmp/.X11-unix modifications  
5\. Network Rules:  
   \- Alert: Outbound to known C2 IPs  
   \- Block: Unauthorized DNS servers  
6\. Save & Enable  
\`\`\`

Step 9: Configure Container Firewall Rules

\`\`\`yaml  
\# Example Network Firewall Policy  
Rule Name: "Web Container Egress"  
Scope:   
  \- Label: app=web  
  \- Label: tier=frontend  
Action: Alert/Block  
Direction: Egress  
Ports:  
  \- 443 (HTTPS to external)  
  \- 3306 (MySQL to internal)  
  \- 6379 (Redis to internal)  
CIDR:  
  \- Allow: 10.0.0.0/8  
  \- Block: 0.0.0.0/0 (default deny)  
\`\`\`

Step 10: Configure Waas (Web App & API Security)

\`\`\`  
1\. Compute → WAAS → Add Rule  
2\. Configure:  
   \- App ID: "customer-portal"  
   \- Hostname: portal.example.com  
   \- Default Action: Block  
3\. Add Security Rules:  
   \- SQL Injection Prevention: Block  
   \- XSS Prevention: Block  
   \- API Protection: ✓  
   \- DDoS Protection: Rate limit 1000 req/min  
4\. Learning Mode: Enable for 7 days  
5\. Deploy WAAS Defender  
\`\`\`

5\. VULNERABILITY MANAGEMENT

Step 11: Configure Vulnerability Policies

\`\`\`  
1\. Compute → Policies → Vulnerabilities → Add Policy  
2\. Set Criteria:  
   \- CVSS Score: \> 7.0 (High/Critical)  
   \- Exploit Available: Yes  
   \- Package Type: OS and Application  
   \- Fix Available: Yes  
3\. Actions:  
   \- Alert: ✓  
   \- Block Image: ✓ (if CVSS \> 9.0)  
   \- Enforce in CI/CD: ✓  
4\. Exceptions:  
   \- CVE-XXXX-XXXX: Until 2024-12-31  
   \- Justification: "Legacy app, migrating Q2"  
\`\`\`

Step 12: Configure Compliance Scanning

\`\`\`  
1\. Compute → Policies → Compliance → Add Policy  
2\. Select Standard:  
   \- CIS Docker Benchmark  
   \- CIS Kubernetes Benchmark  
   \- HIPAA  
   \- PCI DSS  
3\. Set Enforcement:  
   \- Monitor Only  
   \- Block on Failure  
4\. Schedule: Daily scan at 02:00 UTC  
\`\`\`

6\. MONITORING & ALERTING CONFIGURATION

Step 13: Configure Runtime Alerts

\`\`\`  
1\. Compute → Alerts → Add Alert Rule  
2\. Alert Criteria:  
   \- Severity: High/Critical  
   \- Event Types:  
     \- Runtime container escape  
     \- Malicious process execution  
     \- File tampering  
     \- Network anomaly  
3\. Notification Channels:  
   \- Email: soc-team@company.com  
   \- Slack: \#security-alerts  
   \- Webhook: SIEM integration  
   \- PagerDuty: Critical alerts  
4\. Suppression:  
   \- Business hours: 9 AM \- 6 PM  
   \- Ignore test namespaces  
\`\`\`

Step 14: Dashboard Configuration

\`\`\`  
1\. Compute → Monitor → Dashboards → Create  
2\. Add Widgets:  
   \- Runtime Protection Status  
   \- Top Vulnerable Images  
   \- Compliance Posture  
   \- WAAS Attack Map  
   \- Defender Health Status  
3\. Set Filters:  
   \- Environment: Production  
   \- Time Range: Last 7 days  
   \- Cluster: All production clusters  
4\. Save as "Production Security Dashboard"  
\`\`\`

7\. ADVANCED PROTECTIONS

Step 15: Configure Behavioral Threat Detection

\`\`\`  
1\. Compute → Policies → Runtime → Advanced  
2\. Enable Machine Learning:  
   \- Anomaly Detection: ✓  
   \- Learning Period: 14 days  
   \- Baseline: Per workload type  
3\. Configure AI Rules:  
   \- Detect unusual process trees  
   \- Identify crypto mining behavior  
   \- Spot data exfiltration patterns  
4\. Auto-block malicious behavior: ✓  
\`\`\`

Step 16: Secrets Scanning Configuration

\`\`\`  
1\. Compute → Policies → Secrets → Add Rule  
2\. Configure Detection:  
   \- AWS Keys: ^AKIA\[0-9A-Z\]{16}$  
   \- GitHub Tokens: ^ghp\_\[a-zA-Z0-9\]{36}$  
   \- API Keys: Custom regex patterns  
3\. Actions:  
   \- Alert on detection: ✓  
   \- Block commit in CI/CD: ✓  
   \- Auto-revoke detected keys: (via webhook)  
\`\`\`

Step 17: Malware Protection

\`\`\`  
1\. Compute → Defend → Malware → Settings  
2\. Enable:  
   \- Signature-based scanning: ✓  
   \- Heuristic analysis: ✓  
   \- YARA rules: Upload custom rules  
3\. Scheduled Scans:  
   \- Frequency: Daily  
   \- Time: 01:00 UTC  
   \- Full scan: Weekly  
\`\`\`

8\. OPERATIONAL PROCEDURES

Daily Operations Checklist:

\`\`\`  
1\. Check Defender Health Status  
   \- Connected defenders count  
   \- Last check-in time (\< 5 minutes)  
     
2\. Review Critical Alerts  
   \- Runtime incidents  
   \- Vulnerability alerts  
   \- Compliance violations  
     
3\. Monitor WAAS Protection  
   \- Attack attempts blocked  
   \- False positive rate  
     
4\. Check Scan Queue  
   \- Pending registry scans  
   \- CI/CD scan failures  
\`\`\`

Weekly Operations:

\`\`\`  
1\. Review Vulnerability Reports  
   \- New critical vulnerabilities  
   \- Aging vulnerabilities (\> 30 days)  
     
2\. Update Protection Policies  
   \- New threat intelligence  
   \- Application changes  
     
3\. Review Compliance Status  
   \- CIS benchmark compliance  
   \- Policy exceptions review  
     
4\. Defender Version Check  
   \- Update available versions  
   \- Plan maintenance window  
\`\`\`

Incident Response Workflow:

\`\`\`  
1\. Alert Triage:  
   \- Validate alert (true/false positive)  
   \- Determine severity  
     
2\. Investigation:  
   \- Access runtime console  
   \- Review process tree  
   \- Check file system changes  
   \- Analyze network connections  
     
3\. Containment:  
   \- Isolate container/host  
   \- Block malicious process  
   \- Update firewall rules  
     
4\. Remediation:  
   \- Patch vulnerabilities  
   \- Update base images  
   \- Rotate credentials  
     
5\. Post-mortem:  
   \- Root cause analysis  
   \- Update detection rules  
   \- Document lessons learned  
\`\`\`

9\. TROUBLESHOOTING GUIDE

Issue Symptoms Resolution  
Defender offline No heartbeat, logs show connection errors Check network connectivity to console, verify token validity  
Scan failures Images not scanned, registry connection errors Verify registry credentials, check network access to registry  
High resource usage Defender using \>10% CPU/memory Adjust resource limits in deployment, check for noisy workloads  
False positives Benign activities blocked Adjust learning period, add exceptions, tune detection rules  
WAAS not blocking Attacks reaching application Verify WAAS defender deployment, check policy enforcement mode

Common Diagnostic Commands:

\`\`\`bash  
\# Check defender status  
kubectl get pods \-n twistlock | grep defender

\# View defender logs  
kubectl logs \-n twistlock \-l app=defender \--tail=50

\# Test console connectivity  
curl \-k https://\<tenant\>.prismacloud.io/api/v1/\_ping

\# Check scanner health  
kubectl logs \-n twistlock \-l app=scanner \--tail=20  
\`\`\`

10\. PERFORMANCE TUNING

Resource Recommendations:

\`\`\`yaml  
\# Production deployment resource limits  
defender:  
  resources:  
    requests:  
      memory: "512Mi"  
      cpu: "250m"  
    limits:  
      memory: "1024Mi"  
      cpu: "1000m"

scanner:  
  resources:  
    requests:  
      memory: "2Gi"  
      cpu: "1000m"  
    limits:  
      memory: "4Gi"  
      cpu: "2000m"  
\`\`\`

Optimization Tips:

1\. Network Optimization:  
   · Use defender proxy for egress traffic  
   · Configure compression for log forwarding  
2\. Storage Optimization:  
   · Set retention period: 30-90 days  
   · Enable log rotation  
3\. Scan Optimization:  
   · Schedule heavy scans during off-hours  
   · Use incremental scanning where available

11\. BACKUP & DISASTER RECOVERY

Backup Configuration:

\`\`\`bash  
\# Backup defender configurations  
curl \-k \-H "Authorization: Bearer $TOKEN" \\  
  https://\<tenant\>.prismacloud.io/api/v1/settings/backup \\  
  \-o prismacwpp-backup-$(date \+%Y%m%d).json  
\`\`\`

Restore Procedure:

\`\`\`  
1\. Deploy fresh Compute Console (if needed)  
2\. Restore configuration backup  
3\. Re-deploy defenders with same tokens  
4\. Verify connectivity and data sync  
\`\`\`

12\. DOCUMENTATION TEMPLATES

Defender Deployment Log:

\`\`\`  
Date: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
Cluster: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
Defender Version: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
Deployed By: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
Token Used: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
Nodes Covered: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
Issues Encountered: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
Resolution: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
\`\`\`

Policy Exception Request Form:

\`\`\`  
Application: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
CVE/Policy ID: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
Requested By: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
Justification: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
Risk Assessment: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
Expiration Date: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
Approver: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
\`\`\`

\---

APPENDIX: QUICK REFERENCE

API Endpoints for Automation:

\`\`\`bash  
\# Get vulnerabilities  
GET /api/v1/images?search=\<criteria\>

\# Deploy defender  
POST /api/v1/defenders/deploy

\# Trigger scan  
POST /api/v1/scans

\# Get runtime events  
GET /api/v1/audits/runtime/container  
\`\`\`

Useful kubectl Commands:

\`\`\`bash  
\# List all defenders  
kubectl get pods \-n twistlock \-l app=defender

\# Check defender logs  
kubectl logs \-n twistlock \-l app=defender \-f

\# Get defender version  
kubectl exec \-n twistlock \<defender-pod\> \-- defender version

\# Restart defender daemonset  
kubectl rollout restart daemonset \-n twistlock defender  
\`\`\`

Support Resources:

· Compute Documentation: https://docs.paloaltonetworks.com/prisma-cloud/compute-edition  
· API Reference: https://api.docs.prismacloud.io  
· Community: https://live.paloaltonetworks.com/prisma-cloud

\---

Change Record:

Date Version Changes Author  
Initial 1.0 Initial Release \[Your Name\]

Approvals:

· Security Operations: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
· Platform Engineering: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_  
· Compliance Team: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

Note: This SOP should be reviewed quarterly. Always test in non-production before applying to production environments.