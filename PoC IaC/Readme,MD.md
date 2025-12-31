Python script that implements Policy as Code for Terraform IaC, scanning AWS and GCP configurations against OWASP Top 10 and CSA CCM security controls.

 Key Features:

# 1. Security Rule Coverage:
- AWS Resources: S3, EC2, RDS, IAM, Security Groups, CloudWatch
- GCP Resources: GCS, GCE, Cloud SQL, Firewall Rules, Logging
- Cross-provider: Hardcoded secrets, missing tags/labels

# 2. Compliance Mappings:
- OWASP Top 10 (2021): All findings mapped to relevant categories (A01-A09)
- CSA CCM Controls: Mapped to specific controls (IAM, EKM, DSI, IVS, LOG, etc.)

# 3. Severity Levels:
- Critical, High, Medium, Low, Info

# 4. JSON Report Includes:
- Executive summary with risk score
- Findings grouped by severity
- Compliance mapping coverage
- Prioritized recommendations
- Remediation roadmap (immediate/30/90-day plans)

 Usage:

```bash
# Scan current directory
python terraform_scanner.py

# Scan specific directory
python terraform_scanner.py /path/to/terraform

# Specify custom output file
python terraform_scanner.py /path/to/terraform custom_report.json
```

 Example Report Structure:
The JSON report contains:
- Scan metadata and statistics
- Risk score (0-100)
- Findings organized by severity
- OWASP & CSA CCM coverage analysis
- Top 10 prioritized recommendations
- Remediation timeline

The script checks for common security misconfigurations like public access, missing encryption, overly permissive IAM policies, hardcoded secrets, and missing logging—all critical for regulatory compliance (SOC2, PCI-DSS, HIPAA, etc.).


Terraform testing (AWS and GCP)

///////////////Important: These are intentionally vulnerable configurations for testing security scanners only. Never use these in production environments!
 GCP Comprehensive Configuration (gcp-comprehensive.tf)///////////////////////////////////////////////////////////////////////////////////////////////////////

 AWS Terraform Configuration (main.tf)
Contains resources with security issues including:
- VPC with public subnets
- Security groups exposing SSH/RDP to 0.0.0.0/0
- S3 buckets without encryption and with public access
- RDS with hardcoded passwords and public access
- Lambda functions with hardcoded secrets
- Unencrypted EBS volumes
- EC2 instances with IMDSv1 enabled
- Elasticsearch without encryption
- KMS keys without rotation

 GCP Terraform Configuration (main.tf)
Contains resources with security issues including:
- Firewall rules allowing SSH/RDP from anywhere
- Compute instances with public IPs and overly broad scopes
- Storage buckets with public access
- Cloud SQL without backups, SSL, or IP restrictions
- Cloud Functions with public access and hardcoded secrets
- Service accounts with Owner role
- BigQuery datasets accessible to all authenticated users
- GKE clusters with legacy ABAC and other security issues
- Resources without customer-managed encryption

 Usage

For AWS:
```bash
terraform init
terraform plan
terraform apply  # Use with caution!
```

For GCP (note: you'll need to create a dummy `function.zip` file):
```bash
touch function.zip
terraform init
terraform plan -var="project_id=your-project-id"
terraform apply -var="project_id=your-project-id"
```

Note: These Terraform files will and should trigger findings in security scanning tools within CNAPP or CASB like:
- Checkov
- tfsec
- Terrascan
- Snyk IaC
- Bridgecrew
- Prisma Cloud (Cortex Cloud)

# Services Covered:

1. Networking - VPC, subnets, firewall rules with open ports
2. Compute - VM instances with public IPs, hardcoded secrets, no shielded VMs
3. Storage - GCS buckets with public access, no encryption, no versioning
4. Cloud SQL - MySQL & PostgreSQL without backups, SSL, or proper access controls
5. IAM - Service accounts with Owner/Editor roles, public access bindings
6. Cloud Functions - Unauthenticated functions with hardcoded secrets
7. Pub/Sub - Topics without encryption, public publishers
8. BigQuery - Datasets accessible to all authenticated users, no encryption
9. KMS - Keys with long rotation periods, overly permissive access
10. Disks & Snapshots - Unencrypted disks and snapshots
11. GKE - Cluster with legacy ABAC, no private nodes, insecure node pools
12. Cloud DNS - Zones without DNSSEC
13. Secret Manager - Secrets without encryption, hardcoded values
14. Load Balancer - Backend services without logging or security policies
15. Cloud Run - Services with public access and hardcoded secrets
16. Cloud Composer - Airflow with hardcoded credentials
17. Memorystore (Redis) - No authentication or encryption
18. Bigtable - No encryption, overly permissive IAM
19. Spanner - No encryption, public database access
20. Dataproc - Hadoop cluster with insecure configuration

# Usage:

```bash
# Initialize
terraform init

# Validate
terraform validate

# Plan (dry-run)
terraform plan -var="project_id=your-gcp-project-id"

# Scan with security tools
checkov -f gcp-comprehensive.tf
tfsec .
terrascan scan -t terraform
```


