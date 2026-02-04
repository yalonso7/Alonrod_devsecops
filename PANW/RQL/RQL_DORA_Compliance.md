# RQL Controls for DORA (Digital Operational Resilience Act) Alignment

Audience: Cortex Cloud / Prisma Cloud customers in financial services, fintech, blockchain, web3, and trading.  
Regulation: EU Regulation 2022/2554 (DORA). Applicable from January 2025.

---

# Table of Contents

- [Purpose & Scope](#purpose--scope)
- [DORA Pillars Mapped to Cloud](#dora-pillars-mapped-to-cloud)
- [Control Library & RQL Queries](#control-library--rql-queries)
  - [ICT Risk Management & Protection](#ict-risk-management--protection)
  - [Detection & Logging](#detection--logging)
  - [Third-Party ICT / Cloud Risk](#third-party-ict--cloud-risk)
  - [Incident Management & Recovery](#incident-management--recovery)
- [Potential Violations Summary](#potential-violations-summary)
- [How to Use This File](#how-to-use-this-file)

---

# Purpose & Scope

This document provides Prisma Cloud RQL queries to:

- Align cloud resource configurations with DORA’s ICT risk management, protection, detection, and third-party risk requirements.
- Detect potential violations such as missing encryption, weak access control, insufficient logging, and lack of resilience/backup controls.

In scope: AWS (primary), with patterns extendable to GCP and Azure.  
Out of scope: Non-cloud ICT; RQL focuses on config posture, not runtime or process documentation.

---

# DORA Pillars Mapped to Cloud

| DORA pillar | Cloud relevance | RQL focus |
|-------------|-----------------|-----------|
| ICT risk management | Risk-based controls on cloud assets | Encryption, access control, network exposure |
| Protection | Safeguard systems and data | Encryption at rest/transit, WAF, least privilege |
| Detection | Identify incidents promptly | Audit logs, object-level logging, monitoring |
| Containment / Recovery | Limit impact, restore services | Backup, DR, network segmentation |
| Third-party ICT risk | Cloud provider / SaaS assurance | Config hygiene, shared responsibility controls |

---

# Control Library & RQL Queries

# ICT Risk Management & Protection

# DORA-01: Storage (e.g. S3) Without Encryption at Rest

DORA alignment: Protection; ICT risk management.  
Potential violation: Sensitive or critical data stored unencrypted.

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-encryption'
  and json.rule = "ServerSideEncryptionConfiguration.Rules[*].ApplyServerSideEncryptionByDefault.SSEAlgorithm does not exist"
```

Optional scope (e.g. financial/trading workloads):

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-encryption'
  and (tags.regulation = 'DORA' or tags.workload = 'financial' or tags.data-classification = 'confidential')
  and json.rule = "ServerSideEncryptionConfiguration.Rules[*].ApplyServerSideEncryptionByDefault.SSEAlgorithm does not exist"
```

---

# DORA-02: Publicly Accessible Storage Buckets

DORA alignment: Protection; access control.  
Potential violation: Unauthorized access to financial/critical data.

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-acl'
  and json.rule = "
    grants[? (
      (grantee.URI contains 'AllUsers' or grantee.URI contains 'AuthenticatedUsers')
      and (permission equals 'READ' or permission equals 'FULL_CONTROL')
    )] size > 0
  "
```

---

# DORA-03: API Gateways Without Authorization (Financial/Trading APIs)

DORA alignment: Protection; access control.  
Potential violation: Exposed APIs without authentication.

```sql
config from cloud.resource
where api.name = 'aws-apigateway-get-rest-apis'
  and json.rule = "resources[*].resourceMethods[*].authorizationType equals 'NONE'"
```

---

# DORA-04: Public API Gateways Without WAF

DORA alignment: Protection; network security.  
Potential violation: Internet-facing APIs without WAF protection.

```sql
config from cloud.resource
where api.name = 'aws-apigateway-get-rest-apis'
  and json.rule = "endpointConfiguration.types contains 'EDGE' or endpointConfiguration.types contains 'REGIONAL'"
  and json.rule does not contain "webAclArn"
```

---

# DORA-05: Security Groups Open to Internet on Sensitive Ports

DORA alignment: Protection; network security.  
Potential violation: Excessive exposure of management or data ports.

```sql
config from cloud.resource
where api.name = 'aws-ec2-describe-security-groups'
  and json.rule = "
    ipPermissions[?(
      (fromPort <= 22 and toPort >= 22) or
      (fromPort <= 3389 and toPort >= 3389) or
      (fromPort <= 5432 and toPort >= 5432) or
      (fromPort <= 3306 and toPort >= 3306)
    )].ipRanges[*].cidrIp contains '0.0.0.0/0'
  "
```

---

# DORA-06: Publicly Accessible Managed Databases (RDS)

DORA alignment: Protection; access control.  
Potential violation: Financial/trading DBs reachable from the internet.

```sql
config from cloud.resource
where api.name = 'aws-rds-describe-db-instances'
  and json.rule = "PubliclyAccessible is true"
```

---

# DORA-07: Over-Permissive IAM Roles (Wildcard Actions/Resources)

DORA alignment: ICT risk management; least privilege.  
Potential violation: Roles with excessive permissions increase blast radius.

```sql
config from cloud.resource
where api.name = 'aws-iam-list-role-policies'
  and json.rule = "
    policyDocument.Statement[*].Action contains '*'
    or policyDocument.Statement[*].Resource contains '*'
  "
```

---

# Detection & Logging

# DORA-08: S3 Buckets Without Access Logging

DORA alignment: Detection; audit trail.  
Potential violation: No evidence for access to critical data.

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-logging'
  and json.rule = "LoggingEnabled does not exist"
```

---

# DORA-09: CloudTrail Not Enabled or Not Multi-Region

DORA alignment: Detection; incident identification.  
Potential violation: Incomplete audit trail for ICT operations.

```sql
config from cloud.resource
where api.name = 'aws-cloudtrail-describe-trails'
  and json.rule = "status.isLogging is false or isMultiRegionTrail is false"
```

---

# DORA-10: CloudTrail Without S3 Data Events (Object-Level Auditing)

DORA alignment: Detection; data access visibility.  
Potential violation: Cannot detect or investigate object-level access.

```sql
config from cloud.resource
where api.name = 'aws-cloudtrail-describe-trails'
  and json.rule = "eventSelectors[?contains(dataResources[*].type, 'AWS::S3::Object')] size is 0"
```

---

# DORA-11: RDS / DB Without Enhanced Monitoring or Audit Logging

DORA alignment: Detection.  
Potential violation: Limited visibility into DB access and changes.

*(Pattern; exact API names may vary by Prisma Cloud connector.)*

```sql
config from cloud.resource
where api.name = 'aws-rds-describe-db-instances'
  and json.rule = "MonitoringInterval equals 0 or PerformanceInsightsEnabled is false"
```

---

# Third-Party ICT / Cloud Risk

# DORA-12: Critical Resources Without Mandatory Tags (Cloud Governance)

DORA alignment: Third-party ICT risk; asset inventory and control.  
Potential violation: Cannot consistently apply risk and compliance policies.

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-acl'
  and json.rule = "tags.Environment does not exist or tags.Owner does not exist"
```

*(Adjust tag keys to your DORA governance standard.)*

---

# DORA-13: Lambda/Serverless Roles with Administrator Access

DORA alignment: ICT risk management; least privilege for cloud services.  
Potential violation: Third-party or internal code running with excessive rights.

```sql
config from cloud.resource
where api.name = 'aws-iam-list-attached-role-policies'
  and json.rule = "attachedPolicies[*].policyName contains 'AdministratorAccess'"
  and roleName starts with 'lambda-'
```

---

# Incident Management & Recovery

# DORA-14: S3 Buckets Without Versioning (Data Recovery)

DORA alignment: Recovery; repair.  
Potential violation: Cannot recover from accidental or malicious overwrite.

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-versioning'
  and json.rule = "Status does not equal 'Enabled'"
```

---

# DORA-15: RDS Without Automated Backups or Short Retention

DORA alignment: Recovery; business continuity.  
Potential violation: Insufficient backup for restoration.

```sql
config from cloud.resource
where api.name = 'aws-rds-describe-db-instances'
  and json.rule = "BackupRetentionPeriod < 7"
```

*(Tune threshold per policy, e.g. 7 or 30 days.)*

---

# DORA-16: EBS Volumes (Critical Workloads) Without Encryption

DORA alignment: Protection; ICT risk.  
Potential violation: Unencrypted persistent storage for financial workloads.

```sql
config from cloud.resource
where api.name = 'aws-ec2-describe-volumes'
  and json.rule = "Encrypted is false"
```

---

# Potential Violations Summary

| Control ID   | Short description                          | Typical severity |
|-------------|---------------------------------------------|------------------|
| DORA-01     | Storage without encryption                  | High             |
| DORA-02     | Public storage buckets                     | Critical         |
| DORA-03     | API without authorization                  | High             |
| DORA-04     | Public API without WAF                     | High             |
| DORA-05     | Security groups open to 0.0.0.0/0          | High             |
| DORA-06     | Public RDS                                 | Critical         |
| DORA-07     | Over-permissive IAM roles                  | High             |
| DORA-08     | S3 without access logging                  | Medium           |
| DORA-09     | CloudTrail off or not multi-region         | High             |
| DORA-10     | No S3 data events in CloudTrail            | Medium           |
| DORA-11     | RDS without enhanced monitoring/audit      | Medium           |
| DORA-12     | Missing governance tags                    | Low–Medium       |
| DORA-13     | Lambda with AdministratorAccess            | High             |
| DORA-14     | S3 without versioning                      | Medium           |
| DORA-15     | RDS short backup retention                 | High             |
| DORA-16     | EBS unencrypted                            | High             |

---

# How to Use This File

1. Copy each RQL block into Prisma Cloud as Saved Searches or Custom Policies.
2. Scope queries by account, region, or tags (e.g. `tags.regulation = 'DORA'`, `tags.workload = 'financial'`) where shown or required.
3. Tune `api.name` and `json.rule` to your Prisma Cloud schema and environment.
4. Map findings to your DORA control matrix and incident/reporting procedures.
5. Use the Potential Violations Summary for prioritization and reporting to compliance.
