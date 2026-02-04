# RQL Controls for FinTRAC (AML/ATF) Alignment

Audience: Cortex Cloud / Prisma Cloud customers subject to Canadian AML/ATF obligations (financial entities, MSBs, virtual currency dealers, securities, etc.).  
Regime: Proceeds of Crime (Money Laundering) and Terrorist Financing Act (PCMLTFA) and FinTRAC guidance.

---

# Table of Contents

- [Purpose & Scope](#purpose--scope)
- [FinTRAC Obligations Mapped to Cloud](#fintrac-obligations-mapped-to-cloud)
- [Control Library & RQL Queries](#control-library--rql-queries)
  - [Record-Keeping & Retention](#record-keeping--retention)
  - [Protection of Personal & Financial Information](#protection-of-personal--financial-information)
  - [Access Control & Audit Trail](#access-control--audit-trail)
  - [Reporting & System Security](#reporting--system-security)
- [Potential Violations Summary](#potential-violations-summary)
- [How to Use This File](#how-to-use-this-file)

---

# Purpose & Scope

This document provides Prisma Cloud RQL queries to:

- Align cloud configurations with FinTRAC expectations for record-keeping (including 5-year retention), protection of personal and financial information, and system security.
- Detect potential violations such as unencrypted AML/transaction data, missing access logs, public exposure of reporting or client data, and weak access control.

In scope: AWS (primary); patterns extendable to GCP and Azure.  
Out of scope: Process and procedural compliance (e.g. STR submission); RQL focuses on technical controls that support FinTRAC obligations.

---

# FinTRAC Obligations Mapped to Cloud

| FinTRAC area | Cloud relevance | RQL focus |
|--------------|-----------------|-----------|
| Record-keeping | Retention, integrity, availability of records | Backup, versioning, durable storage |
| Protection of information | Personal and financial data security | Encryption, no public access, classification |
| Access control | Who can access records and systems | IAM, least privilege, no anonymous access |
| Audit trail | Evidence of access and changes | Logging, CloudTrail, object-level audit |
| System security | Secure systems handling FINTRAC data | Encryption, WAF, network controls |

---

# Control Library & RQL Queries

# Record-Keeping & Retention

# FTRAC-01: Storage Buckets (AML/Reporting Data) Without Versioning

FinTRAC alignment: Record-keeping; integrity and recovery.  
Potential violation: Records could be overwritten without recovery option (5-year retention at risk).

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-versioning'
  and json.rule = "Status does not equal 'Enabled'"
```

Scoped to AML/reporting workload (optional):

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-versioning'
  and (tags.workload = 'aml' or tags.regulation = 'FinTRAC' or tags.data-classification = 'financial')
  and json.rule = "Status does not equal 'Enabled'"
```

---

# FTRAC-02: Short Backup Retention for Databases Holding AML/Transaction Records

FinTRAC alignment: Record-keeping (e.g. 5-year retention).  
Potential violation: Cannot retain records for required period.

```sql
config from cloud.resource
where api.name = 'aws-rds-describe-db-instances'
  and json.rule = "BackupRetentionPeriod < 7"
```

*(Tune threshold to policy; consider 30+ days minimum, with long-term retention for 5-year compliance.)*

---

# FTRAC-03: Object Storage (AML/STR Data) Without Lifecycle or Durable Storage Class

FinTRAC alignment: Record-keeping; durability and retention.  
Potential violation: Data may be lost or not retained appropriately.

*(Pattern: check for buckets that should use Glacier/IA for long-term retention; often enforced via tags and lifecycle policies.)*

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-lifecycle-configuration'
  and json.rule = "Rules does not exist or size(Rules) is 0"
```

*(Refine with tag filter for AML/reporting buckets.)*

---

# Protection of Personal & Financial Information

# FTRAC-04: Storage Buckets (AML/Client Data) Without Encryption at Rest

FinTRAC alignment: Protection of personal and financial information.  
Potential violation: Sensitive AML/client data stored unencrypted.

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-encryption'
  and json.rule = "ServerSideEncryptionConfiguration.Rules[*].ApplyServerSideEncryptionByDefault.SSEAlgorithm does not exist"
```

---

# FTRAC-05: Publicly Accessible Buckets (Potential AML/Client Data)

FinTRAC alignment: Protection of information; access control.  
Potential violation: Unauthorized access to reporting or client data.

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

# FTRAC-06: EBS Volumes (AML/Transaction Processing) Unencrypted

FinTRAC alignment: Protection of information.  
Potential violation: Unencrypted persistent storage for financial/AML data.

```sql
config from cloud.resource
where api.name = 'aws-ec2-describe-volumes'
  and json.rule = "Encrypted is false"
```

---

# FTRAC-07: RDS Instances (AML/Client Data) Publicly Accessible

FinTRAC alignment: Protection; access control.  
Potential violation: Databases holding STR/AML data reachable from internet.

```sql
config from cloud.resource
where api.name = 'aws-rds-describe-db-instances'
  and json.rule = "PubliclyAccessible is true"
```

---

# Access Control & Audit Trail

# FTRAC-08: S3 Buckets (AML/Reporting) Without Access Logging

FinTRAC alignment: Record-keeping; audit trail of access.  
Potential violation: No evidence of who accessed records.

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-logging'
  and json.rule = "LoggingEnabled does not exist"
```

---

# FTRAC-09: CloudTrail Not Enabled or Not Multi-Region

FinTRAC alignment: Audit trail; system security.  
Potential violation: Incomplete evidence for regulatory or incident review.

```sql
config from cloud.resource
where api.name = 'aws-cloudtrail-describe-trails'
  and json.rule = "status.isLogging is false or isMultiRegionTrail is false"
```

---

# FTRAC-10: CloudTrail Without S3 Data Events (Object-Level Audit for Record Buckets)

FinTRAC alignment: Audit trail for record access.  
Potential violation: Cannot demonstrate or investigate access to stored records.

```sql
config from cloud.resource
where api.name = 'aws-cloudtrail-describe-trails'
  and json.rule = "eventSelectors[?contains(dataResources[*].type, 'AWS::S3::Object')] size is 0"
```

---

# FTRAC-11: Over-Permissive IAM Roles (Access to AML/Reporting Systems)

FinTRAC alignment: Access control; least privilege.  
Potential violation: Excessive access to STR/AML data or reporting systems.

```sql
config from cloud.resource
where api.name = 'aws-iam-list-role-policies'
  and json.rule = "
    policyDocument.Statement[*].Action contains '*'
    or policyDocument.Statement[*].Resource contains '*'
  "
```

---

# FTRAC-12: API Gateways (Reporting/Client Portals) Without Authorization

FinTRAC alignment: Access control; protection of information.  
Potential violation: APIs that may expose or submit STR/AML data without auth.

```sql
config from cloud.resource
where api.name = 'aws-apigateway-get-rest-apis'
  and json.rule = "resources[*].resourceMethods[*].authorizationType equals 'NONE'"
```

---

# Reporting & System Security

# FTRAC-13: Public API Gateways Without WAF (Reporting/Financial Workloads)

FinTRAC alignment: System security; protection of systems handling FINTRAC data.  
Potential violation: Internet-facing reporting/financial APIs without WAF.

```sql
config from cloud.resource
where api.name = 'aws-apigateway-get-rest-apis'
  and json.rule = "endpointConfiguration.types contains 'EDGE' or endpointConfiguration.types contains 'REGIONAL'"
  and json.rule does not contain "webAclArn"
```

---

# FTRAC-14: Security Groups Open to Internet on Sensitive Ports (AML/Financial VPCs)

FinTRAC alignment: System security; network access control.  
Potential violation: Management or data systems exposed to internet.

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

# FTRAC-15: RDS Without Encryption at Rest (AML/Client Data)

FinTRAC alignment: Protection of personal and financial information.  
Potential violation: Database holding STR/AML/client data unencrypted.

```sql
config from cloud.resource
where api.name = 'aws-rds-describe-db-instances'
  and json.rule = "StorageEncrypted is false"
```

---

# Potential Violations Summary

| Control ID   | Short description                              | Typical severity |
|-------------|-------------------------------------------------|------------------|
| FTRAC-01    | AML/reporting buckets without versioning        | Medium           |
| FTRAC-02    | Short DB backup retention                       | High             |
| FTRAC-03    | No lifecycle/durable storage for records        | Medium           |
| FTRAC-04    | AML/client storage without encryption          | High             |
| FTRAC-05    | Public buckets (AML/client data)                | Critical         |
| FTRAC-06    | EBS unencrypted (AML workloads)                 | High             |
| FTRAC-07    | Public RDS (AML/client data)                   | Critical         |
| FTRAC-08    | AML/reporting buckets without logging          | Medium           |
| FTRAC-09    | CloudTrail off or not multi-region             | High             |
| FTRAC-10    | No S3 data events (object-level audit)         | Medium           |
| FTRAC-11    | Over-permissive IAM (AML/reporting access)      | High             |
| FTRAC-12    | Reporting/portal API without auth               | High             |
| FTRAC-13    | Public API without WAF                          | High             |
| FTRAC-14    | SG open to 0.0.0.0/0 on sensitive ports        | High             |
| FTRAC-15    | RDS unencrypted                                | High             |

---

# How to Use This File

1. Tag AML, reporting, and client-data workloads (e.g. `workload=aml`, `regulation=FinTRAC`) so scoped queries apply.
2. Copy each RQL into Prisma Cloud as Saved Searches or Custom Policies; name e.g. `FTRAC-04-AML-Storage-No-Encryption`.
3. Tune retention thresholds (e.g. backup retention, lifecycle) to match your 5-year and internal policies.
4. Map findings to your FinTRAC/PCMLTFA control matrix and privacy/security assessments.
5. Use the Potential Violations Summary for prioritization and compliance reporting.
