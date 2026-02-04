# RQL Controls for MICA (Markets in Crypto-Assets) Alignment

Audience: Cortex Cloud / Prisma Cloud customers in blockchain, web3, crypto-asset services, and trading.  
Regulation: EU Regulation 2023/1114 (MiCA). Phased application from 2024–2025.

---

# Table of Contents

- [Purpose & Scope](#purpose--scope)
- [MICA Technical Areas Mapped to Cloud](#mica-technical-areas-mapped-to-cloud)
- [Control Library & RQL Queries](#control-library--rql-queries)
  - [Custody & Key Management](#custody--key-management)
  - [Network & Systems Security](#network--systems-security)
  - [Access Control & Identity](#access-control--identity)
  - [Record-Keeping & Integrity](#record-keeping--integrity)
- [Potential Violations Summary](#potential-violations-summary)
- [How to Use This File](#how-to-use-this-file)

---

# Purpose & Scope

This document provides Prisma Cloud RQL queries to:

- Align cloud configurations with MiCA’s requirements for custody, systems security, cryptographic key management, and access protocols.
- Detect potential violations such as exposed custody data, weak key storage, missing encryption, and insufficient access control or logging.

In scope: AWS (primary); patterns extendable to GCP and Azure.  
Relevant MiCA concepts: Crypto-asset custody, CASPs, key management, network and information systems security (aligns with NIS2/DORA).

---

# MICA Technical Areas Mapped to Cloud

| MiCA area | Cloud relevance | RQL focus |
|-----------|-----------------|-----------|
| Custody & administration | Secure storage of keys and client assets data | Encryption, access control, no public exposure |
| Key management | KMS, secrets managers, HSM-backed keys | Encryption at rest, key policy, rotation |
| Network & systems security | Segmentation, WAF, secure APIs | Security groups, WAF, TLS |
| Access protocols | Least privilege, MFA, audit trails | IAM, logging, MFA (where configurable) |
| Record-keeping & integrity | Immutability, audit trail | Versioning, logging, backup |

---

# Control Library & RQL Queries

# Custody & Key Management

# MICA-01: Storage Buckets (Custody/Client Data) Without Encryption

MICA alignment: Custody; protection of client crypto-asset data.  
Potential violation: Custody-related data stored unencrypted.

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-encryption'
  and json.rule = "ServerSideEncryptionConfiguration.Rules[*].ApplyServerSideEncryptionByDefault.SSEAlgorithm does not exist"
```

Scoped to custody/workload tags (optional):

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-encryption'
  and (tags.workload = 'custody' or tags.regulation = 'MICA' or tags.data-classification = 'crypto-assets')
  and json.rule = "ServerSideEncryptionConfiguration.Rules[*].ApplyServerSideEncryptionByDefault.SSEAlgorithm does not exist"
```

---

# MICA-02: S3 Buckets Containing Custody/Key Data with Public Access

MICA alignment: Custody; access control.  
Potential violation: Unauthorized access to custody or key material.

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-acl'
  and json.rule = "
    (tags.workload = 'custody' or tags.regulation = 'MICA')
    and grants[? (
      (grantee.URI contains 'AllUsers' or grantee.URI contains 'AuthenticatedUsers')
      and (permission equals 'READ' or permission equals 'FULL_CONTROL')
    )] size > 0
  "
```

*(If tags are not available, use the same public-grants rule without tag filter.)*

---

# MICA-03: KMS Keys Not Customer-Managed (CMK) or Without Key Policy Restriction

MICA alignment: Cryptographic key management; control over keys.  
Potential violation: Keys not under entity control or overly permissive use.

```sql
config from cloud.resource
where api.name = 'aws-kms-describe-key'
  and json.rule = "KeyMetadata.KeyManager equals 'AWS'"
```

*(Detects AWS-managed keys; policy may require customer-managed CMKs for custody.)*

---

# MICA-04: Secrets Manager / Parameter Store (Key Material) with Public or Overly Permissive Access

MICA alignment: Key management; access protocols.  
Potential violation: Private keys or secrets accessible beyond intended scope.

*(Pattern: ensure no public access and least-privilege IAM; often combined with IAM policy checks.)*

```sql
config from cloud.resource
where api.name = 'aws-secretsmanager-list-secrets'
  and json.rule = "tags.workload equals 'custody'"
```

*(Add IAM policy checks for secrets: no wildcard GetSecretValue for anonymous or broad principals.)*

---

# Network & Systems Security

# MICA-05: Crypto/Trading APIs Without Authorization

MICA alignment: Network and systems security; access control.  
Potential violation: Exposed trading or custody APIs without auth.

```sql
config from cloud.resource
where api.name = 'aws-apigateway-get-rest-apis'
  and json.rule = "
    (tags.workload = 'trading' or tags.workload = 'custody' or tags.regulation = 'MICA')
    and resources[*].resourceMethods[*].authorizationType equals 'NONE'
  "
```

---

# MICA-06: Public Crypto/Trading APIs Without WAF

MICA alignment: Network security; input validation and abuse prevention.  
Potential violation: Internet-facing APIs without WAF.

```sql
config from cloud.resource
where api.name = 'aws-apigateway-get-rest-apis'
  and json.rule = "
    (tags.workload = 'trading' or tags.workload = 'custody')
    and (endpointConfiguration.types contains 'EDGE' or endpointConfiguration.types contains 'REGIONAL')
  "
  and json.rule does not contain "webAclArn"
```

---

# MICA-07: Security Groups Open to Internet on Admin or DB Ports (Custody/Trading VPCs)

MICA alignment: Network security; access protocols.  
Potential violation: Management or data plane exposed to internet.

```sql
config from cloud.resource
where api.name = 'aws-ec2-describe-security-groups'
  and json.rule = "
    (tags.workload = 'custody' or tags.workload = 'trading')
    and ipPermissions[?(
      (fromPort <= 22 and toPort >= 22) or
      (fromPort <= 3389 and toPort >= 3389) or
      (fromPort <= 5432 and toPort >= 5432)
    )].ipRanges[*].cidrIp contains '0.0.0.0/0'
  "
```

---

# MICA-08: Load Balancers (Inference/Trading) Allowing HTTP Without Redirect to HTTPS

MICA alignment: Systems security; encryption in transit.  
Potential violation: Cleartext exposure of trading/custody traffic.

```sql
config from cloud.resource
where api.name = 'aws-elbv2-describe-load-balancers'
  and json.rule = "
    (tags.workload = 'trading' or tags.workload = 'custody')
    and listeners[*].protocol contains 'HTTP'
    and listeners[*].defaultActions[*].type does not contain 'redirect'
  "
```

---

# Access Control & Identity

# MICA-09: Over-Permissive Roles for Custody or Trading Workloads

MICA alignment: Access protocols; least privilege.  
Potential violation: Custody/trading roles with wildcard permissions.

```sql
config from cloud.resource
where api.name = 'aws-iam-list-role-policies'
  and json.rule = "
    (tags.workload = 'custody' or tags.workload = 'trading')
    and (policyDocument.Statement[*].Action contains '*' or policyDocument.Statement[*].Resource contains '*')
  "
```

---

# MICA-10: Lambda/Serverless Used for Custody Logic with Admin or Wildcard Policies

MICA alignment: Systems security; access protocols.  
Potential violation: Custody-related functions with excessive privileges.

```sql
config from cloud.resource
where api.name = 'aws-iam-list-attached-role-policies'
  and json.rule = "attachedPolicies[*].policyName contains 'AdministratorAccess'"
  and (roleName contains 'custody' or roleName contains 'trading' or roleName contains 'lambda')
```

---

# MICA-11: Publicly Accessible Databases (Trading/Custody Data)

MICA alignment: Custody; access control.  
Potential violation: DB holding client or trading data reachable from internet.

```sql
config from cloud.resource
where api.name = 'aws-rds-describe-db-instances'
  and json.rule = "PubliclyAccessible is true"
```

*(Scope by tags if RDS is tagged, e.g. custody/trading.)*

---

# Record-Keeping & Integrity

# MICA-12: Custody/Trading S3 Buckets Without Access Logging

MICA alignment: Record-keeping; audit trail.  
Potential violation: No evidence of access to custody/trading data.

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-logging'
  and json.rule = "LoggingEnabled does not exist"
```

*(Optional: add tag filter for custody/trading buckets.)*

---

# MICA-13: Custody/Trading Buckets Without Versioning (Integrity/Recovery)

MICA alignment: Custody; integrity and recovery.  
Potential violation: Cannot prove or restore prior state.

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-versioning'
  and json.rule = "Status does not equal 'Enabled'"
```

---

# MICA-14: CloudTrail Not Enabled or Not Multi-Region (Crypto/Trading Accounts)

MICA alignment: Record-keeping; systems security.  
Potential violation: Incomplete audit trail for regulatory and incident response.

```sql
config from cloud.resource
where api.name = 'aws-cloudtrail-describe-trails'
  and json.rule = "status.isLogging is false or isMultiRegionTrail is false"
```

---

# MICA-15: Container/Artifact Registries for Trading/Custody with Mutable Tags

MICA alignment: Integrity; supply chain.  
Potential violation: Image/artifact overwrite without traceability.

```sql
config from cloud.resource
where api.name = 'aws-ecr-describe-repositories'
  and json.rule = "
    (tags.workload = 'custody' or tags.workload = 'trading')
    and imageTagMutability equals 'MUTABLE'
  "
```

---

# Potential Violations Summary

| Control ID   | Short description                              | Typical severity |
|-------------|-------------------------------------------------|------------------|
| MICA-01     | Custody/data storage without encryption         | High             |
| MICA-02     | Public access on custody buckets                | Critical         |
| MICA-03     | AWS-managed KMS keys (where CMK required)       | Medium           |
| MICA-04     | Secrets/key material access controls            | High             |
| MICA-05     | Crypto/trading API without auth                 | High             |
| MICA-06     | Public crypto API without WAF                  | High             |
| MICA-07     | Custody/trading SG open to internet             | High             |
| MICA-08     | HTTP allowed without HTTPS redirect             | High             |
| MICA-09     | Over-permissive custody/trading roles           | High             |
| MICA-10     | Custody Lambda with admin policy                | High             |
| MICA-11     | Public RDS (trading/custody data)                | Critical         |
| MICA-12     | Custody/trading buckets without logging         | Medium           |
| MICA-13     | Custody/trading buckets without versioning      | Medium           |
| MICA-14     | CloudTrail off or not multi-region              | High             |
| MICA-15     | ECR mutable tags for custody/trading            | Medium           |

---

# How to Use This File

1. Tag custody, trading, and crypto workloads consistently (e.g. `workload=custody`, `regulation=MICA`) so scoped queries apply.
2. Copy each RQL into Prisma Cloud as Saved Searches or Custom Policies; name e.g. `MICA-01-Custody-Storage-No-Encryption`.
3. Adjust `api.name` and `json.rule` to your Prisma Cloud schema; add/remove tag filters as needed.
4. Map findings to your MiCA control matrix and to NIS2/DORA where overlapping.
5. Use the Potential Violations Summary for prioritization and regulatory reporting.
