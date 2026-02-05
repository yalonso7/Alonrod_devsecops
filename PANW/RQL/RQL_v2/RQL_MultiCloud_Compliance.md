# Multi-Cloud RQL Compliance Reference — DORA, MICA, FinTRAC

Audience: Cortex Cloud / Prisma Cloud customers (blockchain, web3, trading, financial services) running workloads across AWS, GCP, Azure, Oracle Cloud (OCI), Alibaba Cloud, and IBM Cloud.

Purpose: Provide equivalent RQL queries per control intent so you can achieve consistent DORA, MICA, and FinTRAC alignment regardless of provider. Use with [RQL_DORA_Compliance.md](./RQL_DORA_Compliance.md), [RQL_MICA_Compliance.md](./RQL_MICA_Compliance.md), and [RQL_FinTRAC_Compliance.md](./RQL_FinTRAC_Compliance.md).

---

# Table of Contents

- [Provider Support & api.name Reference](#provider-support--apiname-reference)
- [Control 1: Object/Blob Storage Without Encryption at Rest](#control-1-objectblob-storage-without-encryption-at-rest)
- [Control 2: Publicly Accessible Storage (Buckets / Containers)](#control-2-publicly-accessible-storage-buckets--containers)
- [Control 3: APIs / API Management Without Authorization](#control-3-apis--api-management-without-authorization)
- [Control 4: Public APIs Without WAF or Equivalent](#control-4-public-apis-without-waf-or-equivalent)
- [Control 5: Security Groups / Firewall Rules Open to Internet (Sensitive Ports)](#control-5-security-groups--firewall-rules-open-to-internet-sensitive-ports)
- [Control 6: Managed Databases Publicly Accessible](#control-6-managed-databases-publicly-accessible)
- [Control 7: Over-Permissive IAM / Identity (Wildcard or Admin)](#control-7-over-permissive-iam--identity-wildcard-or-admin)
- [Control 8: Storage Without Access Logging](#control-8-storage-without-access-logging)
- [Control 9: Audit / Activity Logging Disabled or Incomplete](#control-9-audit--activity-logging-disabled-or-incomplete)
- [Control 10: Storage Without Versioning or Backup](#control-10-storage-without-versioning-or-backup)
- [Control 11: Disks / Volumes Unencrypted](#control-11-disks--volumes-unencrypted)
- [Control 12: Key/Secrets Management (Customer-Managed or Restrictive)](#control-12-keysecrets-management-customer-managed-or-restrictive)
- [Verification Notes for OCI, Alibaba, IBM](#verification-notes-for-oci-alibaba-ibm)

---

# Provider Support & api.name Reference

| Provider | Prisma Cloud support | cloud.type | Typical api.name pattern | Notes |
|----------|----------------------|------------|---------------------------|-------|
| AWS | Full | `aws` | `aws-s3api-*`, `aws-rds-*`, `aws-ec2-*`, `aws-iam-*`, `aws-cloudtrail-*`, etc. | See DORA/MICA/FinTRAC docs for full AWS queries. |
| GCP | Full | `gcp` | `gcloud-storage-buckets-list`, `gcloud-iam-*`, `gcloud-sql-*`, `gcloud-compute-*` | Use `cloud.type = 'gcp'` when scoping. |
| Azure | Full | `azure` | `azure-storage-account-list`, `azure-disk-list`, `azure-vm-list`, `azure-sql-*`, `azure-network-*` | Properties often under `properties.*`. |
| Oracle (OCI) | Supported | `oci` or `oracle` | Verify in UI: e.g. `oci-objectstorage-*`, `oci-database-*`, `oci-compute-*` | Account onboarding via Terraform; confirm api.name in Search. |
| Alibaba Cloud | Supported | `alibaba` or `aliyun` | Verify in UI: e.g. `alibaba-oss-*`, `alibaba-rds-*`, `alibaba-ecs-*` | Variants: ali-int, ali-cn, ali-fn. |
| IBM Cloud | Verify in your tenant | `ibm` or `ibmcloud` | Verify in UI: e.g. `ibm-cloud-object-storage-*`, `ibm-database-*`, `ibm-vpc-*` | If not listed in Prisma docs, use this as template and confirm api.name. |

SME note: Always confirm `api.name` and JSON paths in Prisma Cloud → Search → Build Query or the Resource Explorer for your Prisma version and onboarded accounts. Naming can differ by connector version.

---

# Control 1: Object/Blob Storage Without Encryption at Rest

Regulation: DORA, MICA, FinTRAC (protection of data).

| Provider | api.name (verify in UI) | RQL / json.rule intent |
|----------|-------------------------|-------------------------|
| AWS | `aws-s3api-get-bucket-encryption` | `ServerSideEncryptionConfiguration.Rules[*].ApplyServerSideEncryptionByDefault.SSEAlgorithm does not exist` |
| GCP | `gcloud-storage-buckets-list` | Bucket encryption default: check for missing `encryption.defaultKmsKeyName` or equivalent in schema |
| Azure | `azure-storage-account-list` | `properties.encryption.services.blob.enabled is false` or encryption block missing |
| OCI | e.g. `oci-objectstorage-bucket-list` | Encryption key / vault not set (verify field names in Prisma) |
| Alibaba | e.g. `alibaba-oss-bucket-list` or OSS equivalent | Server-side encryption not enabled (verify field names) |
| IBM | e.g. `ibm-cloud-object-storage-bucket-list` | Encryption not enabled (verify field names) |

# AWS (reference)

```sql
config from cloud.resource
where cloud.type = 'aws' and api.name = 'aws-s3api-get-bucket-encryption'
  and json.rule = "ServerSideEncryptionConfiguration.Rules[*].ApplyServerSideEncryptionByDefault.SSEAlgorithm does not exist"
```

# GCP

```sql
config from cloud.resource
where cloud.type = 'gcp' and api.name = 'gcloud-storage-buckets-list'
  and json.rule = "encryption.defaultKmsKeyName does not exist"
```

*If your Prisma schema uses different fields (e.g. `encryption` absent when default encryption is off), adjust the rule.*

# Azure

```sql
config from cloud.resource
where cloud.type = 'azure' and api.name = 'azure-storage-account-list'
  and json.rule = "properties.encryption.services.blob.enabled is false or properties.encryption does not exist"
```

# Oracle OCI (template — verify api.name and path)

```sql
config from cloud.resource
where cloud.type = 'oci' and api.name = 'oci-objectstorage-bucket-list'
  and json.rule = "<kmsKeyId or encryption field> does not exist"
```

# Alibaba Cloud (template — verify api.name and path)

```sql
config from cloud.resource
where cloud.type = 'alibaba' and api.name = 'alibaba-oss-bucket-list'
  and json.rule = "<ServerSideEncryption or equivalent> does not exist"
```

# IBM Cloud (template — verify api.name and path)

```sql
config from cloud.resource
where cloud.type = 'ibm' and api.name = 'ibm-cloud-object-storage-bucket-list'
  and json.rule = "<encryption or keyProtect> does not exist"
```

---

# Control 2: Publicly Accessible Storage (Buckets / Containers)

Regulation: DORA, MICA, FinTRAC (access control; no public read).

| Provider | api.name | RQL intent |
|----------|----------|-------------|
| AWS | `aws-s3api-get-bucket-acl` | `grants` with AllUsers/AuthenticatedUsers READ or FULL_CONTROL |
| GCP | `gcloud-storage-buckets-list` | `iam.bindings[*].members` contains `allUsers` or ACL entity `allUsers` |
| Azure | `azure-storage-account-list` or blob service | Public access not disabled; blob container public access level |
| OCI | Object Storage bucket | Public access flag / bucket visibility |
| Alibaba | OSS bucket | Bucket ACL public read |
| IBM | COS bucket | Public access enabled |

# AWS (reference)

```sql
config from cloud.resource
where cloud.type = 'aws' and api.name = 'aws-s3api-get-bucket-acl'
  and json.rule = "grants[? (grantee.URI contains 'AllUsers' or grantee.URI contains 'AuthenticatedUsers') and (permission equals 'READ' or permission equals 'FULL_CONTROL')] size > 0"
```

# GCP

```sql
config from cloud.resource
where cloud.type = 'gcp' and api.name = 'gcloud-storage-buckets-list'
  and json.rule = "iam.bindings[*].members[*] contains 'allUsers' or acl[*].entity contains 'allUsers'"
```

# Azure (storage account allow blob public access)

```sql
config from cloud.resource
where cloud.type = 'azure' and api.name = 'azure-storage-account-list'
  and json.rule = "properties.allowBlobPublicAccess is true"
```

# Oracle OCI (template)

```sql
config from cloud.resource
where cloud.type = 'oci' and api.name = 'oci-objectstorage-bucket-list'
  and json.rule = "publicAccessType is not 'NoPublicAccess' or accessType contains 'Public'"
```

# Alibaba Cloud (template)

```sql
config from cloud.resource
where cloud.type = 'alibaba' and api.name = 'alibaba-oss-bucket-list'
  and json.rule = "acl equals 'public-read' or acl equals 'public-read-write'"
```

# IBM Cloud (template)

```sql
config from cloud.resource
where cloud.type = 'ibm' and api.name = 'ibm-cloud-object-storage-bucket-list'
  and json.rule = "firewall.allowed_ip or public_access is true"
```

---

# Control 3: APIs / API Management Without Authorization

Regulation: DORA, MICA, FinTRAC (access control).

| Provider | api.name | RQL intent |
|----------|----------|------------|
| AWS | `aws-apigateway-get-rest-apis` | `authorizationType equals 'NONE'` on methods |
| GCP | `gcloud-apis-apigateway-list` or API Gateway config | No API key / OAuth / auth config required |
| Azure | `azure-api-management-list` or `azure-api-management-api-list` | APIs without subscription or auth |
| OCI | API Gateway / API Gateway deployment | No auth enabled |
| Alibaba | API Gateway API | No app key / auth |
| IBM | API Connect / API Gateway | No security / auth |

# AWS (reference)

```sql
config from cloud.resource
where cloud.type = 'aws' and api.name = 'aws-apigateway-get-rest-apis'
  and json.rule = "resources[*].resourceMethods[*].authorizationType equals 'NONE'"
```

# GCP (API Gateway — verify api.name)

```sql
config from cloud.resource
where cloud.type = 'gcp' and api.name = 'gcloud-apis-apigateway-list'
  and json.rule = "labels or config does not contain required auth"
```

*Refine using actual schema: look for absence of API key requirement or OAuth.*

# Azure (API Management — verify api.name)

```sql
config from cloud.resource
where cloud.type = 'azure' and api.name = 'azure-api-management-api-list'
  and json.rule = "subscriptionRequired is false or authenticationSettings does not exist"
```

# OCI / Alibaba / IBM

Use provider-specific API Gateway resource types and equivalent “auth required” or “open” flags; confirm api.name in Prisma.

---

# Control 4: Public APIs Without WAF or Equivalent

Regulation: DORA, MICA (network/system security).

| Provider | api.name | RQL intent |
|----------|----------|------------|
| AWS | `aws-apigateway-get-rest-apis` | No `webAclArn`; endpoint public |
| GCP | API Gateway / Load Balancer | No Cloud Armor policy attached |
| Azure | `azure-api-management-list` | No WAF / Front Door WAF policy |
| OCI | WAF policy / API Gateway | WAF not attached |
| Alibaba | WAF / API Gateway | WAF not enabled |
| IBM | WAF / API Gateway | WAF not attached |

# AWS (reference)

```sql
config from cloud.resource
where cloud.type = 'aws' and api.name = 'aws-apigateway-get-rest-apis'
  and (json.rule = "endpointConfiguration.types contains 'EDGE' or endpointConfiguration.types contains 'REGIONAL'")
  and json.rule does not contain "webAclArn"
```

# Azure (Front Door / WAF — verify api.name)

```sql
config from cloud.resource
where cloud.type = 'azure' and api.name = 'azure-frontdoor-list'
  and json.rule = "webApplicationFirewallPolicy does not exist"
```

*GCP: Check Cloud Armor backend policy on load balancers. OCI/Alibaba/IBM: map to WAF resource and “attached” condition.*

---

# Control 5: Security Groups / Firewall Rules Open to Internet (Sensitive Ports)

Regulation: DORA, MICA, FinTRAC (network security).

| Provider | api.name | RQL intent |
|----------|----------|------------|
| AWS | `aws-ec2-describe-security-groups` | `ipPermissions` with 0.0.0.0/0 on 22, 3389, 5432, 3306, etc. |
| GCP | `gcloud-compute-firewall-list` | `sourceRanges` contains 0.0.0.0/0; allowed ports include 22, 3389, 5432, 3306 |
| Azure | `azure-network-security-group-list` or NSG rules | source 0.0.0.0/0 or *; port 22, 3389, 5432, 3306 |
| OCI | `oci-core-security-list-list` or `oci-vpc-security-list` | CIDR 0.0.0.0/0; ingress on sensitive ports |
| Alibaba | `alibaba-ecs-security-group` or VPC security group | 0.0.0.0/0 ingress on 22, 3389, 3306 |
| IBM | `ibm-vpc-security-group` or classic firewall | 0.0.0.0/0 on sensitive ports |

# AWS (reference)

```sql
config from cloud.resource
where cloud.type = 'aws' and api.name = 'aws-ec2-describe-security-groups'
  and json.rule = "ipPermissions[? ((fromPort <= 22 and toPort >= 22) or (fromPort <= 3389 and toPort >= 3389) or (fromPort <= 5432 and toPort >= 5432))].ipRanges[*].cidrIp contains '0.0.0.0/0'"
```

# GCP

```sql
config from cloud.resource
where cloud.type = 'gcp' and api.name = 'gcloud-compute-firewall-list'
  and json.rule = "sourceRanges[*] contains '0.0.0.0/0' and (allowed[*].ports[*] contains '22' or allowed[*].ports[*] contains '3389' or allowed[*].ports[*] contains '5432' or allowed[*].ports[*] contains '3306')"
```

# Azure (NSG — verify api.name)

```sql
config from cloud.resource
where cloud.type = 'azure' and api.name = 'azure-network-security-group-list'
  and json.rule = "securityRules[? (sourceAddressPrefix equals '*' or sourceAddressPrefix contains '0.0.0.0') and (destinationPortRange contains '22' or destinationPortRange contains '3389' or destinationPortRange contains '5432')] size > 0"
```

# OCI (template)

```sql
config from cloud.resource
where cloud.type = 'oci' and api.name = 'oci-core-security-list-list'
  and json.rule = "ingressSecurityRules[? source contains '0.0.0.0/0' and (tcpOptions.destinationPortRange contains 22 or contains 3389 or contains 5432)] size > 0"
```

# Alibaba (template)

```sql
config from cloud.resource
where cloud.type = 'alibaba' and api.name = 'alibaba-ecs-security-group-list'
  and json.rule = "permissions[? portRange contains '22/22' or portRange contains '3389/3389' and sourceCidrIp equals '0.0.0.0/0'] size > 0"
```

# IBM (template)

```sql
config from cloud.resource
where cloud.type = 'ibm' and api.name = 'ibm-vpc-security-group-list'
  and json.rule = "rules[? remote.cidr_block equals '0.0.0.0/0' and (port_min <= 22 and port_max >= 22 or port_min <= 3389 and port_max >= 3389)] size > 0"
```

---

# Control 6: Managed Databases Publicly Accessible

Regulation: DORA, MICA, FinTRAC (access control).

| Provider | api.name | RQL intent |
|----------|----------|------------|
| AWS | `aws-rds-describe-db-instances` | `PubliclyAccessible is true` |
| GCP | `gcloud-sql-instances-list` or Cloud SQL | `settings.ipConfiguration.authorizedNetworks` or publicIp present |
| Azure | `azure-sql-server-list` or MySQL/PostgreSQL | `publicNetworkAccess is 'Enabled'` or similar |
| OCI | `oci-database-db-system-list` or Autonomous DB | `isPubliclyAccessible is true` |
| Alibaba | `alibaba-rds-instance-list` | `connectionMode` or public connection |
| IBM | `ibm-database-*` or Db2 / PostgreSQL | Public endpoint enabled |

# AWS (reference)

```sql
config from cloud.resource
where cloud.type = 'aws' and api.name = 'aws-rds-describe-db-instances'
  and json.rule = "PubliclyAccessible is true"
```

# GCP (Cloud SQL — verify api.name and path)

```sql
config from cloud.resource
where cloud.type = 'gcp' and api.name = 'gcloud-sql-instances-list'
  and json.rule = "settings.ipConfiguration.authorizedNetworks[*] size > 0 or settings.ipConfiguration.ipv4Enabled is true"
```

*Tune: “public” often means authorizedNetworks including 0.0.0.0/0 or ipv4Enabled.*

# Azure (SQL server — verify api.name)

```sql
config from cloud.resource
where cloud.type = 'azure' and api.name = 'azure-sql-server-list'
  and json.rule = "properties.publicNetworkAccess equals 'Enabled'"
```

# OCI / Alibaba / IBM

Use the managed database resource for each cloud and the “public access” or “public endpoint” field; verify api.name and JSON path in Prisma.

---

# Control 7: Over-Permissive IAM / Identity (Wildcard or Admin)

Regulation: DORA, MICA, FinTRAC (least privilege).

| Provider | api.name | RQL intent |
|----------|----------|------------|
| AWS | `aws-iam-list-role-policies` / attached | `Action contains '*'` or `Resource contains '*'` or AdministratorAccess |
| GCP | `gcloud-iam-project-iam-policy` or `gcloud-iam-project-roles-list` | `roles/owner`, `roles/editor`, or binding with `*` |
| Azure | `azure-iam-role-definition-list` or RBAC assignments | Custom role with `*` action or built-in Owner/Contributor on scope |
| OCI | IAM policy / dynamic group | Policy statement with `allow *` or admin |
| Alibaba | RAM role/policy | `Action: *` or `Resource: *` |
| IBM | IAM policy / service ID | Role with all services or `*` |

# AWS (reference)

```sql
config from cloud.resource
where cloud.type = 'aws' and api.name = 'aws-iam-list-role-policies'
  and json.rule = "policyDocument.Statement[*].Action contains '*' or policyDocument.Statement[*].Resource contains '*'"
```

# GCP (project IAM — reference from OWASP guide)

```sql
config from cloud.resource
where cloud.type = 'gcp' and api.name = 'gcloud-iam-project-roles-list'
  and json.rule = "bindings[*].role contains 'roles/owner' or bindings[*].role contains 'roles/editor'"
```

# Azure (custom role with wildcard — verify api.name)

```sql
config from cloud.resource
where cloud.type = 'azure' and api.name = 'azure-iam-role-definition-list'
  and json.rule = "properties.permissions[*].actions[*] contains '*'"
```

# OCI / Alibaba / IBM

Query IAM policy or role resources for statements with `allow *` or admin-equivalent actions; verify api.name.

---

# Control 8: Storage Without Access Logging

Regulation: DORA, MICA, FinTRAC (audit trail).

| Provider | api.name | RQL intent |
|----------|----------|------------|
| AWS | `aws-s3api-get-bucket-logging` | `LoggingEnabled does not exist` |
| GCP | `gcloud-storage-buckets-list` | Logging config absent or logBucket not set |
| Azure | `azure-storage-account-list` (diagnostic / logging) | Blob logging not enabled |
| OCI | Object Storage bucket | Logging not enabled |
| Alibaba | OSS bucket | Access logging disabled |
| IBM | COS bucket | Activity logging disabled |

# AWS (reference)

```sql
config from cloud.resource
where cloud.type = 'aws' and api.name = 'aws-s3api-get-bucket-logging'
  and json.rule = "LoggingEnabled does not exist"
```

# GCP (bucket logging — verify path)

```sql
config from cloud.resource
where cloud.type = 'gcp' and api.name = 'gcloud-storage-buckets-list'
  and json.rule = "logging.logBucket does not exist or logging does not exist"
```

# Azure (template — verify api and path)

```sql
config from cloud.resource
where cloud.type = 'azure' and api.name = 'azure-storage-account-list'
  and json.rule = "properties.blobServices[*].properties.logging.read is false and properties.blobServices[*].properties.logging.write is false"
```

# OCI / Alibaba / IBM

Use bucket/object storage resource and “logging enabled” or “access log” field; verify api.name and path.

---

# Control 9: Audit / Activity Logging Disabled or Incomplete

Regulation: DORA, MICA, FinTRAC (detection; audit trail).

| Provider | api.name | RQL intent |
|----------|----------|------------|
| AWS | `aws-cloudtrail-describe-trails` | `isLogging is false` or `isMultiRegionTrail is false` |
| GCP | `gcloud-logging-sink-list` or project logging | Log exclusions too broad; or no audit log sink |
| Azure | `azure-monitor-log-profile-list` or activity log | Log profile not configured or storage/category missing |
| OCI | Audit / Logging | Audit not enabled for tenancy/compartment |
| Alibaba | ActionTrail | Trail not enabled or not multi-region |
| IBM | Activity Tracker / LogDNA | Not enabled or not retained |

# AWS (reference)

```sql
config from cloud.resource
where cloud.type = 'aws' and api.name = 'aws-cloudtrail-describe-trails'
  and json.rule = "status.isLogging is false or isMultiRegionTrail is false"
```

# GCP (project audit config — verify api.name)

```sql
config from cloud.resource
where cloud.type = 'gcp' and api.name = 'gcloud-project-settings-list'
  and json.rule = "auditLogConfig does not exist or auditLogConfig[*].service equals 'allServices' and exemptedMembers size > 0"
```

*Refine: ensure audit logs are enabled for admin read/write and data read.*

# Azure (activity log — verify api.name)

```sql
config from cloud.resource
where cloud.type = 'azure' and api.name = 'azure-monitor-log-profile-list'
  and json.rule = "categories size is 0 or retentionPolicy.enabled is false"
```

# OCI / Alibaba / IBM

Use the platform audit/trail resource and “enabled” / “multi-region” / “retention” fields; verify api.name.

---

# Control 10: Storage Without Versioning or Backup

Regulation: DORA, MICA, FinTRAC (recovery; record retention).

| Provider | api.name | RQL intent |
|----------|----------|------------|
| AWS | `aws-s3api-get-bucket-versioning` | `Status does not equal 'Enabled'` |
| GCP | `gcloud-storage-buckets-list` | Object versioning not enabled |
| Azure | `azure-storage-account-list` | Blob versioning / soft delete not enabled |
| OCI | Object Storage bucket | Versioning disabled |
| Alibaba | OSS bucket | Versioning disabled |
| IBM | COS bucket | Versioning disabled |

# AWS (reference)

```sql
config from cloud.resource
where cloud.type = 'aws' and api.name = 'aws-s3api-get-bucket-versioning'
  and json.rule = "Status does not equal 'Enabled'"
```

# GCP (versioning — verify path)

```sql
config from cloud.resource
where cloud.type = 'gcp' and api.name = 'gcloud-storage-buckets-list'
  and json.rule = "versioning.enabled is false or versioning does not exist"
```

# Azure (blob versioning / soft delete — verify path)

```sql
config from cloud.resource
where cloud.type = 'azure' and api.name = 'azure-storage-account-list'
  and json.rule = "properties.blobServices[*].properties.isVersioningEnabled is false"
```

# OCI / Alibaba / IBM

Use bucket resource and versioning/retention field; verify api.name and path.

---

# Control 11: Disks / Volumes Unencrypted

Regulation: DORA, MICA, FinTRAC (protection of data).

| Provider | api.name | RQL intent |
|----------|----------|------------|
| AWS | `aws-ec2-describe-volumes` | `Encrypted is false` |
| GCP | `gcloud-compute-disks-list` | `diskEncryptionKey does not exist` or empty |
| Azure | `azure-disk-list` | `properties.encryption does not exist` or type not customer-managed |
| OCI | `oci-core-volume-list` | `kmsKeyId` not set |
| Alibaba | `alibaba-ecs-disk-list` | Encryption not enabled |
| IBM | `ibm-vpc-volume-list` or classic block storage | Encryption not enabled |

# AWS (reference)

```sql
config from cloud.resource
where cloud.type = 'aws' and api.name = 'aws-ec2-describe-volumes'
  and json.rule = "Encrypted is false"
```

# GCP

```sql
config from cloud.resource
where cloud.type = 'gcp' and api.name = 'gcloud-compute-disks-list'
  and json.rule = "diskEncryptionKey does not exist or diskEncryptionKey.kmsKeyName does not exist"
```

# Azure

```sql
config from cloud.resource
where cloud.type = 'azure' and api.name = 'azure-disk-list'
  and json.rule = "properties.encryption does not exist or properties.encryption.type equals 'EncryptionAtRestWithPlatformKey'"
```

# OCI / Alibaba / IBM

Use compute volume/disk resource and encryption key or encryption type; verify api.name and path.

---

# Control 12: Key/Secrets Management (Customer-Managed or Restrictive)

Regulation: MICA (key management); DORA/FinTRAC (control over sensitive data).

| Provider | api.name | RQL intent |
|----------|----------|------------|
| AWS | `aws-kms-describe-key` | `KeyManager equals 'AWS'` (when CMK required) |
| GCP | `gcloud-kms-keys-list` | Key not CMEK or rotation not set |
| Azure | `azure-keyvault-list` or key resource | Soft delete not enabled; purge protection disabled |
| OCI | Vault / key | Key not customer-managed |
| Alibaba | KMS | Key not customer-managed |
| IBM | Key Protect / HPCS | Key not customer-managed |

# AWS (reference)

```sql
config from cloud.resource
where cloud.type = 'aws' and api.name = 'aws-kms-describe-key'
  and json.rule = "KeyMetadata.KeyManager equals 'AWS'"
```

# GCP (KMS key rotation — verify api.name)

```sql
config from cloud.resource
where cloud.type = 'gcp' and api.name = 'gcloud-kms-keys-list'
  and json.rule = "rotationPeriod does not exist or nextRotationTime does not exist"
```

# Azure (Key Vault soft delete — verify api.name)

```sql
config from cloud.resource
where cloud.type = 'azure' and api.name = 'azure-keyvault-list'
  and json.rule = "properties.enableSoftDelete is false or properties.enablePurgeProtection is false"
```

# OCI / Alibaba / IBM

Use KMS/vault resource and “customer-managed” or “key rotation” or “protection” fields; verify api.name.

---

# Verification Notes for OCI, Alibaba, IBM

1. api.name  
   In Prisma Cloud go to Search → Config → Build query and select the cloud (OCI, Alibaba, IBM). Use the resource type dropdown or run a broad query (e.g. `config from cloud.resource where cloud.type = 'oci'`) and inspect returned `api.name` and JSON structure.

2. JSON paths  
   Provider APIs use different property names (e.g. camelCase vs snake_case, nested under `spec` or `properties`). Inspect a sample resource in Search or the API response and align `json.rule` to the actual schema.

3. IBM Cloud  
   If your Prisma Cloud tenant does not list IBM Cloud, these queries serve as templates for when support is added or for use in other tooling that can query IBM Cloud APIs with similar logic.

4. Scoping  
   Add `and cloud.account = '<id>'` or `and tags.<key> = '<value>'` to limit to regulated workloads (e.g. `tags.regulation = 'DORA'`).

---

Next steps: Map each control to your DORA/MICA/FinTRAC control matrix, create Saved Searches or Custom Policies per provider in Prisma Cloud, and run them against the relevant accounts. Update this document as you confirm `api.name` and paths for OCI, Alibaba, and IBM.
