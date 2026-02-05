# Prisma Cloud RQL Guide & SOP  
# Aligning Security Controls to OWASP Top 10 & CSA CCM

---

# Table of Contents

- [Purpose](#purpose)  
- [Scope](#scope)  
- [Standards and References](#standards-and-references)  
- [RQL Fundamentals](#rql-fundamentals)  
- [Control Library & Mappings](#control-library--mappings)  
  - [API Gateways Lacking Authorization](#api-gateways-lacking-authorization)  
  - [Over‑Permissive Lambda Roles](#over-permissive-lambda-roles)  
  - [Over‑Permissive Service Accounts (GCP)](#over-permissive-service-accounts-gcp)  
  - [S3 Buckets Without Logging](#s3-buckets-without-logging)  
  - [Public or Misconfigured S3 Buckets](#public-or-misconfigured-s3-buckets)  
  - [Network Misconfigurations (Security Groups / Firewalls)](#network-misconfigurations-security-groups--firewalls)  
  - [Logging & Monitoring Baseline](#logging--monitoring-baseline)  
- [SOP: Operationalizing RQL Controls](#sop-operationalizing-rql-controls)  
  - [Designing the Control Library](#designing-the-control-library)  
  - [RQL Query Lifecycle](#rql-query-lifecycle)  
  - [Alerting & Triage Process](#alerting--triage-process)  
  - [Exception & Risk Acceptance](#exception--risk-acceptance)  
  - [Continuous Monitoring & Reporting](#continuous-monitoring--reporting)  
- [Extending for Your Environment](#extending-for-your-environment)  

---

# Purpose

Objective: Define a practical guide and SOP for using Prisma Cloud RQL to detect and monitor cloud misconfigurations and risks, mapped to OWASP Top 10 and CSA Cloud Controls Matrix (CCM).

Outcomes:

- A mapped control set (RQL queries ↔ OWASP ↔ CSA CCM).  
- A repeatable SOP to design, validate, deploy, and maintain RQL‑based controls.  
- Coverage for key risks such as API gateways missing authorization, over‑permissive Lambda/service accounts, missing logging on S3 and other resources, and general misconfigurations.

---

# Scope

# Technologies

- Cloud Providers
  - AWS (initial focus): API Gateway, Lambda, IAM, S3, CloudTrail, CloudWatch, Security Groups, RDS, etc.
  - Extendable to GCP (IAM, Storage, Cloud Logging, service accounts) and Azure (API Management, Functions, Storage, Monitor).

# Risk Areas

- Identity & Access Management:  
  Over‑permissive roles, wildcards in policies, privileged service accounts, lack of least privilege.
- API Exposure & Access Control:  
  API gateways without auth, missing WAF, public endpoints.
- Logging, Monitoring & Detection:  
  Missing S3 access logs, incomplete CloudTrail, disabled audit logs.
- Network Exposure & Segmentation:  
  Public security groups, public RDS or equivalent managed databases.
- Data Protection & Storage:  
  Public/storage buckets, missing encryption, misconfigured access.

---

# Standards and References

# OWASP Top 10 (focus controls)

- A01:2021 – Broken Access Control  
  Over‑permissive IAM roles, missing API auth, public data stores.
- A02:2021 – Cryptographic Failures  
  Missing encryption at rest / in transit.
- A05:2021 – Security Misconfiguration  
  Public buckets, insecure defaults, missing WAF, overly open security groups.
- A07:2021 – Identification and Authentication Failures  
  Weak or missing auth for APIs.
- A08:2021 – Software and Data Integrity Failures  
  (Extended with CI/CD and runtime policies as needed.)
- A09:2021 – Security Logging and Monitoring Failures  
  Missing bucket logs, CloudTrail gaps, insufficient monitoring.
- A10:2021 – Server‑Side Request Forgery (SSRF)  
  (Primarily covered by network & identity controls and service‑specific configs.)

# CSA Cloud Controls Matrix (CCM) (example domains)

- IAM – Identity & Access Management (IAM‑xx)  
- DSI – Data Security & Information Lifecycle (DSI‑xx)  
- LOG – Logging & Monitoring (LOG‑xx)  
- IVS – Infrastructure & Virtualization Security (IVS‑xx)  
- TVM – Threat & Vulnerability Management (TVM‑xx)  
- AIS / GRM – Application & Interface Security / Governance, Risk & Management  

---

# RQL Fundamentals

# Core Pattern

Most controls will use config queries:

```sql
config from cloud.resource
where api.name = '<cloud-api-name>'
  and json.rule = '<condition on configuration JSON>'
```

# Common Constructs

- Filter by API (resource type):

  ```sql
  where api.name = 'aws-s3api-get-bucket-acl'
  ```

- Environment scoping (example):

  ```sql
  and tags.environment = 'prod'
  -- or
  and cloud.account in ('prod-account-1', 'prod-account-2')
  ```

- JSON rule patterns:
  - Equality: `field equals value`
  - Non‑existence: `field does not exist`
  - Array contains: `field[*].subfield contains 'VALUE'`
  - Size checks: `size(field) == 0` or `... size > 0`

> Note: Exact `api.name` strings may vary by Prisma Cloud version. Use Prisma’s UI auto‑complete or resource explorer to confirm.

---

# Control Library & Mappings

Below is a starter control set with:  
(1) Description, (2) OWASP/CSA mapping, (3) Example RQL.

You can turn each into a Saved Search / Custom Policy in Prisma Cloud with a naming convention like:  
`STD-OWASP-A01-API-GW-NO-AUTH`, `STD-CCM-IAM-03-LAMBDA-ADMIN-ROLE`, etc.

---

# API Gateways Lacking Authorization

# Control: API gateway methods without any authorization

- Risk: API endpoints are accessible without IAM, Cognito, or a custom authorizer.  
- OWASP: A01:2021 – Broken Access Control, A05:2021 – Security Misconfiguration  
- CSA CCM: IAM‑12 (User Access Authorization), IVS‑12 (Network & Security Configuration)

RQL – AWS API Gateway methods with `authorizationType = NONE`:

```sql
config from cloud.resource
where api.name = 'aws-apigateway-get-rest-apis'
  and json.rule = "resources[*].resourceMethods[*].authorizationType equals 'NONE'"
```

# Control: Public API Gateways without WAF

- Risk: Internet‑facing APIs lack WAF protection.  
- OWASP: A05, A01  
- CSA CCM: IVS‑12, AIS‑02

RQL – API Gateways with public endpoints & no WAF association:

```sql
config from cloud.resource
where api.name = 'aws-apigateway-get-rest-apis'
  and json.rule = "endpointConfiguration.types contains 'EDGE' or endpointConfiguration.types contains 'REGIONAL'"
  and json.rule does not contain "webAclArn"
```

---

# Over‑Permissive Lambda Roles

# Control: Lambda execution roles with wildcard permissions

- Risk: Lambda can perform nearly any AWS action or access any resource.  
- OWASP: A01 – Broken Access Control, A05 – Security Misconfiguration  
- CSA CCM: IAM‑03 (Least Privilege), IAM‑08 (Segregation of Duties), TVM‑03

RQL – Lambda roles using `*` in `Action` or `Resource`:

```sql
config from cloud.resource
where api.name = 'aws-lambda-get-function'
  and json.rule = "
    role.policyDocument.Statement[*].Action contains '*' 
    or role.policyDocument.Statement[*].Resource contains '*'
  "
```

# Control: Lambda execution roles with AdministratorAccess

- Risk: Lambda runs with full admin rights.  
- Mappings: same as above.

RQL – Lambda roles with `AdministratorAccess` attached:

```sql
config from cloud.resource
where api.name = 'aws-iam-list-attached-role-policies'
  and json.rule = "attachedPolicies[*].policyName contains 'AdministratorAccess'"
  and roleName starts with 'lambda-'
```

---

# Over‑Permissive Service Accounts (GCP)

# Control: GCP service accounts with Owner/Editor project roles

- Risk: Service accounts can perform almost any action in the project/org.  
- OWASP: A01 – Broken Access Control  
- CSA CCM: IAM‑03/08/12, GRM‑02

RQL – Service accounts bound to `roles/owner` or `roles/editor`:

```sql
config from cloud.resource
where api.name = 'gcloud-iam-project-roles-list'
  and json.rule = "
    bindings[*].members[*] contains 'serviceAccount:' 
    and (bindings[*].role contains 'roles/owner' or bindings[*].role contains 'roles/editor')
  "
```

(You can extend this to org‑level roles or other high‑privilege roles.)

---

# S3 Buckets Without Logging

# Control: S3 buckets without access logging

- Risk: Inability to investigate access to data stores.  
- OWASP: A09 – Security Logging and Monitoring Failures  
- CSA CCM: LOG‑01/02, DSI‑02

RQL – S3 buckets missing access logging:

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-logging'
  and json.rule = "LoggingEnabled does not exist"
```

# Control: Missing CloudTrail data events for S3 object access

- Risk: No object‑level audit trail for critical buckets.  
- OWASP: A09  
- CSA CCM: LOG‑01/02

RQL – CloudTrail without S3 data event selectors:

```sql
config from cloud.resource
where api.name = 'aws-cloudtrail-describe-trails'
  and json.rule = "
    eventSelectors[?contains(dataResources[*].type, 'AWS::S3::Object')] size is 0
  "
```

---

# Public or Misconfigured S3 Buckets

# Control: Publicly readable S3 buckets

- Risk: Unintended public data exposure.  
- OWASP: A01 – Broken Access Control, A05 – Security Misconfiguration  
- CSA CCM: DSI‑01/02/03, IVS‑04

RQL – Buckets with public ACL grants:

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

# Control: Buckets without default encryption

- Risk: Data at rest is unencrypted.  
- OWASP: A02 – Cryptographic Failures  
- CSA CCM: DSI‑01/02

RQL – Buckets missing SSE configuration:

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-encryption'
  and json.rule = "
    ServerSideEncryptionConfiguration.Rules[*].ApplyServerSideEncryptionByDefault.SSEAlgorithm does not exist
  "
```

---

# Network Misconfigurations (Security Groups / Firewalls)

# Control: Security groups open to the world on sensitive ports

- Risk: Direct remote access and exploitation (SSH, RDP, DB).  
- OWASP: A05 – Security Misconfiguration  
- CSA CCM: IVS‑04 (Network Security), IVS‑12, TVM‑02/03

RQL – Security groups open to `0.0.0.0/0` on sensitive ports:

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

# Control: Publicly accessible managed databases

- Risk: Databases directly reachable from the Internet.  
- Mappings: same as above.

RQL – Public RDS instances:

```sql
config from cloud.resource
where api.name = 'aws-rds-describe-db-instances'
  and json.rule = "PubliclyAccessible is true"
```

(Extend to Cloud SQL, Azure SQL, etc., using their respective APIs.)

---

# Logging & Monitoring Baseline

# Control: CloudTrail not enabled or not multi‑region

- Risk: Gaps in audit logs, incomplete forensic trail.  
- OWASP: A09 – Security Logging and Monitoring Failures  
- CSA CCM: LOG‑01/02

RQL – Trails not logging or not multi‑region:

```sql
config from cloud.resource
where api.name = 'aws-cloudtrail-describe-trails'
  and json.rule = "
    status.isLogging is false
    or isMultiRegionTrail is false
  "
```

# Control: Missing CloudWatch alarms for critical events (pattern)

- Risk: Anomalies are not alerted on.  
- OWASP: A09  
- CSA CCM: LOG‑01/02, SEF‑02

RQL – Example pattern (tune per environment):

```sql
config from cloud.resource
where api.name = 'aws-cloudwatch-describe-alarms'
  and json.rule = "
    alarms[*].alarmName does not contain 'UnauthorizedAccess'
    and alarms[*].alarmName does not contain 'ErrorRate'
  "
```

> Note: In practice, you’ll usually enforce the presence of specific required alarms per account/tag, not a global “does not exist anywhere” condition.

---

# SOP: Operationalizing RQL Controls

This section defines the standard operating procedure for creating, maintaining, and enforcing RQL controls tied to OWASP and CSA CCM.

---

# Designing the Control Library

1. Inventory & Scope
   - Identify target environments: e.g., `prod`, `staging`, critical workloads.
   - List in‑scope:
     - Cloud accounts/subscriptions/projects.
     - Regions and services (API Gateway, Lambda, S3, IAM, RDS, etc).
2. Build a Control Matrix
   - Maintain a spreadsheet or wiki table with columns:
     - Control ID (e.g., `CTRL-API-001`)  
     - Control Name (e.g., “API Gateway Methods Require Authorization”)  
     - Description  
     - OWASP Mapping (e.g., A01, A05)  
     - CSA CCM Mapping (e.g., IAM‑12, IVS‑12)  
     - RQL Query / Policy Name  
     - Severity (Critical/High/Medium/Low)  
     - Owner (team or individual)  
     - Environment scope (prod only, all, etc.)  
3. Prioritization
   - Start with 20–40 high‑impact controls:
     - Public data, missing auth, admin roles, missing logging in prod.
   - Add additional controls iteratively.

---

# RQL Query Lifecycle

1. Design
   - For each control, define “bad condition” clearly in plain language.
     - Example: “Any API Gateway method exposed to the Internet where `authorizationType = NONE`.”
   - Draft the RQL query based on the resource type and configuration JSON.
2. Validate
   - Run the query against non‑prod or a subset of accounts.
   - Randomly sample 5–10 findings:
     - Confirm they truly violate the control.
     - Adjust `json.rule` filters to reduce false positives.
3. Standardize & Save
   - Convert validated queries into:
     - Saved Searches or Custom Policies in Prisma Cloud.
   - Apply a consistent naming convention, for example:
     - `STD-OWASP-A01-API-GW-NO-AUTH`  
     - `STD-CCM-IAM-03-LAMBDA-WILDCARD-PERMISSIONS`
   - In the description field, record:
     - Purpose, control mapping, and remediation guidance.
4. Deploy
   - Associate policies with relevant accounts/collections (e.g., only `prod-tagged` resources).
   - Decide if each policy is:
     - Alert only, or
     - Alert + ticket creation (e.g., Jira/ServiceNow via integration).

---

# Alerting & Triage Process

1. Severity Model
   - Critical:
     - Publicly accessible databases.
     - S3 buckets with public access that store sensitive data.
     - Lambda or service accounts with admin privileges in production.
   - High:
     - API Gateways without auth in production.
     - Missing logging on critical S3 buckets.
   - Medium/Low:
     - Non‑prod misconfigurations, missing tags, less risky deviations.
2. Alert Routing
   - Integrate Prisma Cloud with ticketing (Jira/ServiceNow) and/or chat (Slack/Teams).
   - For Critical/High policy violations:
     - Auto‑create tickets with:
       - Resource ID, cloud account, region.
       - Tags (`owner`, `application`, `environment`).
       - Policy name, OWASP and CSA CCM mapping.
       - RQL query / policy ID for reproduction.
3. SLAs
   - Define SLA targets for closure:
     - Critical: ≤ 3 business days.  
     - High: ≤ 7–14 business days.  
     - Medium/Low: best‑effort / backlog.
   - Track SLA compliance via dashboard metrics.

---

# Exception & Risk Acceptance

1. Standard Exception Process
   - Create a consistent exception form that includes:
     - Business justification and context.
     - Compensating controls in place.
     - Duration (time‑bound exceptions only).
     - Approver (risk owner / security lead).
2. Implementation in RQL / Policies
   - Use tags or metadata (e.g., `exception = 'waived-LOG-01'`).
   - Update RQL rules to exclude waived resources, for example:

     ```sql
     and (tags.exception does not exist or tags.exception != 'waived-LOG-01')
     ```

   - Keep a central register of exceptions (linked to policy IDs and expiry dates).
3. Review
   - Periodically (e.g., monthly/quarterly), review:
     - Exceptions nearing expiry.
     - Whether exceptions can be closed based on remediation.

---

# Continuous Monitoring & Reporting

1. Dashboards
   - Create Prisma Cloud dashboards sliced by:
     - Standard: OWASP / CSA CCM coverage and open findings.
     - Domain: Identity, API, Data, Network, Logging.
     - Environment: prod vs non‑prod, business unit, etc.
2. Key Metrics
   - # of open Critical/High findings by:
     - OWASP category.
     - CSA CCM domain.
   - Mean Time to Remediate (MTTR) per control or domain.
   - Coverage metrics:
     - % of APIs with enforced auth.
     - % of S3 buckets with logging & encryption.
3. Review Cadence
   - Monthly:
     - Review dashboard, major trends, and SLA breaches.
     - Identify top offenders (teams/accounts) and follow up.
   - Quarterly:
     - Revisit control mappings and priorities.
     - Incorporate new OWASP or CCM updates and newly adopted cloud services.
     - Tune RQL rules based on observed noise.

---

# Extending for Your Environment

- Cloud Providers  
  Extend the control library to:
  - GCP: Cloud Storage (public buckets, encryption), Cloud Functions (service account roles), Cloud Run, Cloud SQL, VPC firewall rules, Cloud Logging.  
  - Azure: API Management, Functions, App Service, Azure Storage, Azure Monitor, NSGs, Azure SQL/Cosmos DB.
- Custom Policies & Business Rules  
  - Add RQL controls that match internal policies:
    - Tag compliance (e.g., `owner`, `data-classification`).  
    - Specific encryption standards (KMS keys, CMKs, etc.).  
    - Geo/region restrictions.
- Automation & Integration
  - Integrate Prisma Cloud with:
    - CI/CD (e.g., scanning templates and IaC for misconfigurations).
    - ChatOps for real‑time alerts.
    - CMDB for context and ownership mapping.

---

Next step suggestion: Build a control matrix table in your wiki or repo based on this document and fill in Control ID, Owner, SLA, and current status for each RQL above.

