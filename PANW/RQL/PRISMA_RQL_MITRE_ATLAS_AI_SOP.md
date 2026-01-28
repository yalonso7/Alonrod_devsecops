# Prisma Cloud RQL Guide & SOP  
# AI / ML Cloud Security Controls Mapped to MITRE ATLAS

---

# Table of Contents

- [Purpose](#purpose)  
- [Scope](#scope)  
- [References](#references)  
- [Overview of MITRE ATLAS Phases](#overview-of-mitre-atlas-phases)  
- [Core AI Cloud Threat Scenarios](#core-ai-cloud-threat-scenarios)  
- [RQL Control Library (by MITRE ATLAS Phase)](#rql-control-library-by-mitre-atlas-phase)  
  - [Reconnaissance & Initial Access](#reconnaissance--initial-access)  
  - [Data & Feature Store Compromise](#data--feature-store-compromise)  
  - [Model Training, Pipeline, and Artifact Security](#model-training-pipeline-and-artifact-security)  
  - [Inference Endpoint & API Protection](#inference-endpoint--api-protection)  
  - [Infrastructure, GPU, and Identity Hardening](#infrastructure-gpu-and-identity-hardening)  
  - [Logging, Monitoring, and Detection](#logging-monitoring-and-detection)  
- [Standard Operating Procedure (SOP)](#standard-operating-procedure-sop)  
  - [Design & Maintenance of the AI Security Control Library](#design--maintenance-of-the-ai-security-control-library)  
  - [Detection Engineering Workflow](#detection-engineering-workflow)  
  - [Incident Response Workflow for AI Cloud Resources](#incident-response-workflow-for-ai-cloud-resources)  
  - [Exception Management](#exception-management)  
  - [Reporting & Metrics](#reporting--metrics)  
- [Extending This SOP](#extending-this-sop)  

---

# Purpose

This document defines a Prisma Cloud RQL guide and SOP for securing AI/ML workloads and supporting cloud resources, aligned to the MITRE ATLAS framework.

Objectives:

- Provide a reusable RQL control library focused on AI/ML use cases.  
- Map each control to the MITRE ATLAS tactic(s) it mitigates.  
- Define an operational SOP for detection engineering and incident response using Prisma Cloud.  

---

# Scope

# Cloud Platforms

- AWS:  
  - General: IAM, EC2 (including GPU instances), S3, RDS, CloudTrail, CloudWatch, Security Groups.  
  - AI‑adjacent: EKS/ECS clusters, SageMaker (where integrated), container registries (ECR).  
- GCP (extend):  
  - IAM, Compute Engine, GCS, Cloud SQL/BigQuery, GKE, Cloud Logging / Monitoring.  
- Azure (extend):  
  - IAM, VM Scale Sets, Storage Accounts, SQL/NoSQL services, AKS, Monitor / Log Analytics.

> Note: Prisma Cloud models AI/ML workloads primarily via underlying cloud resources (compute, storage, identity, network, container, serverless). This SOP focuses on those resource controls as enablers for AI/ML security.

# In‑Scope AI / ML Assets

- Training & Inference Compute  
  - GPU/CPU instances, managed ML services, containerized model servers.  
- Data & Feature Stores  
  - Object storage (e.g., S3), databases (RDS/Cloud SQL), data warehouses.  
- Model Artifacts & Registries  
  - Artifact registries, container registries, model repositories.  
- Pipelines & Orchestration  
  - CI/CD systems that deploy models, job schedulers, Kubernetes clusters.  
- Identity & Access  
  - IAM roles, service accounts, instance profiles used by AI components.

---

# References

- MITRE ATLAS: Adversarial Threat Landscape for Artificial‑Intelligence Systems  
  - Focused tactics / phases used here:
    - Reconnaissance
    - Initial Access
    - Data Poisoning / Data Compromise
    - Model Theft / Exfiltration
    - Evasion / Abuse of AI Services
    - Impact & Persistence
- Prisma Cloud RQL:  
  - `config from cloud.resource` for configuration posture.  
  - Filters by `api.name`, `cloud.account`, `tags.*`, and JSON fields (`json.rule`).  

---

# Overview of MITRE ATLAS Phases

We group MITRE ATLAS activities into cloud‑relevant phases:

1. Reconnaissance & Initial Access  
   - Discovery of exposed AI endpoints, storage, or control planes.  
   - Abuse of public APIs, over‑permissive roles, or leaked keys.  
2. Data & Feature Store Compromise (Data Poisoning / Theft)  
   - Unauthorized modifications to training data / feature stores.  
   - Theft of sensitive data used for model training.  
3. Model Training, Pipeline, and Artifact Security  
   - Tampering with training pipelines, build artifacts, or model registries.  
   - Compromising CI/CD roles or containers that package models.  
4. Inference Endpoint & API Protection  
   - Abuse of model APIs (e.g., prompt injection entry points, model theft through extensive querying).  
   - Misconfigured gateways, lack of auth, no rate limiting / WAF.  
5. Infrastructure, GPU, and Identity Hardening  
   - Misconfigurations in compute, containers, Kubernetes, and GPU workloads.  
6. Logging, Monitoring, and Detection  
   - Ability to reconstruct and detect anomalies across AI workloads via logs and metrics.

---

# Core AI Cloud Threat Scenarios

This RQL library targets the following high‑level AI threats:

- T1 – Exposed AI Inference APIs  
  - Public model endpoints without authentication or WAF protection.  
- T2 – Compromised Training / Feature Data  
  - Insecure data stores (public, unencrypted, no logging) used for training or feature generation.  
- T3 – Pipeline / Artifact Tampering  
  - Over‑privileged CI/CD roles or registries enabling untrusted model artifacts.  
- T4 – GPU & Compute Resource Hijacking  
  - Misconfigured GPU nodes or instances exploitable for crypto‑mining or lateral movement.  
- T5 – Identity Misuse for AI Services  
  - Over‑permissive IAM roles / service accounts linked to AI workloads.  
- T6 – Lack of AI‑Relevant Telemetry  
  - Missing logs on critical assets (data, model endpoints, pipelines).

Each control below is mapped to at least one of these threats and to MITRE ATLAS tactics.

---

# RQL Control Library (by MITRE ATLAS Phase)

# How to Use This Section

- Each control includes:
  - Description and target threats.  
  - MITRE ATLAS mapping (tactics/phases).  
  - Example RQL ready to be adapted into Prisma Cloud custom policies.  
- Use `tags` (e.g., `tags.workload = 'ai'` or `tags.ml-pipeline = 'true'`) to scope controls to AI workloads.

---

# Reconnaissance & Initial Access

# C‑RA‑01: Public AI Inference APIs Without Auth

- Threats: T1 (Exposed AI APIs)  
- MITRE ATLAS: Reconnaissance, Initial Access, Abuse of ML APIs  
- Description: Detect API Gateways exposing AI workloads (`tags.workload = 'ai'`) with no authorization configured.

RQL – AWS API Gateway methods with `authorizationType = NONE` for AI‑tagged APIs:

```sql
config from cloud.resource
where api.name = 'aws-apigateway-get-rest-apis'
  and json.rule = "
    tags.workload equals 'ai'
    and resources[*].resourceMethods[*].authorizationType equals 'NONE'
  "
```

# C‑RA‑02: Public AI Inference APIs Without WAF

- Threats: T1  
- MITRE ATLAS: Reconnaissance, Initial Access  
- Description: Internet‑facing AI APIs should be fronted by WAF for input validation and anomaly detection.

RQL – Public AI APIs without WAF association:

```sql
config from cloud.resource
where api.name = 'aws-apigateway-get-rest-apis'
  and json.rule = "
    tags.workload equals 'ai'
    and (endpointConfiguration.types contains 'EDGE'
         or endpointConfiguration.types contains 'REGIONAL')
  "
  and json.rule does not contain "webAclArn"
```

# C‑RA‑03: Public Storage Used by AI Workloads

- Threats: T1, T2  
- MITRE ATLAS: Reconnaissance, Data Gathering  
- Description: Detect object stores tagged for AI/ML workloads that are publicly readable.

RQL – Public S3 buckets tagged as AI data stores:

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-acl'
  and json.rule = "
    tags.workload equals 'ai'
    and grants[? (
      (grantee.URI contains 'AllUsers' or grantee.URI contains 'AuthenticatedUsers')
      and (permission equals 'READ' or permission equals 'FULL_CONTROL')
    )] size > 0
  "
```

---

# Data & Feature Store Compromise

# C‑DF‑01: AI Training / Feature Stores Without Encryption

- Threats: T2  
- MITRE ATLAS: Data Poisoning, Data Theft  
- Description: Data stores holding training/feature data must be encrypted at rest.

RQL – AI S3 buckets without default encryption:

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-encryption'
  and json.rule = "
    tags.workload equals 'ai'
    and ServerSideEncryptionConfiguration.Rules[*].ApplyServerSideEncryptionByDefault.SSEAlgorithm does not exist
  "
```

# C‑DF‑02: AI Training / Feature Stores Without Access Logging

- Threats: T2, T6  
- MITRE ATLAS: Data Poisoning, Data Theft, Forensics & Analysis  
- Description: Detect AI data buckets without access logging, hindering forensic analysis.

RQL – AI S3 buckets missing access logging:

```sql
config from cloud.resource
where api.name = 'aws-s3api-get-bucket-logging'
  and json.rule = "
    tags.workload equals 'ai'
    and LoggingEnabled does not exist
  "
```

# C‑DF‑03: Public Database Instances Used for AI Training

- Threats: T2  
- MITRE ATLAS: Data Gathering, Data Theft  
- Description: Databases used as training sources must not be publicly accessible.

RQL – Public RDS instances tagged as AI data sources:

```sql
config from cloud.resource
where api.name = 'aws-rds-describe-db-instances'
  and json.rule = "
    tags.workload equals 'ai'
    and PubliclyAccessible is true
  "
```

---

# Model Training, Pipeline, and Artifact Security

# C‑TP‑01: Over‑Permissive CI/CD Roles for AI Pipelines

- Threats: T3, T5  
- MITRE ATLAS: Model Tampering, Supply‑Chain Attack  
- Description: Detect IAM roles used by AI CI/CD that have wildcard privileges.

RQL – AI pipeline roles with `*` in Action/Resource:

```sql
config from cloud.resource
where api.name = 'aws-iam-get-role'
  and json.rule = "
    tags.pipeline equals 'ai'
    and (policyDocument.Statement[*].Action contains '*'
         or policyDocument.Statement[*].Resource contains '*')
  "
```

# C‑TP‑02: Admin‑Level Roles for AI Pipelines

- Threats: T3, T5  
- MITRE ATLAS: Model Tampering, Impact  
- Description: Detect AI tagged roles with AdministratorAccess policy attached.

RQL – AI roles with AdministratorAccess:

```sql
config from cloud.resource
where api.name = 'aws-iam-list-attached-role-policies'
  and json.rule = "
    tags.pipeline equals 'ai'
    and attachedPolicies[*].policyName contains 'AdministratorAccess'
  "
```

# C‑TP‑03: Container Registries for AI Models Without Immutable Tags

- Threats: T3  
- MITRE ATLAS: Model Tampering, Data/Model Integrity  
- Description: AI model images should be stored in registries with immutable tags to prevent overwrite.

RQL – ECR repositories for AI images without image tag immutability:

```sql
config from cloud.resource
where api.name = 'aws-ecr-describe-repositories'
  and json.rule = "
    tags.workload equals 'ai'
    and imageTagMutability equals 'MUTABLE'
  "
```

---

# Inference Endpoint & API Protection

# C‑IN‑01: AI Inference Endpoints Without TLS

- Threats: T1, T2  
- MITRE ATLAS: Abuse of ML APIs, Data Theft  
- Description: AI inference endpoints must use HTTPS / TLS.

*(Example pattern using load balancers for AI endpoints; tune to your architecture.)*

RQL – AI load balancers allowing HTTP listener without redirect to HTTPS:

```sql
config from cloud.resource
where api.name = 'aws-elbv2-describe-load-balancers'
  and json.rule = "
    tags.workload equals 'ai'
    and listeners[*].protocol contains 'HTTP'
    and listeners[*].defaultActions[*].type does not contain 'redirect'
  "
```

# C‑IN‑02: No Rate Limiting / WAF on AI Endpoints

- Threats: T1, T4 (e.g., model extraction via excessive queries)  
- MITRE ATLAS: Abuse of ML APIs, Evasion  
- Description: AI‑tagged APIs must use rate limiting and WAF protections.

RQL – AI API Gateways without WAF or throttling (pattern):

```sql
config from cloud.resource
where api.name = 'aws-apigateway-get-rest-apis'
  and json.rule = "
    tags.workload equals 'ai'
    and (endpointConfiguration.types contains 'EDGE'
         or endpointConfiguration.types contains 'REGIONAL')
  "
  and json.rule does not contain "webAclArn"
```

*(Rate limiting is often encoded in usage plans; add additional `json.rule` checks based on your API Gateway configuration model.)*

---

# Infrastructure, GPU, and Identity Hardening

# C‑INF‑01: GPU Instances with Public SSH/RDP Access

- Threats: T4, T5  
- MITRE ATLAS: Initial Access, Persistence, Impact  
- Description: GPU instances used for AI training or inference must not be directly reachable from the Internet on admin ports.

RQL – Security groups for AI GPU instances open to 0.0.0.0/0 on sensitive ports:

```sql
config from cloud.resource
where api.name = 'aws-ec2-describe-security-groups'
  and json.rule = "
    tags.workload equals 'ai'
    and ipPermissions[?(
      (fromPort <= 22 and toPort >= 22) or
      (fromPort <= 3389 and toPort >= 3389)
    )].ipRanges[*].cidrIp contains '0.0.0.0/0'
  "
```

# C‑INF‑02: AI Compute Instances Without Instance Profile Restrictions

- Threats: T4, T5  
- MITRE ATLAS: Credential Access, Lateral Movement  
- Description: Ensure instance profiles used by AI workloads do not expose broad IAM privileges.

RQL – AI instance profiles using wildcard actions/resources:

```sql
config from cloud.resource
where api.name = 'aws-iam-get-instance-profile'
  and json.rule = "
    tags.workload equals 'ai'
    and (roles[*].assumeRolePolicyDocument.Statement[*].Action contains '*'
         or roles[*].policyDocument.Statement[*].Action contains '*'
         or roles[*].policyDocument.Statement[*].Resource contains '*')
  "
```

# C‑INF‑03: AI Kubernetes Clusters Without Network Policies (pattern)

- Threats: T4, T5  
- MITRE ATLAS: Lateral Movement, Evasion  
- Description: AI namespaces or clusters should enforce network policies to reduce lateral movement.

*(Pattern – tune based on Prisma’s Kubernetes / CNAPP data model in your environment.)*

```sql
config from cloud.resource
where api.name = 'kubernetes-io-v1-namespaces'
  and json.rule = "
    metadata.labels['workload'] equals 'ai'
    and networkPolicies size == 0
  "
```

---

# Logging, Monitoring, and Detection

# C‑LM‑01: CloudTrail Not Enabled / Not Multi‑Region for AI Accounts

- Threats: T2, T3, T4, T6  
- MITRE ATLAS: Forensics & Analysis  
- Description: AI accounts or collections must have CloudTrail logging enabled and multi‑region.

RQL – Trails not logging or not multi‑region for AI collections:

```sql
config from cloud.resource
where api.name = 'aws-cloudtrail-describe-trails'
  and json.rule = "
    tags.workload equals 'ai'
    and (status.isLogging is false
         or isMultiRegionTrail is false)
  "
```

# C‑LM‑02: Missing Object‑Level Logging for AI Data Buckets

- Threats: T2, T6  
- MITRE ATLAS: Data Poisoning, Forensics & Analysis  
- Description: Object‑level events for AI data buckets should be logged via CloudTrail data events.

RQL – AI CloudTrail without S3 data events:

```sql
config from cloud.resource
where api.name = 'aws-cloudtrail-describe-trails'
  and json.rule = "
    tags.workload equals 'ai'
    and eventSelectors[?contains(dataResources[*].type, 'AWS::S3::Object')] size is 0
  "
```

# C‑LM‑03: Missing Alerts for AI Resources (Pattern)

- Threats: T1–T6  
- MITRE ATLAS: Forensics & Analysis, Impact Mitigation  
- Description: Critical AI resources should have CloudWatch / equivalent alerts configured (e.g., on access errors, throttling, spikes).

RQL – AI alarms not present (example pattern):

```sql
config from cloud.resource
where api.name = 'aws-cloudwatch-describe-alarms'
  and json.rule = "
    tags.workload equals 'ai'
    and alarms[*].alarmName does not contain 'AI-'
  "
```

> Tune this control to check for required alarm names/patterns per environment.

---

# Standard Operating Procedure (SOP)

This section defines how to operationalize the above controls using Prisma Cloud.

---

# Design & Maintenance of the AI Security Control Library

1. Define AI Workload Tagging Standard
   - Choose one or more tags:
     - `workload = 'ai'`  
     - `ml-pipeline = 'true'`  
     - `data-domain = 'training'` or `data-domain = 'features'`
   - Ensure engineering teams apply tags consistently to AI‑related resources.
2. Create an AI Security Control Matrix
   - Columns:
     - Control ID (e.g., `C-RA-01`)  
     - Control Name  
     - MITRE ATLAS Tactic(s)  
     - Threat(s) (T1–T6)  
     - RQL Policy / Saved Search Name  
     - Severity (Critical/High/Medium/Low)  
     - Scope (accounts, tags, regions)  
     - Owner (team)  
3. Prioritize High‑Impact Controls
   - Start with:
     - Public AI endpoints without auth/WAF (C‑RA‑01/02).  
     - Public or unencrypted AI data stores (C‑DF‑01/03).  
     - Over‑permissive AI pipeline roles (C‑TP‑01/02).  
     - GPU instances with public access (C‑INF‑01).  
4. Review & Update Quarterly
   - Adjust mappings as MITRE ATLAS evolves.  
   - Add controls for new AI services or architectures adopted in your environment.

---

# Detection Engineering Workflow

1. Control Design
   - For each new AI threat / ATLAS tactic:
     - Describe the threat scenario in plain language.  
     - Identify cloud resources involved (e.g., S3, API Gateway, IAM roles, EKS).  
     - Determine what misconfiguration or condition indicates risk.
2. RQL Development
   - Draft `config from cloud.resource` queries scoped via:
     - `api.name` for relevant services.  
     - `tags.workload = 'ai'` or other AI tags.  
   - Test against a non‑prod or subset of AI resources.
3. Validation
   - Sample at least 5–10 findings per control:  
     - Confirm each result is a real violation.  
     - Refine `json.rule` to reduce noise (e.g., exclude allowed patterns).
4. Standardization
   - Convert validated RQL into:
     - Prisma Cloud Saved Searches and Custom Policies.  
   - Use consistent naming, e.g.:  
     - `AI-ATLAS-C-RA-01-PUBLIC-AI-API-NO-AUTH`  
     - `AI-ATLAS-C-DF-01-AI-DATA-NO-ENCRYPTION`
5. Deployment
   - Assign policies to:
     - Collections representing AI workloads (by account, tag, or project).  
   - Set severity, default notification channels, and ticketing integration.

---

# Incident Response Workflow for AI Cloud Resources

Use this workflow when Prisma Cloud raises Critical or High findings for AI controls.

1. Triage & Classification
   - Confirm:
     - Resource identity (account, region, tags).  
     - Control ID and MITRE ATLAS mapping.  
     - Whether resource is production AI or non‑prod.  
   - Assign priority:
     - Critical: direct exposure of AI endpoints or data (e.g., C‑RA‑01, C‑DF‑03).  
     - High: missing encryption/logging, over‑permissive roles (e.g., C‑DF‑01/02, C‑TP‑01).
2. Containment
   - Depending on control:
     - Restrict public access (update security group, bucket ACL, database public flag).  
     - Attach or correct IAM policies (remove wildcards, revoke admin roles).  
     - Apply WAF / rate limiting or temporarily disable public endpoints.  
   - For suspected active abuse (high volume, signs of compromise):
     - Isolate instance, scale down endpoint, or block offending IPs at WAF / firewall.
3. Investigation
   - Collect:
     - CloudTrail / audit logs.  
     - API Gateway / load balancer access logs.  
     - Storage / DB access history (where available).  
   - Determine:
     - Whether malicious activity occurred (e.g., data exfil, training data tampering).  
     - Affected time window and impacted models or datasets.
4. Eradication & Remediation
   - Remediate configuration per control’s recommended fix:  
     - Enforce TLS, WAF, auth for AI endpoints.  
     - Encrypt and restrict access to AI data stores.  
     - Harden CI/CD roles and registries.  
   - For data poisoning or model tampering suspicion:
     - Invalidate and retrain models from trusted backups.  
     - Replay pipelines with verified data and code.
5. Recovery
   - Restore AI services with hardened configs.  
   - Confirm Prisma Cloud policies no longer trigger for the corrected resources.  
   - Closely monitor AI endpoints and data stores for anomalies post‑incident.
6. Lessons Learned
   - Document:
     - Root cause and attack path.  
     - Gaps in controls or visibility.  
   - Update:
     - RQL controls (tighten conditions).  
     - Tagging standards, runbooks, and CI/CD guardrails.

---

# Exception Management

1. When Exceptions Are Allowed
   - Temporary business or technical constraints for AI workloads:  
     - Urgent experiment requiring broader network access.  
     - Legacy data stores pending migration.  
2. Exception Request Content
   - Required fields:
     - Resource identifier(s).  
     - Control ID(s) to be waived.  
     - Justification and risk acceptance.  
     - Compensating controls (e.g., additional monitoring).  
     - Expiry date and approver.
3. Implementation in RQL
   - Use tags such as `exception = 'ai-atlas-C-RA-01'` for approved exceptions.
   - Update RQL to exclude waived resources:

     ```sql
     and (tags.exception does not exist
          or tags.exception != 'ai-atlas-C-RA-01')
     ```

4. Exception Review
   - Review all open AI exceptions monthly:  
     - Close exceptions where remediation is complete.  
     - Renew only with explicit re‑approval.

---

# Reporting & Metrics

1. Dashboards
   - Create dedicated Prisma Cloud dashboards for:
     - AI MITRE ATLAS posture: counts by tactic (Recon, Data Poisoning, etc.).  
     - AI resource types: endpoints, data stores, pipelines, infrastructure.  
     - Environment: prod vs non‑prod.
2. Key Metrics
   - # of open Critical/High AI findings by ATLAS tactic.  
   - Mean Time to Remediate (MTTR) AI findings by control ID.  
   - Coverage:
     - % of AI endpoints with auth + WAF.  
     - % of AI data buckets encrypted and logged.  
     - % of AI pipelines using least‑privilege roles.
3. Review Cadence
   - Monthly:
     - Review dashboards with AI platform and security teams.  
   - Quarterly:
     - Adjust control coverage based on new AI services and threat intel.  
     - Add or tighten RQL controls where persistent issues are observed.

---

# Extending This SOP

- Cloud‑Specific Enhancements
  - Add GCP and Azure equivalents for each AWS control (e.g., GCS, Cloud SQL, Cloud Functions, Azure Storage, Azure SQL, Functions, APIM).  
  - Extend to Kubernetes / container posture for AI workloads via Prisma Cloud CNAPP capabilities.
- Model‑Level & Application‑Level Controls
  - Combine RQL checks with:  
    - Application‑level telemetry (e.g., prompt injection detection, model usage anomalies).  
    - XDR/XSIAM analytics tied back to AI endpoints.  
- Integration with Governance
  - Map each control to internal AI governance policies and risk register items.  
  - Use this SOP as the authoritative AI cloud security standard for infrastructure and identity posture.

