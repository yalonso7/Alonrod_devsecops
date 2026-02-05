# RQL Regulatory Compliance Index — DORA, MICA, FinTRAC

Audience: Cortex Cloud / Prisma Cloud customers in blockchain, web3, crypto-assets, and trading who need to align cloud posture with DORA, MICA, and FinTRAC.

---

# Overview

This index links to three RQL query documents. Each document contains ready-to-use Prisma Cloud RQL queries that:

- Support alignment with the listed regulation.
- Detect potential violations (misconfigurations and control gaps) in cloud resources.

Use these with Prisma Cloud (Cortex Xpanse / Cortex Cloud posture) to run config-based checks and feed findings into your compliance and risk processes.

**Multi-cloud coverage:** For **GCP, Azure, Oracle Cloud (OCI), Alibaba Cloud, and IBM Cloud**, use [RQL_MultiCloud_Compliance.md](./RQL_MultiCloud_Compliance.md) for equivalent RQL queries per provider (same DORA/MICA/FinTRAC control intent).

---

# Document Map

| Regulation | Document | Primary focus |
|------------|----------|----------------|
| DORA (EU – Digital Operational Resilience) | [RQL_DORA_Compliance.md](./RQL_DORA_Compliance.md) | ICT risk, protection, detection, third-party cloud risk, recovery |
| MICA (EU – Markets in Crypto-Assets) | [RQL_MICA_Compliance.md](./RQL_MICA_Compliance.md) | Custody, key management, network/systems security, access protocols, record-keeping |
| FinTRAC (Canada – AML/ATF) | [RQL_FinTRAC_Compliance.md](./RQL_FinTRAC_Compliance.md) | Record-keeping (5-year), protection of personal/financial data, access control, audit trail |
| **Multi-Cloud (all above)** | [RQL_MultiCloud_Compliance.md](./RQL_MultiCloud_Compliance.md) | Same control intent across **AWS, GCP, Azure, Oracle OCI, Alibaba Cloud, IBM Cloud** |

---

# Who Should Use Which File

| Customer profile | Primary doc(s) | Optional |
|------------------|----------------|----------|
| EU financial entities (banks, insurers, investment firms, fintech) | DORA | MICA if offering crypto-asset services |
| Crypto-asset service providers (CASPs), exchanges, custody (EU) | MICA, DORA | FinTRAC if Canadian exposure |
| Canadian reporting entities (MSBs, virtual currency dealers, securities, etc.) | FinTRAC | DORA/MICA if EU operations |
| Trading platforms (global) | DORA + FinTRAC or MICA depending on jurisdiction | All three for multi-jurisdiction |

---

# Control Overlap (Cross-Regulatory)

Many technical controls support more than one regulation. Use a single RQL policy where the control is identical and map the finding to each applicable framework.

| Control area | DORA | MICA | FinTRAC |
|--------------|------|------|---------|
| Encryption at rest (e.g. S3, RDS, EBS) | ✓ | ✓ | ✓ |
| No public storage / DB | ✓ | ✓ | ✓ |
| API auth + WAF | ✓ | ✓ | ✓ |
| Access logging (S3, etc.) | ✓ | ✓ | ✓ |
| CloudTrail (on, multi-region, data events) | ✓ | ✓ | ✓ |
| Versioning / backup / retention | ✓ | ✓ | ✓ |
| Least privilege IAM | ✓ | ✓ | ✓ |
| Security groups / network exposure | ✓ | ✓ | ✓ |
| Custody/key management (KMS, secrets) | — | ✓ | ✓ (where applicable) |
| Record-keeping / 5-year retention | ✓ (recovery) | ✓ | ✓ (explicit) |

---

# Quick Start

1. Choose the document(s) that match your regulatory scope (DORA, MICA, FinTRAC).
2. Open the linked markdown file and copy the RQL blocks you need.
3. Create in Prisma Cloud:
   - Saved Searches for ad-hoc or periodic runs, or  
   - Custom Policies (config rules) for continuous compliance.
4. Scope queries by:
   - Cloud account(s) / subscription(s)  
   - Tags (e.g. `tags.regulation = 'DORA'`, `tags.workload = 'custody'`, `tags.regulation = 'FinTRAC'`)  
   - Region (if required for data residency)
5. Map findings to your internal control IDs and to DORA/MICA/FinTRAC requirements for audits and reporting.

---

# Tagging Recommendations (Blockchain / Web3 / Trading)

Consistent tags make it easier to scope RQL to regulated workloads and to report by regulation.

| Tag key | Example values | Use case |
|---------|----------------|---------|
| `regulation` | `DORA`, `MICA`, `FinTRAC` | Which regime(s) apply to the resource |
| `workload` | `custody`, `trading`, `aml`, `financial` | Type of workload for MICA/FinTRAC/DORA |
| `data-classification` | `confidential`, `financial`, `crypto-assets` | Encryption and access policies |
| `environment` | `prod`, `staging` | Prioritize prod in compliance reporting |

---

# Multi-Cloud Provider Coverage

| Provider | RQL queries | Notes |
|----------|-------------|--------|
| **AWS** | In DORA, MICA, FinTRAC docs | Primary; full control set. |
| **GCP** | [RQL_MultiCloud_Compliance.md](./RQL_MultiCloud_Compliance.md) | `cloud.type = 'gcp'`; e.g. `gcloud-storage-buckets-list`, `gcloud-compute-firewall-list`. |
| **Azure** | [RQL_MultiCloud_Compliance.md](./RQL_MultiCloud_Compliance.md) | `cloud.type = 'azure'`; e.g. `azure-storage-account-list`, `azure-disk-list`. |
| **Oracle (OCI)** | [RQL_MultiCloud_Compliance.md](./RQL_MultiCloud_Compliance.md) | Verify `api.name` in Prisma UI (e.g. OCI object storage, DB, VPC). |
| **Alibaba Cloud** | [RQL_MultiCloud_Compliance.md](./RQL_MultiCloud_Compliance.md) | Verify `api.name` (e.g. OSS, RDS, ECS); variants: ali-int, ali-cn, ali-fn. |
| **IBM Cloud** | [RQL_MultiCloud_Compliance.md](./RQL_MultiCloud_Compliance.md) | Template queries; confirm Prisma support and `api.name` in your tenant. |

---

# Related RQL Content in This Repo

- [PRISMA_RQL_OWASP_CCM_GUIDE.md](./PRISMA_RQL_OWASP_CCM_GUIDE.md) — OWASP Top 10 and CSA CCM alignment (general security baseline).
- [PRISMA_RQL_MITRE_ATLAS_AI_SOP.md](./PRISMA_RQL_MITRE_ATLAS_AI_SOP.md) — AI/ML security controls mapped to MITRE ATLAS (relevant if you use ML in trading or custody).

---

# Maintenance

- Review RQL queries when Prisma Cloud adds or changes resource types or `api.name` / schema.
- Update control IDs and severity in each document to match your risk taxonomy and regulatory interpretations.
- Extend to GCP/Azure using the same control intent and the appropriate `api.name` and `json.rule` for those clouds.
