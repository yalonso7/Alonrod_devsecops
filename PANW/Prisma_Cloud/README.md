# Prisma Cloud to Cortex Cloud Migration & GRC Reporting Tool

This tool automates the migration of security configurations from Prisma Cloud to Cortex Cloud while providing comprehensive Governance, Risk, and Compliance (GRC) reporting. It is designed for DevSecOps teams to ensure a seamless transition with validated security posture visibility.

 🚀 Key Features

# 1. Intelligent Migration
*   Policy Transformation: Automatically converts Prisma Cloud policies into Cortex Cloud compatible formats.
*   Alert Rules & Accounts: Migrates alert rules and cloud account configurations.
*   Data Integrity: Verifies item counts between source and destination to ensure no data is lost during transformation.

# 2. Advanced GRC & Compliance Reporting
*   Regulatory Alignment: Automatically maps existing policies to key compliance frameworks:
    *   HIPAA (Health Insurance Portability and Accountability Act)
    *   NIST (National Institute of Standards and Technology)
    *   ISO 27001 (Information Security Management)
    *   SOC 2 (Service Organization Control 2)
    *   PCI DSS (Payment Card Industry Data Security Standard)
*   Smart Mapping: Uses both metadata and semantic analysis to categorize policies even when explicit tags are missing.

# 3. Visual Analytics (HTML Report)
Generates an interactive `migration_compliance_report.html` containing:
*   Executive Summary: High-level metrics on migrated assets.
*   Severity Distribution: Doughnut charts visualizing risk exposure (Critical vs. High vs. Low).
*   Compliance Heatmap: Stacked bar charts showing policy coverage across compliance standards.
*   Detailed Tables: Drill-down views of specific frameworks and migration verification status.

# 4. Enterprise-Grade Reliability
*   Pagination Support: Handles large environments with thousands of policies/alerts by automatically paginating API requests.
*   Robust Error Handling: Continues processing valid items even if individual transformations fail, ensuring maximum data recovery.

---

 📋 Prerequisites

*   Python 3.6+
*   `requests` library

 🛠️ Installation

1.  Clone the repository or download the script.
2.  Install dependencies:
    ```bash
    pip install requests
    ```

 💻 Usage

Run the tool from the command line by providing your Prisma Cloud credentials.

```bash
python PrismaCloud_migrationtool.py \
  --prisma-url "https://api.prismacloud.io" \
  --access-key "YOUR_ACCESS_KEY" \
  --secret-key "YOUR_SECRET_KEY" \
  --output-dir "./migration_output"
```

# Arguments

| Argument | Description | Required |
|----------|-------------|:--------:|
| `--prisma-url` | Base URL of your Prisma Cloud API (e.g., `https://api.prismacloud.io`) | Yes |
| `--access-key` | Your Prisma Cloud Access Key ID | Yes |
| `--secret-key` | Your Prisma Cloud Secret Key | Yes |
| `--output-dir` | Directory where reports and JSON files will be saved (default: `./migration_output`) | No |

---

 📂 Output Files

The tool generates the following files in the specified output directory:

1.  `migration_compliance_report.html`
    *   The Main Deliverable. An interactive HTML dashboard for stakeholders, auditors, and DevSecOps engineers.
    *   Contains graphs, compliance matrices, and verification summaries.

2.  `migration_report.csv`
    *   A concise CSV summary of the migration counts (Source vs. Target) for quick auditing.

3.  `cortex_import_ready.json`
    *   The transformed data ready to be imported into Cortex Cloud.

4.  `prisma_export_raw.json`
    *   A full backup of the raw data exported from Prisma Cloud for reference or rollback.

---

 💡 Feature Benefits Deep Dive

# Why Pagination Matters?
In large enterprise environments, you may have thousands of custom policies. Standard API calls often limit results to 50 or 100 items. This tool's pagination engine ensures 100% data completeness by fetching every single item, preventing "silent data loss" during migration.

# Why Automated GRC Mapping?
Manual compliance mapping is tedious and prone to error. By analyzing policy metadata and descriptions, this tool provides an instant compliance posture assessment. This allows you to answer questions like *"How does our current policy set align with SOC 2?"* immediately after the export.

# Why HTML Visualizations?
JSON and CSV files are hard for leadership to consume. The HTML report bridges the gap between DevSecOps technical data and CISO-level strategic views, making it easier to demonstrate value and prove compliance coverage during the migration project.

#DevSecOps Notes

Key Management Best Practices

-Rotate Keys Periodically: Set an expiration date or use automated tools (like AWS Secrets Manager or Azure Key Vault) to rotate keys regularly.

-Limit Permissions: Create keys for specific roles or service accounts with the least privilege necessary rather than using a full System Admin account.

-Inactive Status: If a key is compromised, immediately change its status to Inactive in the Prisma Cloud console to block access. 
