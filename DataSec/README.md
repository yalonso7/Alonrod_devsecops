# SAST & Data Security/Integrity Scanner

A comprehensive security scanner designed for DevSecOps and GRC professionals. This tool performs Static Application Security Testing (SAST) and sensitive data discovery (PII/PHI) across source code and data files, providing automated compliance mapping to major regulatory frameworks.

 🚀 Key Features

# 1. Sensitive Data Discovery (DLP/Data Sec)
Detects over 15 types of sensitive information including:
- PII (Personally Identifiable Information): SSN, Credit Cards, Emails, Phone Numbers, Driver's Licenses, Passports, Bank Accounts.
- PHI (Protected Health Information): Medical Record Numbers, Insurance Policy Numbers, Medicare Numbers, Biometric Data, Genetic Data.
- Secrets & Credentials: API Keys, AWS Keys, Private Keys, Database Connection Strings, Hardcoded Passwords.

# 2. Static Application Security Testing (SAST)
Scans source code for common security vulnerabilities aligned with OWASP Top 10:
- SQL Injection
- Command Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Insecure Cryptography
- Insecure Deserialization
- Hardcoded Secrets

# 3. Regulatory Compliance Mapping
Automatically maps findings to specific controls in:
- HIPAA (Health Insurance Portability and Accountability Act)
- PCI-DSS (Payment Card Industry Data Security Standard)
- NIST 800-53 (Security and Privacy Controls for Information Systems)
- ISO 27001 (Information Security Management)
- SOC 2 (Service Organization Control 2)

# 4. Visual Reporting
Generates a self-contained HTML report featuring:
- Executive Summary Dashboards
- Findings by Severity (Pie Charts)
- Findings by Category (Bar Charts)
- Compliance Scorecards
- Detailed finding locations with code context and remediation advice

 📋 Prerequisites

- Python 3.8+
- Required Python packages:
  - `pandas`
  - `matplotlib`
  - `seaborn`

 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd DataSec
   ```

2. Install dependencies:
   ```bash
   pip install pandas matplotlib seaborn
   ```

 💻 Usage

Run the scanner from the command line by providing the directory path you want to scan.

# Basic Scan
```bash
python sast-pii-phi-scanner.py /path/to/your/project
```

# Specify Output File
By default, the report is saved as `security_report.html`. You can specify a custom output path:
```bash
python sast-pii-phi-scanner.py ./src --output my_audit_report.html
```

 🔍 Supported File Types

The scanner recursively checks files with the following extensions:

- Code: `.py`, `.js`, `.java`, `.cs`, `.cpp`, `.c`, `.rb`, `.php`, `.go`, `.rs`, `.ts`, `.jsx`, `.tsx`, `.sql`, `.sh`, `.yaml`, `.yml`, `.json`, `.xml`, `.properties`, `.conf`, `.ini`
- Data: `.csv`, `.txt`, `.log`, `.dat`

*Note: Binary files, git directories, and common build artifacts (e.g., `node_modules`, `venv`) are automatically excluded.*

 📊 Report Interpretation

The generated HTML report is divided into four sections:

1.  Dashboard: High-level metrics on files scanned and total findings.
2.  Executive Summary: Visualizations showing the distribution of findings by severity and type.
3.  Compliance Status: A scorecard showing how your codebase aligns with each supported framework, including a calculated compliance score and critical gaps.
4.  Detailed Findings: A list of every detected issue, including:
    *   Severity: CRITICAL, HIGH, MEDIUM, LOW.
    *   Location: File path and line number.
    *   Context: The specific code snippet or data pattern found.
    *   Remediation: Actionable advice on how to fix the issue.

 ⚠️ Disclaimer

This tool is intended for security assessment purposes only.
- False Positives: While the tool uses context-aware logic to reduce noise (e.g., ignoring test data), false positives are possible.
- False Negatives: Regex-based scanning may miss obfuscated or complex patterns.
- Validation: Always manually verify findings before taking remediation actions.

 🤝 Contributing

Contributions are welcome! Please submit a Pull Request to add new patterns, support additional frameworks, or improve the scanning logic.
