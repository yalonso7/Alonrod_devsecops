# Scam Scanner Toolkit (Python + Go)

This toolkit provides two static scanners to detect likely fake-job/web3 scam repositories:

- `tools/scam_scanner.py`
- `tools/go-scam-scanner/main.go`

Both produce the same style of outputs:
- Markdown incident report with dashboards/graphs (Mermaid)
- JSON summary for automation and SIEM ingestion
- Rule-based findings + ML-style exploitability likelihood + anomaly detection

---

## 1) Python Scanner

### Run

```bash
python tools/scam_scanner.py . --output-md SCAM_SCAN_REPORT_PY.md --output-json SCAM_SCAN_SUMMARY_PY.json
```

### What it detects

- Dynamic code execution primitives (`new Function`, `eval`)
- Process execution (`child_process`, `exec`, `spawn`)
- VS Code auto-run tasks (`runOn: folderOpen`)
- Encoded/obfuscated payload indicators (base64 and hex escapes)
- Hardcoded secrets
- Wallet signature/approval risk patterns
- Suspicious remote URL usage

### ML capabilities

- **Exploitability likelihood model:** Logistic scoring over extracted maliciousness features.
- **Anomaly detection:** Statistical outlier scoring per file (entropy, obfuscation markers, suspicious token density).

---

## 2) Go Scanner

### Run

```bash
go run ./tools/go-scam-scanner --target . --output-md SCAM_SCAN_REPORT_GO.md --output-json SCAM_SCAN_SUMMARY_GO.json
```

### Notes

- Uses native Go only (no external dependencies).
- Mirrors Python report structure and key detection logic.

---

## Report Structure

Each generated Markdown report includes:

1. Executive Summary
2. Risk Dashboard
3. Severity pie chart
4. Exploitability/anomaly dashboard
5. Attack-chain graph
6. Prioritized findings with evidence snippets
7. IOC section (network + behavioral)
8. ML feature snapshot
9. Remediation plan and remediation graph
10. Confidence/limitations and final verdict

---

## Safe Usage

- Run scanners in an isolated environment for suspicious repositories.
- Avoid opening untrusted repos in IDEs before scanning.
- Never execute `npm install` / `npm start` before triage is complete.

