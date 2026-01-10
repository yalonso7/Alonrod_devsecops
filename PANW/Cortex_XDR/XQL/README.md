# Cortex XDR XQL Incident Response Tools

This directory contains tools and documentation for using Cortex XDR's XQL (Extended Query Language) for incident response and threat hunting.

# Contents

- XQL_Incident_Response_SOP.md: Comprehensive Standard Operating Procedure document covering XQL syntax, query examples, and incident response scenarios
- mitre_attack_reporter.py: HTML report generator that maps security events to MITRE ATT&CK framework
- requirements.txt: Python dependencies for the reporting tool

# Quick Start

# Installation

```bash
pip install -r requirements.txt
```

# Using the MITRE ATT&CK Reporter

The reporter tool generates HTML reports from XQL query results and automatically maps behaviors to MITRE ATT&CK techniques.

# Basic Usage

```bash
# From JSON file
python mitre_attack_reporter.py query_results.json

# From CSV file
python mitre_attack_reporter.py query_results.csv

# Specify output file
python mitre_attack_reporter.py query_results.json -o report.html

# Specify output directory
python mitre_attack_reporter.py query_results.json -d ./reports
```

# Input File Formats

JSON Format:
```json
[
  {
    "event_time_ts": 1704067200,
    "event_type": "PROCESS",
    "action_process_image_name": "powershell.exe",
    "action_process_command_line": "powershell -enc ...",
    "actor_primary_user_sid": "S-1-5-21-..."
  }
]
```

CSV Format:
```csv
event_time_ts,event_type,action_process_image_name,action_process_command_line
1704067200,PROCESS,powershell.exe,"powershell -enc ..."
```

# Features

- Automatic MITRE ATT&CK Mapping: Detects and maps attack techniques based on event indicators
- Timeline Visualization: Creates chronological timeline of security events
- Tactics Summary: Groups events by MITRE ATT&CK tactics
- Technique Details: Provides detailed information about detected techniques
- Statistics: Shows top processes, hosts, and event counts
- HTML Reports: Generates professional HTML reports with visualizations

# XQL Query Examples

See `XQL_Incident_Response_SOP.md` for comprehensive query examples covering:

- Lateral Movement Detection
- Credential Harvesting
- Data Exfiltration
- Privilege Escalation
- Process Injection
- And more...

# MITRE ATT&CK Framework

The tool automatically maps events to MITRE ATT&CK techniques including:

- Lateral Movement: T1021.001 (RDP), T1021.002 (SMB), T1078 (Valid Accounts)
- Credential Access: T1003.001 (LSASS Memory), T1555.003 (Browser Credentials)
- Exfiltration: T1041 (C2 Channel), T1567.002 (Cloud Storage), T1071.004 (DNS)
- Privilege Escalation: T1548.002 (UAC Bypass), T1543.003 (Windows Service)
- Defense Evasion: T1055 (Process Injection), T1070.001 (Event Log Clearing)
- Persistence: T1547.001 (Registry Run Keys)
- Execution: T1059.001 (PowerShell), T1059.003 (Windows Command Shell)

# Support

For questions or issues:
- Review the SOP document for detailed query syntax and examples
- Check the tool's help: `python mitre_attack_reporter.py --help`
- Contact Security Operations team

# Version History

- v1.0 (2026-01-09): Initial release with XQL SOP and MITRE ATT&CK reporter
