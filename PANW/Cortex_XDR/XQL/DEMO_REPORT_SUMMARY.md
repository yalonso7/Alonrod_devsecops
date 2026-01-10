# Demo MITRE ATT&CK Report Summary

# Report Generated Successfully

File: `demo_mitre_report.html`  
Generated: 2026-01-09 22:35:24  
Source Data: `demo_sample_data.json` (15 security events)

# Report Contents

# Executive Summary
- Total Events: 15
- MITRE Techniques Detected: 9
- Attack Tactics: 5
- Affected Hosts: 4
- Timeline: 2023-12-31T20:00:00 to 2023-12-31T20:14:00 (14 minutes)

# MITRE ATT&CK Techniques Identified

1. T1059.001 - Command and Scripting Interpreter: PowerShell
   - Tactic: Execution
   - Description: Adversaries may abuse PowerShell to execute commands.

2. T1021.001 - Remote Desktop Protocol
   - Tactic: Lateral Movement
   - Description: Adversaries may use Remote Desktop Protocol (RDP) to move laterally.

3. T1003.001 - LSASS Memory
   - Tactic: Credential Access
   - Description: Adversaries may attempt to access credential material stored in LSASS memory.

4. T1021.002 - SMB/Windows Admin Shares
   - Tactic: Lateral Movement
   - Description: Adversaries may use SMB to move laterally.

5. T1548.002 - Bypass User Account Control
   - Tactic: Privilege Escalation
   - Description: Adversaries may bypass UAC mechanisms to elevate privileges.

6. T1055 - Process Injection
   - Tactic: Defense Evasion
   - Description: Adversaries may inject code into processes to evade defenses.

7. T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys
   - Tactic: Persistence
   - Description: Adversaries may modify registry run keys to maintain persistence.

8. T1555.003 - Credentials from Web Browsers
   - Tactic: Credential Access
   - Description: Adversaries may acquire credentials from web browsers.

9. T1053.005 - Scheduled Task/Job: Scheduled Task
   - Tactic: Privilege Escalation
   - Description: Adversaries may abuse task scheduling functionality to escalate privileges.

10. T1543.003 - Create or Modify System Process: Windows Service
    - Tactic: Privilege Escalation
    - Description: Adversaries may create or modify Windows services to escalate privileges.

11. T1070.001 - Indicator Removal: Clear Windows Event Logs
    - Tactic: Defense Evasion
    - Description: Adversaries may clear Windows event logs to hide their activity.

12. T1567.002 - Exfiltration to Cloud Storage
    - Tactic: Exfiltration
    - Description: Adversaries may exfiltrate data to cloud storage services.

13. T1112 - Modify Registry
    - Tactic: Privilege Escalation
    - Description: Adversaries may modify the registry to escalate privileges.

# Attack Tactics Distribution

- Lateral Movement: Multiple events
- Credential Access: Multiple events
- Privilege Escalation: Multiple events
- Defense Evasion: Multiple events
- Persistence: Multiple events
- Execution: Multiple events
- Exfiltration: Multiple events

# Key Findings

1. Multi-Stage Attack: The timeline shows a progression from initial execution through lateral movement, credential harvesting, privilege escalation, and data exfiltration.

2. Living-off-the-Land: Multiple legitimate Windows binaries were abused (PowerShell, RDP, schtasks, sc.exe, etc.)

3. Persistence Mechanisms: Registry modifications and scheduled tasks were used to maintain access.

4. Defense Evasion: Event log clearing and process injection techniques were employed.

5. Data Exfiltration: Large outbound data transfers to external IPs and cloud storage services.

# Report Features

The HTML report includes:

- ✅ Visual Statistics Dashboard - Summary cards with key metrics
- ✅ MITRE ATT&CK Technique Cards - Detailed information for each detected technique
- ✅ Tactics Summary - Visual breakdown by attack tactic
- ✅ Top Processes Table - Most frequently observed processes
- ✅ Top External Hosts - External IPs with connection counts
- ✅ Event Timeline - Chronological view of all security events
- ✅ Affected Systems - Lists of compromised hosts and users
- ✅ Professional Styling - Modern, responsive HTML design

# How to View

Open `demo_mitre_report.html` in any modern web browser to view the full interactive report.

# Generating Your Own Reports

```bash
# From JSON file
python mitre_attack_reporter.py your_data.json -o report.html

# From CSV file
python mitre_attack_reporter.py your_data.csv -o report.html

# With custom output directory
python mitre_attack_reporter.py your_data.json -d ./reports
```

# Data Format

The tool accepts JSON or CSV files with XQL query results. Required fields:
- `event_time_ts` - Timestamp (Unix epoch or ISO format)
- `event_type` - Event type (PROCESS, NETWORK, FILE, REGISTRY, etc.)
- `action_process_image_name` - Process name
- `action_process_command_line` - Command line arguments
- `action_remote_ip` - Remote IP address
- `action_remote_port` - Remote port number
- `actor_primary_user_sid` - User SID
- And other XQL standard fields

The tool automatically detects MITRE ATT&CK techniques based on event indicators and maps them to the appropriate tactics and techniques.
