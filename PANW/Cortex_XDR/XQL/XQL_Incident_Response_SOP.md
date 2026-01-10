# Standard Operating Procedure Guide
# Cortex XDR XQL: Incident Response and Threat Hunting

Document Version: 1.0  
Last Updated: January 9, 2026  
Document Owner: Security Operations  
Review Cycle: Quarterly

---

# Executive Summary

This SOP provides comprehensive guidance for using Cortex XDR's XQL (Extended Query Language) for incident response and threat hunting activities. This document covers XQL syntax, query construction, and practical examples for investigating adversary activities including lateral movement, credential harvesting, exfiltration, privilege escalation, process injection, and related attack techniques.

---

# 1. XQL Overview and Architecture

# 1.1 What is XQL?

XQL (Extended Query Language) is Cortex XDR's powerful query language that enables security analysts to search, analyze, and correlate security events across endpoints, network traffic, and cloud data. XQL provides:

- Unified Data Access: Query across multiple data sources (endpoints, network, cloud)
- Real-time Analysis: Execute queries against live data streams
- Historical Investigation: Search through historical event data
- Advanced Correlation: Join and correlate events from different sources
- MITRE ATT&CK Mapping: Built-in support for mapping behaviors to MITRE ATT&CK framework

# 1.2 XQL Data Sources

XQL can query the following data sources:

- Endpoint Data: Process execution, file operations, registry changes, network connections
- Network Data: Network connections, DNS queries, HTTP/HTTPS traffic
- Cloud Data: CloudTrail logs, VPC Flow logs, CloudWatch events
- Identity Data: Authentication events, user activities, privilege changes
- Threat Intelligence: IOC matches, threat actor attribution

# 1.3 XQL Query Structure

Basic XQL query structure:
```xql
dataset = <dataset_name>
| filter <condition>
| fields <field_list>
| dedup <field>
| sort <field> <direction>
| limit <number>
```

---

# 2. XQL Syntax and Fundamentals

# 2.1 Core XQL Commands

# Dataset Declaration
```xql
dataset = xdr_data
```
Available datasets:
- `xdr_data`: All XDR events
- `xdr_network`: Network-specific events
- `xdr_endpoint`: Endpoint-specific events
- `xdr_identity`: Identity and authentication events

# Filter Command
```xql
| filter <field> <operator> <value>
```

Operators:
- `=`: Equals
- `!=`: Not equals
- `>`: Greater than
- `<`: Less than
- `>=`: Greater than or equal
- `<=`: Less than or equal
- `contains`: String contains
- `in`: Value in list
- `not in`: Value not in list
- `like`: Pattern matching (SQL LIKE)
- `regex`: Regular expression matching

Examples:
```xql
# Filter by process name
| filter action_process_image_name = "cmd.exe"

# Filter by multiple values
| filter action_process_image_name in ("cmd.exe", "powershell.exe", "wmic.exe")

# Filter by time range
| filter event_time_ts >= 1704067200 and event_time_ts <= 1704153600

# Pattern matching
| filter action_process_image_name like "%powershell%"

# Regular expression
| filter action_process_image_name regex ".*\.(exe|dll|bat)$"
```

# Fields Command
```xql
| fields <field1>, <field2>, <field3>
```

Select specific fields to include in results:
```xql
| fields event_time_ts, action_process_image_name, action_file_path, actor_primary_user_sid
```

# Deduplication
```xql
| dedup <field> [keep_first | keep_last]
```

Remove duplicate records based on specified field:
```xql
| dedup action_process_image_name keep_first
```

# Sorting
```xql
| sort <field> [asc | desc]
```

Sort results by field:
```xql
| sort event_time_ts desc
```

# Limiting Results
```xql
| limit <number>
```

Limit the number of results returned:
```xql
| limit 1000
```

# 2.2 Advanced XQL Operations

# Aggregation (comp)
```xql
| comp <aggregation_function>() by <field> as <alias>
```

Aggregation functions:
- `count()`: Count occurrences
- `sum()`: Sum numeric values
- `avg()`: Average numeric values
- `min()`: Minimum value
- `max()`: Maximum value
- `distinct_count()`: Count distinct values

Examples:
```xql
# Count processes by image name
| comp count() by action_process_image_name as process_count

# Count distinct users
| comp distinct_count(actor_primary_user_sid) by action_process_image_name as unique_users

# Average file size
| comp avg(action_file_size) by action_file_path as avg_size
```

# Joining Datasets
```xql
| join type=left <dataset> on <join_condition>
```

Example:
```xql
dataset = xdr_data
| filter event_type = PROCESS
| join type=left xdr_data on action_process_image_name = action_parent_process_image_name
```

# Time-based Operations
```xql
# Convert timestamp to readable format
| format time(event_time_ts) as readable_time

# Filter by relative time
| filter event_time_ts >= now() - 3600  # Last hour
| filter event_time_ts >= now() - 86400  # Last 24 hours
```

# Conditional Logic
```xql
# Using if-else
| eval <new_field> = if(<condition>, <true_value>, <false_value>)

# Using case statements
| eval risk_level = case(
    event_severity = "critical", "HIGH",
    event_severity = "high", "MEDIUM",
    default "LOW"
)
```

---

# 3. Incident Response Scenarios

# 3.1 Lateral Movement Detection

Lateral movement refers to techniques adversaries use to move through a network after initial compromise.

# Query 1: Suspicious Remote Process Execution
```xql
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("psexec.exe", "wmic.exe", "sc.exe", "at.exe", "schtasks.exe")
| filter action_remote_process_image_name != null
| fields event_time_ts, action_process_image_name, action_remote_process_image_name, 
        actor_primary_user_sid, actor_process_image_name, action_process_image_path,
        action_remote_ip, action_remote_hostname
| sort event_time_ts desc
| limit 500
```

# Query 2: Network Connections to Multiple Internal Hosts
```xql
dataset = xdr_data
| filter event_type = NETWORK
| filter action_local_ip != null
| filter action_remote_ip != null
| filter action_remote_ip like "10.%"
| comp count() by actor_process_image_name, action_local_ip as connection_count
| filter connection_count > 10
| fields actor_process_image_name, action_local_ip, connection_count, 
        action_remote_ip, action_remote_port
| sort connection_count desc
```

# Query 3: SMB/File Share Access Patterns
```xql
dataset = xdr_data
| filter event_type = FILE
| filter action_file_path like "\\\\%"
| filter action_file_path not like "\\\\%\\IPC$%"
| comp count() by actor_primary_user_sid, action_file_path as access_count
| filter access_count > 5
| fields event_time_ts, actor_primary_user_sid, action_file_path, 
        action_process_image_name, action_file_operation, access_count
| sort event_time_ts desc
```

# Query 4: RDP/WinRM Connections
```xql
dataset = xdr_data
| filter event_type = NETWORK
| filter action_remote_port in (3389, 5985, 5986)
| filter action_local_ip != null
| comp count() by action_remote_ip, action_local_ip as session_count
| filter session_count > 3
| fields event_time_ts, action_remote_ip, action_local_ip, action_remote_port,
        actor_process_image_name, action_network_protocol
| sort event_time_ts desc
```

# Query 5: Scheduled Task Creation for Lateral Movement
```xql
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "schtasks.exe"
| filter action_process_command_line contains "/create"
| filter action_process_command_line contains "/s"
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, action_remote_hostname, action_remote_ip
| sort event_time_ts desc
```

# 3.2 Credential Harvesting Detection

Credential harvesting involves techniques to collect authentication credentials.

# Query 1: LSASS Memory Access (Mimikatz-like Activity)
```xql
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "lsass.exe"
| filter action_parent_process_image_name != "winlogon.exe"
| filter action_parent_process_image_name != "services.exe"
| fields event_time_ts, action_parent_process_image_name, action_parent_process_command_line,
        actor_primary_user_sid, action_process_image_path, action_process_pid
| sort event_time_ts desc
```

# Query 2: Credential Dumping Tools Execution
```xql
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("mimikatz.exe", "procdump.exe", "dumpcap.exe", 
                                      "wce.exe", "fgdump.exe", "gsecdump.exe", 
                                      "pwdump.exe", "quarkspwdump.exe")
| fields event_time_ts, action_process_image_name, action_process_image_path,
        action_process_command_line, actor_primary_user_sid, action_process_pid
| sort event_time_ts desc
```

# Query 3: Registry Access for Credential Storage
```xql
dataset = xdr_data
| filter event_type = REGISTRY
| filter action_registry_key_name contains "LSA"
| filter action_registry_key_name contains "SAM"
| filter action_registry_key_name contains "SECURITY"
| filter action_registry_operation in ("RegOpenKey", "RegQueryValue", "RegSetValue")
| fields event_time_ts, action_registry_key_name, action_registry_value_name,
        action_registry_operation, actor_process_image_name, actor_primary_user_sid
| sort event_time_ts desc
```

# Query 4: Browser Credential Extraction
```xql
dataset = xdr_data
| filter event_type = FILE
| filter action_file_path like "%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data%"
| filter action_file_path like "%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles%\\logins.json%"
| filter action_file_path like "%\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data%"
| filter action_file_operation in ("FILE_WRITE", "FILE_READ")
| fields event_time_ts, action_file_path, action_file_operation,
        actor_process_image_name, actor_primary_user_sid
| sort event_time_ts desc
```

# Query 5: PowerShell Credential Harvesting
```xql
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "powershell.exe"
| filter action_process_command_line regex "(?i)(password|pwd|passwd|credential|securestring|convertto-securestring)"
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, action_process_image_path
| sort event_time_ts desc
```

# 3.3 Data Exfiltration Detection

Exfiltration involves unauthorized transfer of data from the network.

# Query 1: Large Outbound Data Transfers
```xql
dataset = xdr_data
| filter event_type = NETWORK
| filter action_network_bytes_out > 104857600  # 100 MB
| filter action_remote_ip not like "10.%"
| filter action_remote_ip not like "172.16.%"
| filter action_remote_ip not like "192.168.%"
| fields event_time_ts, action_local_ip, action_remote_ip, action_remote_port,
        action_network_bytes_out, actor_process_image_name, action_network_protocol
| sort action_network_bytes_out desc
| limit 100
```

# Query 2: Unusual Outbound Connections
```xql
dataset = xdr_data
| filter event_type = NETWORK
| filter action_remote_ip not like "10.%"
| filter action_remote_ip not like "172.16.%"
| filter action_remote_ip not like "192.168.%"
| filter action_remote_port in (443, 80, 8080, 8443)
| comp count() by action_remote_ip, actor_process_image_name as connection_count
| filter connection_count > 20
| comp sum(action_network_bytes_out) by action_remote_ip as total_bytes
| fields action_remote_ip, actor_process_image_name, connection_count, total_bytes
| sort total_bytes desc
```

# Query 3: Cloud Storage Upload Activity
```xql
dataset = xdr_data
| filter event_type = NETWORK
| filter action_remote_hostname like "%.dropbox.com"
| filter action_remote_hostname like "%.googleapis.com"
| filter action_remote_hostname like "%.amazonaws.com"
| filter action_remote_hostname like "%.onedrive.com"
| filter action_network_bytes_out > 1048576  # 1 MB
| fields event_time_ts, action_remote_hostname, action_remote_ip,
        action_network_bytes_out, actor_process_image_name, actor_primary_user_sid
| sort action_network_bytes_out desc
```

# Query 4: File Compression Before Exfiltration
```xql
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("7z.exe", "winrar.exe", "winzip.exe", "tar.exe", "zip.exe")
| filter action_process_command_line regex "(?i)(\.(zip|rar|7z|tar|gz))"
| comp count() by actor_primary_user_sid, action_process_image_name as compression_count
| filter compression_count > 3
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, compression_count
| sort event_time_ts desc
```

# Query 5: DNS Tunneling Indicators
```xql
dataset = xdr_data
| filter event_type = NETWORK
| filter action_network_protocol = "DNS"
| filter action_remote_hostname regex "^[a-z0-9]{50,}\."
| comp count() by action_remote_hostname, actor_process_image_name as dns_query_count
| filter dns_query_count > 100
| fields event_time_ts, action_remote_hostname, actor_process_image_name,
        action_remote_ip, dns_query_count
| sort dns_query_count desc
```

# 3.4 Privilege Escalation Detection

Privilege escalation involves gaining higher-level permissions.

# Query 1: UAC Bypass Attempts
```xql
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("eventvwr.exe", "fodhelper.exe", "sdclt.exe", 
                                      "compmgmtlauncher.exe", "computerdefaults.exe")
| filter action_process_command_line != null
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, action_parent_process_image_name
| sort event_time_ts desc
```

# Query 2: Service Creation with Elevated Privileges
```xql
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "sc.exe"
| filter action_process_command_line contains "create"
| filter action_process_command_line contains "binPath"
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, action_parent_process_image_name
| sort event_time_ts desc
```

# Query 3: Scheduled Task Creation for Privilege Escalation
```xql
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "schtasks.exe"
| filter action_process_command_line contains "/create"
| filter action_process_command_line contains "/ru"
| filter action_process_command_line contains "SYSTEM"
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, action_parent_process_image_name
| sort event_time_ts desc
```

# Query 4: Token Manipulation
```xql
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("incognito.exe", "mimikatz.exe", "token.exe")
| filter action_process_command_line regex "(?i)(token|impersonate|steal)"
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, action_process_image_path
| sort event_time_ts desc
```

# Query 5: Registry Modifications for Privilege Escalation
```xql
dataset = xdr_data
| filter event_type = REGISTRY
| filter action_registry_key_name like "%\\Image File Execution Options%"
| filter action_registry_key_name like "%\\Debugger%"
| filter action_registry_operation = "RegSetValue"
| fields event_time_ts, action_registry_key_name, action_registry_value_name,
        action_registry_operation, actor_process_image_name, actor_primary_user_sid
| sort event_time_ts desc
```

# 3.5 Process Injection Detection

Process injection involves injecting malicious code into running processes.

# Query 1: Process Hollowing Indicators
```xql
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("svchost.exe", "notepad.exe", "explorer.exe")
| filter action_parent_process_image_name not in ("services.exe", "winlogon.exe", "explorer.exe")
| comp count() by action_process_image_name, action_parent_process_image_name as injection_count
| filter injection_count > 1
| fields event_time_ts, action_process_image_name, action_parent_process_image_name,
        action_process_command_line, actor_primary_user_sid, injection_count
| sort event_time_ts desc
```

# Query 2: DLL Injection via LoadLibrary
```xql
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("rundll32.exe", "regsvr32.exe")
| filter action_process_command_line regex "(?i)(\.dll|scrobj\.dll|\.sct)"
| filter action_process_command_line not like "%\\Windows\\System32%"
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, action_parent_process_image_name
| sort event_time_ts desc
```

# Query 3: Reflective DLL Loading
```xql
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "powershell.exe"
| filter action_process_command_line regex "(?i)(reflect|loadlibrary|virtualalloc|createremotethread)"
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, action_parent_process_image_name
| sort event_time_ts desc
```

# Query 4: Process Injection via CreateRemoteThread
```xql
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("mimikatz.exe", "metasploit.exe", "cobaltstrike.exe")
| filter action_process_command_line regex "(?i)(createremotethread|virtualallocex|writeprocessmemory)"
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, action_parent_process_image_name
| sort event_time_ts desc
```

# Query 5: Unusual Process Memory Access
```xql
dataset = xdr_data
| filter event_type = PROCESS
| comp count() by actor_process_image_name, action_process_image_name as access_count
| filter access_count > 5
| filter action_process_image_name in ("lsass.exe", "svchost.exe", "explorer.exe")
| fields event_time_ts, actor_process_image_name, action_process_image_name,
        access_count, actor_primary_user_sid
| sort access_count desc
```

# 3.6 Additional Attack Techniques

# Query 1: Persistence Mechanisms
```xql
dataset = xdr_data
| filter event_type = REGISTRY
| filter action_registry_key_name like "%\\Run%"
| filter action_registry_key_name like "%\\RunOnce%"
| filter action_registry_key_name like "%\\Winlogon%"
| filter action_registry_operation = "RegSetValue"
| fields event_time_ts, action_registry_key_name, action_registry_value_name,
        action_registry_operation, actor_process_image_name, actor_primary_user_sid
| sort event_time_ts desc
```

# Query 2: Living-off-the-Land Binaries (LOLBins)
```xql
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("certutil.exe", "bitsadmin.exe", "mshta.exe",
                                      "wscript.exe", "cscript.exe", "rundll32.exe",
                                      "regsvr32.exe", "msiexec.exe", "wmic.exe")
| filter action_process_command_line regex "(?i)(download|upload|execute|bypass)"
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, action_parent_process_image_name
| sort event_time_ts desc
```

# Query 3: Anti-Forensics Activities
```xql
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("wevtutil.exe", "auditpol.exe", "logman.exe")
| filter action_process_command_line regex "(?i)(clear|delete|stop|disable)"
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, action_parent_process_image_name
| sort event_time_ts desc
```

# Query 4: Suspicious PowerShell Execution
```xql
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "powershell.exe"
| filter action_process_command_line regex "(?i)(-enc|-e |-encodedcommand|hidden|bypass|noprofile|noninteractive)"
| comp count() by actor_primary_user_sid as ps_execution_count
| filter ps_execution_count > 5
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, ps_execution_count
| sort event_time_ts desc
```

# Query 5: WMI Abuse
```xql
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "wmic.exe"
| filter action_process_command_line regex "(?i)(process call create|/node:|/user:|/password:)"
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, action_parent_process_image_name
| sort event_time_ts desc
```

---

# 4. MITRE ATT&CK Framework Mapping

# 4.1 MITRE ATT&CK Tactics and Techniques

XQL queries can be mapped to MITRE ATT&CK framework tactics and techniques:

# Lateral Movement (TA0008)
- T1021.001: Remote Desktop Protocol (Query 3.1.4)
- T1021.002: SMB/Windows Admin Shares (Query 3.1.3)
- T1021.003: Distributed Component Object Model (DCOM)
- T1078: Valid Accounts (Query 3.1.1, 3.1.2)

# Credential Access (TA0006)
- T1003.001: LSASS Memory (Query 3.2.1)
- T1003.002: Security Account Manager (Query 3.2.3)
- T1555.003: Credentials from Web Browsers (Query 3.2.4)
- T1056.001: Keylogging
- T1110.001: Brute Force: Password Guessing

# Exfiltration (TA0010)
- T1041: Exfiltration Over C2 Channel (Query 3.3.1, 3.3.2)
- T1567.002: Exfiltration to Cloud Storage (Query 3.3.3)
- T1020: Automated Exfiltration (Query 3.3.4)
- T1071.004: DNS (Query 3.3.5)

# Privilege Escalation (TA0004)
- T1548.002: Bypass User Account Control (Query 3.4.1)
- T1543.003: Create or Modify System Process: Windows Service (Query 3.4.2)
- T1053.005: Scheduled Task/Job: Scheduled Task (Query 3.4.3)
- T1134: Access Token Manipulation (Query 3.4.4)
- T1112: Modify Registry (Query 3.4.5)

# Defense Evasion (TA0005)
- T1055: Process Injection (Query 3.5.1, 3.5.2, 3.5.3, 3.5.4)
- T1070.001: Indicator Removal: Clear Windows Event Logs (Query 3.6.3)
- T1218.005: System Binary Proxy Execution: Mshta (Query 3.6.2)

# Persistence (TA0003)
- T1547.001: Boot or Logon Autostart Execution: Registry Run Keys (Query 3.6.1)
- T1053.005: Scheduled Task/Job: Scheduled Task

# 4.2 Creating MITRE ATT&CK Mapped Queries

When creating queries, include MITRE ATT&CK mapping in comments:

```xql
# MITRE ATT&CK: T1021.001 - Remote Desktop Protocol
# Tactic: Lateral Movement (TA0008)
dataset = xdr_data
| filter event_type = NETWORK
| filter action_remote_port = 3389
| filter action_local_ip != null
| comp count() by action_remote_ip, action_local_ip as session_count
| filter session_count > 3
| fields event_time_ts, action_remote_ip, action_local_ip, action_remote_port,
        actor_process_image_name, action_network_protocol
| sort event_time_ts desc
```

---

# 5. Best Practices and Optimization

# 5.1 Query Performance Optimization

1. Use Specific Filters Early: Apply the most restrictive filters first
2. Limit Result Sets: Always use `limit` to prevent excessive data retrieval
3. Select Only Needed Fields: Use `fields` to reduce data transfer
4. Use Time Ranges: Filter by `event_time_ts` to limit dataset size
5. Avoid Wildcards in Filters: Use specific values when possible

# 5.2 Query Organization

1. Document Queries: Include comments explaining purpose and MITRE ATT&CK mapping
2. Version Control: Maintain query libraries in version control
3. Parameterization: Create reusable query templates with parameters
4. Testing: Test queries in non-production environments first

# 5.3 Incident Response Workflow

1. Initial Triage: Use broad queries to identify suspicious activity
2. Deep Dive: Narrow queries based on initial findings
3. Correlation: Join multiple data sources to build attack timeline
4. Documentation: Document findings and query results
5. Remediation: Use query results to guide containment and eradication

---

# 6. Advanced XQL Techniques

# 6.1 Building Attack Timelines

```xql
# Create a timeline of related events
dataset = xdr_data
| filter actor_primary_user_sid = "<SID>"
| filter event_time_ts >= <start_time> and event_time_ts <= <end_time>
| fields event_time_ts, event_type, action_process_image_name, 
        action_process_command_line, action_file_path, action_remote_ip
| sort event_time_ts asc
```

# 6.2 Correlation Across Multiple Events

```xql
# Correlate process execution with network connections
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "powershell.exe"
| join type=left xdr_data on actor_process_image_name = action_process_image_name
| filter event_type = NETWORK
| fields event_time_ts, action_process_image_name, action_process_command_line,
        action_remote_ip, action_remote_port, action_network_bytes_out
| sort event_time_ts desc
```

# 6.3 Anomaly Detection

```xql
# Identify unusual process execution patterns
dataset = xdr_data
| filter event_type = PROCESS
| comp count() by actor_primary_user_sid, action_process_image_name as execution_count
| comp avg(execution_count) by actor_primary_user_sid as avg_executions
| eval deviation = execution_count - avg_executions
| filter deviation > 10
| fields actor_primary_user_sid, action_process_image_name, execution_count, 
        avg_executions, deviation
```

---

# 7. Troubleshooting Common Issues

# 7.1 Query Performance Issues

Problem: Query takes too long to execute  
Solutions:
- Add time range filters
- Reduce result set with `limit`
- Use more specific filters
- Split complex queries into multiple simpler queries

# 7.2 Missing Data

Problem: Expected events not appearing in results  
Solutions:
- Verify dataset selection
- Check time range filters
- Verify field names are correct
- Check for case sensitivity in filters

# 7.3 False Positives

Problem: Queries returning too many false positives  
Solutions:
- Add additional context filters
- Exclude known-good processes/hosts
- Use more specific indicators
- Implement whitelisting logic

---

# 8. Integration with Incident Response Tools

# 8.1 Exporting Query Results

Query results can be exported in various formats:
- CSV for analysis in Excel/Python
- JSON for API integration
- HTML for reporting

# 8.2 Automation

XQL queries can be automated via:
- Cortex XDR API
- Cortex XSOAR playbooks
- Scheduled queries with alerting

---

# 9. Document Control

Version History:

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-09 | Security Operations | Initial release |

Review and Approval:

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Author | [Name] | | |
| Reviewer | [Name] | | |
| Approver | [Name] | | |

Distribution List:
- Security Operations Team
- Incident Response Team
- Threat Hunting Team
- Security Engineering Team

---

This SOP should be treated as a living document and updated as new attack techniques emerge, XQL capabilities evolve, or organizational needs change. All users are responsible for adhering to these procedures and suggesting improvements through the formal change management process.
