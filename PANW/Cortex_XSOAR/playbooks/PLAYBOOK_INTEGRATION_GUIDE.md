# XSOAR Playbook Integration Guide

# Overview

This guide explains how to use the XSOAR playbooks for investigating AI/MLOps threats and red team activities, with integration to Cortex XDR XQL queries and MITRE ATT&CK/ATLAS framework alignment.

# Playbook Architecture

# Main Playbooks

1. AI_MLOps_Investigation_Playbook.yml
   - Orchestrates investigation of AI/MLOps security incidents
   - Calls sub-playbooks for each attack type
   - Maps findings to MITRE ATLAS framework

2. Red_Team_Activity_Investigation_Playbook.yml
   - Orchestrates investigation of red team and adversary activities
   - Calls sub-playbooks for each attack technique
   - Maps findings to MITRE ATT&CK framework

# Sub-Playbooks

# AI/MLOps Detection Playbooks

- Detect_Prompt_Injection.yml - ATLAS-LLM-01
- Detect_Tool_Poisoning.yml - ATLAS-LLM-02
- Detect_Tool_Confusion_Shadowing.yml - ATLAS-LLM-03, ATLAS-LLM-04
- Detect_MCP_Attacks.yml - ATLAS-LLM-05
- Detect_Data_Poisoning.yml - ATLAS-ML-01
- Detect_Model_Poisoning.yml - ATLAS-ML-02
- Detect_Adversarial_Inputs.yml - ATLAS-ML-03
- Detect_Model_Theft.yml - ATLAS-ML-04
- Detect_MLOps_Infrastructure_Attacks.yml - ATLAS-ML-05

# Red Team Detection Playbooks

- Detect_Lateral_Movement.yml - T1021.001, T1021.002, T1078
- Detect_Credential_Harvesting.yml - T1003.001, T1003.002, T1555.003
- Detect_Data_Exfiltration.yml - T1041, T1567.002, T1020, T1071.004
- Detect_Privilege_Escalation.yml - T1548.002, T1543.003, T1053.005, T1134, T1112
- Detect_Process_Injection.yml - T1055
- Detect_Persistence.yml - T1547.001, T1053.005
- Detect_Defense_Evasion.yml - T1070.001, T1218.005

# Utility Playbooks

- XQL_Query_Executor.yml - Generic playbook for executing XQL queries

# XQL Query Integration

# Query Sources

All playbooks integrate XQL queries from:

1. Cortex_XDR/XQL/XQL_Incident_Response_SOP.md
   - Traditional security threat queries
   - Red team activity detection

2. Cortex_XDR/XQL/XQL_AI_MLOps_Incident_Response_SOP.md
   - AI/MLOps specific queries
   - MCP ecosystem attacks

# Query Execution Flow

```
Playbook Task
    ↓
XQL Query (from SOP)
    ↓
Cortex XDR Integration
    ↓
Query Results
    ↓
MITRE Framework Mapping
    ↓
Incident Context Storage
```

# Example Query Integration

```yaml
# From Detect_Prompt_Injection.yml
scriptarguments:
  query: |
    dataset = xdr_data
    | filter event_type = NETWORK
    | filter action_remote_hostname like "%.openai.com"
    | filter action_http_request_body contains "ignore previous"
    ...
  mitre_technique: "ATLAS-LLM-01"
  tactic: "Initial Access / Execution"
```

# MITRE Framework Mapping

# MITRE ATT&CK Mapping

Red team playbooks map to MITRE ATT&CK:

| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1021.001 | Remote Desktop Protocol | Lateral Movement |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement |
| T1078 | Valid Accounts | Lateral Movement |
| T1003.001 | LSASS Memory | Credential Access |
| T1003.002 | Security Account Manager | Credential Access |
| T1555.003 | Credentials from Web Browsers | Credential Access |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1567.002 | Exfiltration to Cloud Storage | Exfiltration |
| T1548.002 | Bypass User Account Control | Privilege Escalation |
| T1055 | Process Injection | Defense Evasion |

# MITRE ATLAS Mapping

AI/MLOps playbooks map to MITRE ATLAS:

| Technique ID | Name | Tactic |
|--------------|------|--------|
| ATLAS-LLM-01 | Prompt Injection | Initial Access / Execution |
| ATLAS-LLM-02 | Tool Poisoning | Persistence / Defense Evasion |
| ATLAS-LLM-03 | Tool Confusion | Execution / Defense Evasion |
| ATLAS-LLM-04 | Tool Shadowing | Persistence / Defense Evasion |
| ATLAS-LLM-05 | MCP Protocol Manipulation | Initial Access / Lateral Movement |
| ATLAS-ML-01 | Training Data Poisoning | Initial Access / Impact |
| ATLAS-ML-02 | Model Poisoning | Persistence / Impact |
| ATLAS-ML-03 | Adversarial Input | Execution / Impact |
| ATLAS-ML-04 | Model Theft | Collection / Exfiltration |
| ATLAS-ML-05 | MLOps Infrastructure Attack | Initial Access / Execution |

# Usage Examples

# Example 1: Investigating AI Prompt Injection

1. Trigger: Incident created with type "AI Security Incident"
2. Playbook: AI_MLOps_Investigation_Playbook
3. Execution Flow:
   - Initialize investigation
   - Execute Detect_Prompt_Injection sub-playbook
   - Run XQL queries for prompt injection patterns
   - Map findings to ATLAS-LLM-01
   - Generate report

# Example 2: Investigating Lateral Movement

1. Trigger: Alert for suspicious RDP connections
2. Playbook: Red_Team_Activity_Investigation_Playbook
3. Execution Flow:
   - Initialize investigation
   - Execute Detect_Lateral_Movement sub-playbook
   - Run XQL queries for lateral movement indicators
   - Map findings to T1021.001, T1021.002, T1078
   - Build attack timeline
   - Generate report

# Example 3: Custom XQL Query Execution

1. Use: XQL_Query_Executor playbook
2. Inputs:
   - XQLQuery: Custom query from SOP
   - TimeRange: "7 days"
   - MitreTechnique: "T1055"
   - Tactic: "Defense Evasion"
3. Output: Query results with MITRE mapping

# Configuration

# Required Settings

1. Cortex XDR Integration
   - API credentials configured
   - XQL query execution enabled
   - Appropriate permissions

2. Playbook Permissions
   - Read/write access to incidents
   - Ability to execute integrations
   - Access to incident context

# Optional Settings

1. MITRE ATT&CK Integration
   - For enhanced framework mapping
   - Technique details enrichment

2. Threat Intelligence
   - IOC enrichment
   - Threat actor attribution

# Customization

# Adding New Queries

1. Identify Query: From XQL SOP documents
2. Create Task: Add new task in sub-playbook
3. Configure: Set query, technique ID, and tactic
4. Test: Validate query execution

# Modifying Detection Logic

1. Update Query: Modify XQL query in playbook task
2. Adjust Thresholds: Update filter conditions
3. Test: Validate with sample data

# Adding New Techniques

1. Identify Technique: MITRE ATT&CK or ATLAS ID
2. Create Sub-Playbook: New detection playbook
3. Add Queries: XQL queries from SOP
4. Integrate: Add to main playbook

# Best Practices

1. Time Ranges: Always specify appropriate time windows
2. Result Limits: Set reasonable limits (500-1000 results)
3. Error Handling: Implement try-catch for query failures
4. Documentation: Document all customizations
5. Testing: Test in non-production first
6. Version Control: Track playbook versions
7. Review: Regular review of detection effectiveness

# Troubleshooting

# Common Issues

1. Query Timeout
   - Solution: Reduce time range or add filters
   - Example: Change from "30 days" to "7 days"

2. No Results
   - Solution: Verify query syntax and time range
   - Check: Field names and operators

3. Integration Errors
   - Solution: Verify Cortex XDR integration configuration
   - Check: API credentials and permissions

4. Playbook Failures
   - Solution: Review task logs for specific errors
   - Check: Input parameters and dependencies

# Debugging Steps

1. Check Integration Status: Verify Cortex XDR is connected
2. Test Query Manually: Execute query in Cortex XDR console
3. Review Playbook Logs: Check task execution logs
4. Validate Inputs: Ensure all required inputs are provided
5. Check Permissions: Verify playbook has necessary permissions

# Reporting

# Investigation Reports

Playbooks generate reports including:

1. Executive Summary
   - Total events analyzed
   - Techniques detected
   - Attack timeline

2. MITRE Framework Mapping
   - Technique IDs
   - Tactic alignment
   - Technique descriptions

3. Detailed Findings
   - Query results
   - Affected systems
   - Indicators of compromise

4. Recommendations
   - Remediation steps
   - Prevention measures
   - Detection improvements

# Integration with Other Tools

# Cortex XDR

- XQL Queries: Direct integration
- Incident Correlation: Link to XDR incidents
- Endpoint Isolation: Automated response actions

# MITRE ATT&CK Navigator

- Export: Technique mappings
- Visualization: Attack chain visualization
- Gap Analysis: Detection coverage analysis

# Threat Intelligence

- IOC Enrichment: Enrich findings with threat intel
- Attribution: Link to threat actors
- Context: Additional attack context

# Support and Resources

# Documentation

- XQL SOP Documents: `Cortex_XDR/XQL/`
- Playbook README: `Cortex_XSOAR/playbooks/README.md`
- XSOAR Documentation: Official XSOAR docs

# Training

- XQL Query Syntax: Review SOP documents
- Playbook Development: XSOAR training materials
- MITRE Frameworks: MITRE ATT&CK and ATLAS websites

# Contact

For issues or questions:
- Security Operations Team
- XSOAR Administrators
- Cortex XDR Support

# Version History

- v1.0 (2026-01-10): Initial release
  - AI/MLOps investigation playbook
  - Red team activity investigation playbook
  - Sub-playbooks for key detection scenarios
  - XQL query integration
  - MITRE ATT&CK and ATLAS mapping
