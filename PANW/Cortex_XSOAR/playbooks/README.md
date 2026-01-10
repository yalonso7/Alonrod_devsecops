# Cortex XSOAR Investigation Playbooks

This directory contains XSOAR playbooks for investigating security incidents with MITRE ATT&CK and ATLAS framework alignment, integrated with Cortex XDR XQL queries.

# Contents

# Main Playbooks

1. AI_MLOps_Investigation_Playbook.yml - Comprehensive playbook for investigating AI/MLOps security incidents
   - Detects prompt injection attacks (ATLAS-LLM-01)
   - Detects tool poisoning (ATLAS-LLM-02)
   - Detects tool confusion and shadowing (ATLAS-LLM-03, ATLAS-LLM-04)
   - Detects MCP protocol attacks (ATLAS-LLM-05)
   - Detects training data poisoning (ATLAS-ML-01)
   - Detects model poisoning (ATLAS-ML-02)
   - Detects adversarial inputs (ATLAS-ML-03)
   - Detects model theft (ATLAS-ML-04)
   - Detects MLOps infrastructure attacks (ATLAS-ML-05)

2. Red_Team_Activity_Investigation_Playbook.yml - Comprehensive playbook for investigating red team and adversary activities
   - Detects lateral movement (T1021.001, T1021.002, T1078)
   - Detects credential harvesting (T1003.001, T1003.002, T1555.003)
   - Detects data exfiltration (T1041, T1567.002, T1020, T1071.004)
   - Detects privilege escalation (T1548.002, T1543.003, T1053.005, T1134, T1112)
   - Detects process injection (T1055)
   - Detects persistence mechanisms (T1547.001, T1053.005)
   - Detects defense evasion (T1070.001, T1218.005)

3. XQL_Query_Executor.yml - Generic playbook for executing XQL queries
   - Reusable sub-playbook for executing Cortex XDR XQL queries
   - Maps results to MITRE ATT&CK or ATLAS frameworks
   - Configurable time ranges and result limits

# Sub-Playbooks

- Detect_Prompt_Injection.yml - Detects prompt injection attacks
- Detect_Lateral_Movement.yml - Detects lateral movement activities

# Usage

# Importing Playbooks

1. Navigate to XSOAR: Settings → Integrations → Playbooks
2. Click "Upload Playbook"
3. Select the playbook YAML file
4. Configure any required integrations (Cortex XDR)

# Running Playbooks

# Manual Execution

1. Open an incident in XSOAR
2. Click "Actions" → "Run Playbook"
3. Select the appropriate playbook
4. Review and configure inputs if required
5. Execute the playbook

# Automated Execution

Playbooks can be configured to run automatically based on:
- Incident type
- Severity level
- Custom conditions
- Scheduled triggers

# Configuration

# Required Integrations

- Cortex XDR - For executing XQL queries
- Cortex XSOAR - For playbook execution

# Optional Integrations

- MITRE ATT&CK - For framework mapping
- Threat Intelligence - For IOC enrichment
- SIEM - For additional log correlation

# XQL Query Integration

All playbooks integrate with Cortex XDR XQL queries from:
- `Cortex_XDR/XQL/XQL_Incident_Response_SOP.md` - Traditional security threats
- `Cortex_XDR/XQL/XQL_AI_MLOps_Incident_Response_SOP.md` - AI/MLOps threats

# Query Execution

XQL queries are executed using the Cortex XDR integration with the following parameters:

```yaml
scriptarguments:
  query: |
    dataset = xdr_data
    | filter event_type = NETWORK
    | filter action_remote_hostname like "%.openai.com"
    ...
  mitre_technique: "ATLAS-LLM-01"
  tactic: "Initial Access / Execution"
```

# MITRE Framework Mapping

# MITRE ATT&CK

Red team investigation playbooks map to MITRE ATT&CK techniques:
- Lateral Movement: T1021.001, T1021.002, T1078
- Credential Access: T1003.001, T1003.002, T1555.003
- Exfiltration: T1041, T1567.002, T1020, T1071.004
- Privilege Escalation: T1548.002, T1543.003, T1053.005, T1134, T1112
- Defense Evasion: T1055, T1070.001, T1218.005
- Persistence: T1547.001, T1053.005

# MITRE ATLAS

AI/MLOps investigation playbooks map to MITRE ATLAS techniques:
- ATLAS-LLM-01: Prompt Injection
- ATLAS-LLM-02: Tool Poisoning
- ATLAS-LLM-03: Tool Confusion
- ATLAS-LLM-04: Tool Shadowing
- ATLAS-LLM-05: MCP Protocol Manipulation
- ATLAS-ML-01: Training Data Poisoning
- ATLAS-ML-02: Model Poisoning
- ATLAS-ML-03: Adversarial Input
- ATLAS-ML-04: Model Theft
- ATLAS-ML-05: MLOps Infrastructure Attack

# Customization

# Adding New Queries

1. Create a new sub-playbook or modify existing ones
2. Add XQL query execution tasks
3. Configure MITRE framework mapping
4. Test the playbook with sample data

# Modifying Detection Thresholds

Update query filters in playbook tasks:
```yaml
scriptarguments:
  query: |
    ...
    | filter connection_count > 10  # Adjust threshold
    ...
```

# Adding New MITRE Techniques

1. Identify the MITRE technique ID
2. Add mapping in the playbook task
3. Update documentation

# Best Practices

1. Time Ranges: Always specify appropriate time ranges for XQL queries
2. Result Limits: Set reasonable limits to prevent performance issues
3. Error Handling: Implement error handling for failed queries
4. Documentation: Document all custom queries and modifications
5. Testing: Test playbooks in non-production environments first
6. Version Control: Maintain version control for all playbooks

# Troubleshooting

# Common Issues

1. Query Timeout: Reduce time range or add more specific filters
2. No Results: Verify query syntax and time range
3. Integration Errors: Check Cortex XDR integration configuration
4. Playbook Failures: Review task logs for specific errors

# Support

For issues or questions:
- Review XQL SOP documents for query syntax
- Check XSOAR playbook documentation
- Contact Security Operations team

# Version History

- v1.0 (2026-01-10): Initial release with AI/MLOps and Red Team investigation playbooks
