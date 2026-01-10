# Standard Operating Procedure Guide
# Cortex XDR XQL: AI/MLOps Incident Response and Threat Hunting

Document Version: 1.0  
Last Updated: January 9, 2026  
Document Owner: Security Operations  
Review Cycle: Quarterly

---

# Executive Summary

This SOP provides comprehensive guidance for using Cortex XDR's XQL (Extended Query Language) for incident response and threat hunting in AI/MLOps environments. This document covers XQL syntax, query construction, and practical examples for investigating AI-specific adversary activities including tool poisoning, tool confusion, prompt injection, tool shadowing, model manipulation, training data poisoning, and attacks within MCP (Model Context Protocol) ecosystems.

---

# 1. AI/MLOps Security Overview

# 1.1 AI/ML Threat Landscape

AI and Machine Learning systems face unique security challenges:

- Model Attacks: Adversarial inputs, model inversion, membership inference
- Training Pipeline Attacks: Data poisoning, model poisoning, backdoor insertion
- Inference Attacks: Prompt injection, jailbreaking, output manipulation
- Tool Ecosystem Attacks: Tool poisoning, tool confusion, tool shadowing
- MCP Attacks: Protocol manipulation, context injection, unauthorized tool access
- Infrastructure Attacks: Model theft, API abuse, resource exhaustion

# 1.2 MITRE ATLAS Framework

MITRE ATLAS (Adversarial Threat Landscape for Artificial Intelligence Systems) provides a framework for understanding AI/ML attacks:

- Initial Access: Compromising AI/ML infrastructure
- Execution: Running malicious models or code
- Persistence: Maintaining access to AI systems
- Privilege Escalation: Gaining elevated access to ML pipelines
- Defense Evasion: Bypassing AI security controls
- Credential Access: Stealing API keys, model weights, training data
- Discovery: Enumerating AI/ML infrastructure
- Lateral Movement: Moving through ML pipeline components
- Collection: Gathering training data or model artifacts
- Exfiltration: Stealing models, datasets, or intellectual property
- Impact: Disrupting AI services or causing model failures

# 1.3 XQL Data Sources for AI/MLOps

XQL can query AI/ML-specific data sources:

- ML Pipeline Events: Training job executions, model deployments, data processing
- API Gateway Logs: Model inference requests, prompt submissions, tool invocations
- Container Orchestration: Kubernetes pod events, Docker container activities
- Model Registry Events: Model uploads, downloads, version changes
- Data Pipeline Events: ETL operations, feature store access, dataset modifications
- MCP Protocol Events: Tool registration, context updates, function calls
- Cloud ML Services: SageMaker, Vertex AI, Azure ML activity logs

---

# 2. AI/ML Attack Detection Scenarios

# 2.1 Prompt Injection Attacks

Prompt injection involves manipulating AI system inputs to cause unintended behavior.

# Query 1: Suspicious Prompt Patterns

```xql
# MITRE ATLAS: ATLAS-LLM-01 - Prompt Injection
# Tactic: Initial Access / Execution
dataset = xdr_data
| filter event_type = NETWORK
| filter action_remote_hostname like "%.openai.com"
| filter action_remote_hostname like "%.anthropic.com"
| filter action_remote_hostname like "%.googleapis.com"
| filter action_network_protocol = "HTTPS"
| filter action_http_request_body contains "ignore previous"
| filter action_http_request_body contains "system:"
| filter action_http_request_body contains "#"
| fields event_time_ts, action_remote_hostname, action_http_request_body,
        actor_process_image_name, actor_primary_user_sid, action_local_ip
| sort event_time_ts desc
| limit 500
```

# Query 2: Base64 Encoded Prompt Injection

```xql
# MITRE ATLAS: ATLAS-LLM-01 - Prompt Injection (Encoded)
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "python.exe"
| filter action_process_command_line regex "(?i)(base64|b64|encode)"
| filter action_process_command_line regex "(?i)(openai|anthropic|claude|gpt)"
| comp count() by actor_primary_user_sid, action_process_image_name as injection_count
| filter injection_count > 3
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, injection_count
| sort event_time_ts desc
```

# Query 3: Rapid API Calls with Suspicious Patterns

```xql
# MITRE ATLAS: ATLAS-LLM-01 - Prompt Injection (Rate-based)
dataset = xdr_data
| filter event_type = NETWORK
| filter action_remote_hostname like "%.openai.com"
| filter action_remote_port = 443
| comp count() by action_local_ip, actor_primary_user_sid as api_call_count
| filter api_call_count > 100
| comp sum(action_network_bytes_out) by action_local_ip as total_bytes
| filter total_bytes > 10485760  # 10 MB
| fields event_time_ts, action_local_ip, actor_primary_user_sid,
        api_call_count, total_bytes, action_remote_hostname
| sort api_call_count desc
```

# 2.2 Tool Poisoning Attacks

Tool poisoning involves corrupting AI system tools or functions to cause malicious behavior.

# Query 1: Unauthorized Tool Registration

```xql
# MITRE ATLAS: ATLAS-LLM-02 - Tool Poisoning
# Tactic: Persistence / Defense Evasion
dataset = xdr_data
| filter event_type = FILE
| filter action_file_path like "%/tools/%"
| filter action_file_path like "%/functions/%"
| filter action_file_path like "%.py"
| filter action_file_operation = "FILE_WRITE"
| filter action_file_path not like "%/venv/%"
| filter action_file_path not like "%/node_modules/%"
| fields event_time_ts, action_file_path, action_file_operation,
        actor_process_image_name, actor_primary_user_sid, action_file_hash
| sort event_time_ts desc
```

# Query 2: Tool Function Modification

```xql
# MITRE ATLAS: ATLAS-LLM-02 - Tool Poisoning (Function Modification)
dataset = xdr_data
| filter event_type = FILE
| filter action_file_path like "%tool%"
| filter action_file_path like "%.py"
| filter action_file_operation = "FILE_WRITE"
| filter action_file_path like "%def %"
| filter action_file_path like "%exec(%"
| filter action_file_path like "%eval(%"
| filter action_file_path like "%subprocess%"
| fields event_time_ts, action_file_path, action_file_operation,
        actor_process_image_name, actor_primary_user_sid
| sort event_time_ts desc
```

# Query 3: MCP Tool Registry Changes

```xql
# MITRE ATLAS: ATLAS-LLM-02 - Tool Poisoning (MCP Registry)
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "python.exe"
| filter action_process_command_line regex "(?i)(mcp|model.*context.*protocol)"
| filter action_process_command_line regex "(?i)(register.*tool|add.*function)"
| filter action_process_command_line regex "(?i)(tool.*poison|malicious)"
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, action_process_image_path
| sort event_time_ts desc
```

# 2.3 Tool Confusion Attacks

Tool confusion occurs when AI systems incorrectly select or execute tools due to manipulation.

# Query 1: Unusual Tool Execution Patterns

```xql
# MITRE ATLAS: ATLAS-LLM-03 - Tool Confusion
# Tactic: Execution / Defense Evasion
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("python.exe", "node.exe", "bash.exe")
| filter action_process_command_line regex "(?i)(tool.*call|function.*invoke)"
| comp count() by action_process_image_name, actor_primary_user_sid as tool_calls
| filter tool_calls > 50
| comp distinct_count(action_process_command_line) by actor_primary_user_sid as unique_tools
| filter unique_tools > 20
| fields event_time_ts, action_process_image_name, actor_primary_user_sid,
        tool_calls, unique_tools, action_process_command_line
| sort tool_calls desc
```

# Query 2: Rapid Tool Switching

```xql
# MITRE ATLAS: ATLAS-LLM-03 - Tool Confusion (Rapid Switching)
dataset = xdr_data
| filter event_type = NETWORK
| filter action_remote_hostname like "%.openai.com"
| filter action_http_request_body regex "(?i)(tool_choice|function_call)"
| comp count() by action_local_ip, actor_primary_user_sid as tool_switches
| filter tool_switches > 30
| fields event_time_ts, action_local_ip, actor_primary_user_sid,
        tool_switches, action_remote_hostname
| sort tool_switches desc
```

# Query 3: Tool Name Spoofing

```xql
# MITRE ATLAS: ATLAS-LLM-03 - Tool Confusion (Name Spoofing)
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "python.exe"
| filter action_process_command_line regex "(?i)(tool.*name|function.*name)"
| filter action_process_command_line regex "(?i)(spoof|impersonate|mimic)"
| filter action_process_command_line regex "(?i)(os\.|subprocess\.|eval\(|exec\()"
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, action_process_image_path
| sort event_time_ts desc
```

# 2.4 Tool Shadowing Attacks

Tool shadowing involves creating malicious tools with similar names to legitimate ones.

# Query 1: Duplicate Tool Names

```xql
# MITRE ATLAS: ATLAS-LLM-04 - Tool Shadowing
# Tactic: Persistence / Defense Evasion
dataset = xdr_data
| filter event_type = FILE
| filter action_file_path like "%/tools/%"
| filter action_file_path like "%.py"
| comp count() by action_file_path as file_count
| filter file_count > 1
| fields event_time_ts, action_file_path, action_file_operation,
        actor_process_image_name, actor_primary_user_sid, file_count
| sort file_count desc
```

# Query 2: Tool Name Variations

```xql
# MITRE ATLAS: ATLAS-LLM-04 - Tool Shadowing (Name Variations)
dataset = xdr_data
| filter event_type = FILE
| filter action_file_path like "%tool%"
| filter action_file_path like "%.py"
| filter action_file_path regex "(?i)(tool[_-]?[0-9]|tool[_-]?copy|tool[_-]?backup)"
| filter action_file_operation = "FILE_WRITE"
| fields event_time_ts, action_file_path, action_file_operation,
        actor_process_image_name, actor_primary_user_sid
| sort event_time_ts desc
```

# Query 3: Import Path Manipulation

```xql
# MITRE ATLAS: ATLAS-LLM-04 - Tool Shadowing (Import Manipulation)
dataset = xdr_data
| filter event_type = FILE
| filter action_file_path like "%/__init__.py"
| filter action_file_operation = "FILE_WRITE"
| filter action_file_path like "%/tools/%"
| fields event_time_ts, action_file_path, action_file_operation,
        actor_process_image_name, actor_primary_user_sid
| sort event_time_ts desc
```

# 2.5 Model Context Protocol (MCP) Attacks

MCP attacks target the Model Context Protocol ecosystem for AI tool integration.

# Query 1: Unauthorized MCP Server Connections

```xql
# MITRE ATLAS: ATLAS-LLM-05 - MCP Protocol Manipulation
# Tactic: Initial Access / Lateral Movement
dataset = xdr_data
| filter event_type = NETWORK
| filter action_remote_port in (8000, 8080, 3000, 5000)
| filter action_network_protocol = "TCP"
| filter action_http_user_agent regex "(?i)(mcp|model.*context)"
| comp count() by action_remote_ip, action_local_ip as mcp_connections
| filter mcp_connections > 10
| fields event_time_ts, action_remote_ip, action_local_ip, action_remote_port,
        actor_process_image_name, mcp_connections
| sort mcp_connections desc
```

# Query 2: MCP Context Injection

```xql
# MITRE ATLAS: ATLAS-LLM-05 - MCP Context Injection
dataset = xdr_data
| filter event_type = NETWORK
| filter action_http_request_body regex "(?i)(mcp.*context|context.*update)"
| filter action_http_request_body regex "(?i)(<script|javascript:|eval\(|exec\()"
| filter action_http_request_body regex "(?i)(system|shell|command)"
| fields event_time_ts, action_remote_hostname, action_http_request_body,
        actor_process_image_name, actor_primary_user_sid
| sort event_time_ts desc
```

# Query 3: MCP Tool Registration Abuse

```xql
# MITRE ATLAS: ATLAS-LLM-05 - MCP Tool Registration Abuse
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "python.exe"
| filter action_process_command_line regex "(?i)(mcp.*register|register.*tool)"
| filter action_process_command_line regex "(?i)(@tool|@function)"
| comp count() by actor_primary_user_sid as tool_registrations
| filter tool_registrations > 5
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, tool_registrations
| sort tool_registrations desc
```

# 2.6 Training Data Poisoning

Training data poisoning involves injecting malicious data into ML training datasets.

# Query 1: Unauthorized Dataset Modifications

```xql
# MITRE ATLAS: ATLAS-ML-01 - Training Data Poisoning
# Tactic: Initial Access / Impact
dataset = xdr_data
| filter event_type = FILE
| filter action_file_path like "%/data/%"
| filter action_file_path like "%/datasets/%"
| filter action_file_path like "%/training/%"
| filter action_file_operation = "FILE_WRITE"
| filter action_file_path regex "(?i)(\.csv|\.json|\.parquet|\.tfrecord)"
| comp count() by actor_primary_user_sid, action_file_path as dataset_modifications
| filter dataset_modifications > 10
| fields event_time_ts, action_file_path, action_file_operation,
        actor_process_image_name, actor_primary_user_sid, dataset_modifications
| sort dataset_modifications desc
```

# Query 2: Suspicious Data Injection Patterns

```xql
# MITRE ATLAS: ATLAS-ML-01 - Training Data Poisoning (Injection Patterns)
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("python.exe", "jupyter.exe")
| filter action_process_command_line regex "(?i)(pandas|numpy|tensorflow|pytorch)"
| filter action_process_command_line regex "(?i)(append|concat|merge|insert)"
| filter action_process_command_line regex "(?i)(\.csv|\.json|dataset)"
| comp count() by actor_primary_user_sid as data_operations
| filter data_operations > 20
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, data_operations
| sort data_operations desc
```

# Query 3: Model Training Job Anomalies

```xql
# MITRE ATLAS: ATLAS-ML-01 - Training Data Poisoning (Training Anomalies)
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("python.exe", "python3.exe")
| filter action_process_command_line regex "(?i)(train|fit|epoch)"
| filter action_process_command_line regex "(?i)(tensorflow|pytorch|keras|sklearn)"
| comp count() by actor_primary_user_sid, action_process_image_name as training_jobs
| filter training_jobs > 5
| comp sum(action_process_cpu_time) by actor_primary_user_sid as total_cpu
| filter total_cpu > 3600  # 1 hour
| fields event_time_ts, action_process_image_name, actor_primary_user_sid,
        training_jobs, total_cpu, action_process_command_line
| sort training_jobs desc
```

# 2.7 Model Poisoning and Backdoors

Model poisoning involves inserting backdoors or malicious behavior into trained models.

# Query 1: Model File Modifications

```xql
# MITRE ATLAS: ATLAS-ML-02 - Model Poisoning
# Tactic: Persistence / Impact
dataset = xdr_data
| filter event_type = FILE
| filter action_file_path regex "(?i)(\.pkl|\.h5|\.pb|\.onnx|\.pt|\.pth|\.ckpt)"
| filter action_file_operation = "FILE_WRITE"
| filter action_file_path like "%/models/%"
| filter action_file_path like "%/checkpoints/%"
| comp count() by actor_primary_user_sid, action_file_path as model_modifications
| filter model_modifications > 3
| fields event_time_ts, action_file_path, action_file_operation,
        actor_process_image_name, actor_primary_user_sid, action_file_hash
| sort event_time_ts desc
```

# Query 2: Unauthorized Model Uploads

```xql
# MITRE ATLAS: ATLAS-ML-02 - Model Poisoning (Unauthorized Uploads)
dataset = xdr_data
| filter event_type = NETWORK
| filter action_remote_hostname like "%.s3.amazonaws.com"
| filter action_remote_hostname like "%.blob.core.windows.net"
| filter action_remote_hostname like "%.storage.googleapis.com"
| filter action_http_request_method = "PUT"
| filter action_http_request_uri regex "(?i)(model|checkpoint|weights)"
| filter action_network_bytes_out > 10485760  # 10 MB
| fields event_time_ts, action_remote_hostname, action_http_request_uri,
        action_network_bytes_out, actor_process_image_name, actor_primary_user_sid
| sort action_network_bytes_out desc
```

# Query 3: Model Registry Anomalies

```xql
# MITRE ATLAS: ATLAS-ML-02 - Model Poisoning (Registry Anomalies)
dataset = xdr_data
| filter event_type = NETWORK
| filter action_remote_hostname like "%.mlflow.org"
| filter action_remote_hostname like "%.wandb.ai"
| filter action_remote_hostname like "%.neptune.ai"
| filter action_http_request_method = "POST"
| filter action_http_request_uri regex "(?i)(register|upload|create)"
| comp count() by actor_primary_user_sid as registry_operations
| filter registry_operations > 5
| fields event_time_ts, action_remote_hostname, action_http_request_uri,
        actor_primary_user_sid, registry_operations
| sort registry_operations desc
```

# 2.8 Adversarial Input Attacks

Adversarial inputs are crafted to cause model misclassification or failure.

# Query 1: Suspicious Input Patterns

```xql
# MITRE ATLAS: ATLAS-ML-03 - Adversarial Input
# Tactic: Execution / Impact
dataset = xdr_data
| filter event_type = NETWORK
| filter action_remote_hostname like "%.openai.com"
| filter action_http_request_body regex "(?i)(adversarial|perturb|noise|epsilon)"
| filter action_http_request_body regex "(?i)(fgsm|pgd|carlini|deepfool)"
| fields event_time_ts, action_remote_hostname, action_http_request_body,
        actor_process_image_name, actor_primary_user_sid
| sort event_time_ts desc
```

# Query 2: Rapid Inference Requests

```xql
# MITRE ATLAS: ATLAS-ML-03 - Adversarial Input (Rapid Requests)
dataset = xdr_data
| filter event_type = NETWORK
| filter action_remote_hostname like "%.openai.com"
| filter action_remote_port = 443
| comp count() by action_local_ip, actor_primary_user_sid as inference_requests
| filter inference_requests > 100
| comp avg(action_network_bytes_out) by action_local_ip as avg_request_size
| filter avg_request_size > 10240  # 10 KB
| fields event_time_ts, action_local_ip, actor_primary_user_sid,
        inference_requests, avg_request_size
| sort inference_requests desc
```

# Query 3: Input Manipulation Tools

```xql
# MITRE ATLAS: ATLAS-ML-03 - Adversarial Input (Manipulation Tools)
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "python.exe"
| filter action_process_command_line regex "(?i)(adversarial|foolbox|cleverhans|art)"
| filter action_process_command_line regex "(?i)(attack|perturb|adversary)"
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, action_process_image_path
| sort event_time_ts desc
```

# 2.9 Model Theft and Exfiltration

Model theft involves unauthorized copying or exfiltration of trained models.

# Query 1: Large Model File Downloads

```xql
# MITRE ATLAS: ATLAS-ML-04 - Model Theft
# Tactic: Collection / Exfiltration
dataset = xdr_data
| filter event_type = NETWORK
| filter action_network_bytes_in > 52428800  # 50 MB
| filter action_remote_ip not like "10.%"
| filter action_remote_ip not like "192.168.%"
| filter action_remote_ip not like "172.16.%"
| comp sum(action_network_bytes_in) by action_local_ip, actor_primary_user_sid as total_download
| filter total_download > 104857600  # 100 MB
| fields event_time_ts, action_local_ip, action_remote_ip, action_remote_port,
        total_download, actor_process_image_name, actor_primary_user_sid
| sort total_download desc
```

# Query 2: Model File Access Patterns

```xql
# MITRE ATLAS: ATLAS-ML-04 - Model Theft (Access Patterns)
dataset = xdr_data
| filter event_type = FILE
| filter action_file_path regex "(?i)(\.pkl|\.h5|\.pb|\.onnx|\.pt|\.pth)"
| filter action_file_operation = "FILE_READ"
| comp count() by actor_primary_user_sid, action_file_path as model_accesses
| filter model_accesses > 5
| fields event_time_ts, action_file_path, action_file_operation,
        actor_process_image_name, actor_primary_user_sid, model_accesses
| sort model_accesses desc
```

# Query 3: Unauthorized Model Exports

```xql
# MITRE ATLAS: ATLAS-ML-04 - Model Theft (Exports)
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "python.exe"
| filter action_process_command_line regex "(?i)(export|save|dump|serialize)"
| filter action_process_command_line regex "(?i)(\.pkl|\.h5|\.pb|\.onnx|\.pt)"
| filter action_process_command_line regex "(?i)(model|weights|checkpoint)"
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, action_process_image_path
| sort event_time_ts desc
```

# 2.10 MLOps Infrastructure Attacks

Attacks targeting MLOps infrastructure components like Kubernetes, Docker, and cloud ML services.

# Query 1: Kubernetes Pod Anomalies

```xql
# MITRE ATLAS: ATLAS-ML-05 - MLOps Infrastructure Attack
# Tactic: Initial Access / Execution
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "kubectl.exe"
| filter action_process_command_line regex "(?i)(exec|run|create|apply)"
| filter action_process_command_line regex "(?i)(pod|deployment|job)"
| comp count() by actor_primary_user_sid as k8s_operations
| filter k8s_operations > 10
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, k8s_operations
| sort k8s_operations desc
```

# Query 2: Docker Container Manipulation

```xql
# MITRE ATLAS: ATLAS-ML-05 - MLOps Infrastructure Attack (Docker)
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name = "docker.exe"
| filter action_process_command_line regex "(?i)(run|exec|build|push)"
| filter action_process_command_line regex "(?i)(--privileged|--cap-add|--security-opt)"
| fields event_time_ts, action_process_image_name, action_process_command_line,
        actor_primary_user_sid, action_process_image_path
| sort event_time_ts desc
```

# Query 3: ML Service API Abuse

```xql
# MITRE ATLAS: ATLAS-ML-05 - MLOps Infrastructure Attack (API Abuse)
dataset = xdr_data
| filter event_type = NETWORK
| filter action_remote_hostname like "%.sagemaker.%"
| filter action_remote_hostname like "%.vertexai.%"
| filter action_remote_hostname like "%.azureml.%"
| comp count() by action_local_ip, actor_primary_user_sid as api_calls
| filter api_calls > 1000
| comp sum(action_network_bytes_out) by action_local_ip as total_bytes
| filter total_bytes > 104857600  # 100 MB
| fields event_time_ts, action_local_ip, action_remote_hostname,
        api_calls, total_bytes, actor_primary_user_sid
| sort api_calls desc
```

---

# 3. Advanced Detection Techniques

# 3.1 Behavioral Anomaly Detection

# Query 1: Unusual ML Pipeline Activity

```xql
# Detect unusual patterns in ML pipeline execution
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("python.exe", "jupyter.exe", "kubectl.exe")
| comp count() by actor_primary_user_sid, action_process_image_name as activity_count
| comp avg(activity_count) by actor_primary_user_sid as avg_activity
| eval deviation = activity_count - avg_activity
| filter deviation > 20
| fields event_time_ts, actor_primary_user_sid, action_process_image_name,
        activity_count, avg_activity, deviation
| sort deviation desc
```

# Query 2: Time-based Anomaly Detection

```xql
# Detect ML activity outside normal business hours
dataset = xdr_data
| filter event_type = PROCESS
| filter action_process_image_name in ("python.exe", "jupyter.exe")
| filter action_process_command_line regex "(?i)(train|fit|inference|predict)"
| eval hour = hour(event_time_ts)
| filter hour < 6 or hour > 22
| comp count() by actor_primary_user_sid, hour as off_hours_activity
| filter off_hours_activity > 5
| fields event_time_ts, actor_primary_user_sid, hour, off_hours_activity,
        action_process_command_line
| sort off_hours_activity desc
```

# 3.2 Correlation Across AI/ML Events

# Query 1: Multi-Stage AI Attack Chain

```xql
# Correlate prompt injection with tool execution
dataset = xdr_data
| filter event_type = NETWORK
| filter action_remote_hostname like "%.openai.com"
| filter action_http_request_body regex "(?i)(tool|function|execute)"
| join type=left xdr_data on actor_primary_user_sid = actor_primary_user_sid
| filter event_type = PROCESS
| filter action_process_image_name = "python.exe"
| filter action_process_command_line regex "(?i)(exec|eval|subprocess)"
| fields event_time_ts, action_remote_hostname, action_process_image_name,
        action_process_command_line, actor_primary_user_sid
| sort event_time_ts desc
```

# Query 2: Data Poisoning to Model Deployment

```xql
# Correlate dataset modifications with model deployments
dataset = xdr_data
| filter event_type = FILE
| filter action_file_path like "%/data/%"
| filter action_file_operation = "FILE_WRITE"
| join type=left xdr_data on actor_primary_user_sid = actor_primary_user_sid
| filter event_type = NETWORK
| filter action_remote_hostname like "%.mlflow.%"
| filter action_http_request_method = "POST"
| fields event_time_ts, action_file_path, action_remote_hostname,
        actor_primary_user_sid, action_http_request_uri
| sort event_time_ts desc
```

---

# 4. MITRE ATLAS Framework Mapping

# 4.1 ATLAS Techniques Covered

This SOP covers the following MITRE ATLAS techniques:

# Initial Access
- ATLAS-LLM-01: Prompt Injection
- ATLAS-ML-05: MLOps Infrastructure Attack

# Execution
- ATLAS-LLM-03: Tool Confusion
- ATLAS-ML-03: Adversarial Input

# Persistence
- ATLAS-LLM-02: Tool Poisoning
- ATLAS-LLM-04: Tool Shadowing
- ATLAS-ML-02: Model Poisoning

# Defense Evasion
- ATLAS-LLM-02: Tool Poisoning
- ATLAS-LLM-04: Tool Shadowing

# Credential Access
- ATLAS-LLM-01: Prompt Injection (credential extraction)

# Collection
- ATLAS-ML-04: Model Theft

# Exfiltration
- ATLAS-ML-04: Model Theft

# Impact
- ATLAS-ML-01: Training Data Poisoning
- ATLAS-ML-02: Model Poisoning
- ATLAS-ML-03: Adversarial Input

# 4.2 Creating ATLAS-Mapped Queries

When creating queries, include MITRE ATLAS mapping in comments:

```xql
# MITRE ATLAS: ATLAS-LLM-01 - Prompt Injection
# Tactic: Initial Access / Execution
# Description: Adversaries inject malicious prompts to manipulate AI behavior
dataset = xdr_data
| filter event_type = NETWORK
| filter action_remote_hostname like "%.openai.com"
| filter action_http_request_body contains "ignore previous"
| fields event_time_ts, action_remote_hostname, action_http_request_body,
        actor_process_image_name, actor_primary_user_sid
| sort event_time_ts desc
```

---

# 5. Best Practices for AI/MLOps Incident Response

# 5.1 Query Performance Optimization

1. Use Time Ranges: AI/ML workloads generate large volumes of data - always filter by time
2. Filter Early: Apply ML-specific filters before aggregations
3. Limit Results: Use `limit` to prevent excessive data retrieval
4. Index Key Fields: Focus on ML-specific fields (model names, tool names, API endpoints)

# 5.2 AI/ML-Specific Considerations

1. Model Versioning: Track model versions and changes
2. Tool Registry: Maintain baseline of legitimate tools
3. API Rate Limits: Monitor for API abuse patterns
4. Data Lineage: Track data flow through ML pipelines
5. Container Security: Monitor container orchestration activities

# 5.3 Incident Response Workflow

1. Initial Detection: Use broad queries to identify suspicious AI/ML activity
2. Context Gathering: Correlate across ML pipeline components
3. Impact Assessment: Determine affected models, datasets, and tools
4. Containment: Isolate affected ML infrastructure
5. Remediation: Restore clean models, tools, and datasets
6. Documentation: Document attack vectors and MITRE ATLAS mappings

---

# 6. Integration with AI/ML Security Tools

# 6.1 Model Monitoring Integration

XQL queries can integrate with:
- MLflow: Model registry and tracking
- Weights & Biases: Experiment tracking
- Neptune: ML metadata management
- Evidently AI: Model monitoring

# 6.2 MCP Ecosystem Monitoring

Monitor MCP protocol events:
- Tool registration and deregistration
- Context updates and modifications
- Function call patterns
- Protocol-level anomalies

# 6.3 Cloud ML Service Integration

Query cloud ML service logs:
- AWS SageMaker activity
- Google Vertex AI operations
- Azure Machine Learning events
- Databricks ML workflows

---

# 7. Troubleshooting AI/ML Detection

# 7.1 False Positives

Problem: Legitimate ML operations triggering alerts  
Solutions:
- Whitelist known ML pipelines and tools
- Adjust thresholds based on baseline activity
- Use ML-specific context to reduce noise

# 7.2 Missing Detection

Problem: AI attacks not being detected  
Solutions:
- Expand query patterns to cover new attack vectors
- Monitor MCP protocol events
- Track model and tool registry changes
- Correlate across ML pipeline stages

# 7.3 Performance Issues

Problem: Queries taking too long on ML data  
Solutions:
- Use time-based partitioning
- Filter by specific ML services or tools
- Aggregate at appropriate granularity
- Consider sampling for large datasets

---

# 8. Document Control

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
- AI/ML Engineering Team
- MLOps Team
- Data Science Team
- Security Engineering Team

---

This SOP should be treated as a living document and updated as new AI/ML attack techniques emerge, MCP protocols evolve, or organizational AI/ML infrastructure changes. All users are responsible for adhering to these procedures and suggesting improvements through the formal change management process.
