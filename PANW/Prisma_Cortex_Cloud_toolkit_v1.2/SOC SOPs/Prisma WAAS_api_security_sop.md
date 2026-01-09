# Standard Operating Procedure
# Prisma Cloud WAAS Module & API Security
# CSA CCM & OWASP API Top 10 Alignment

Document Version: 2.0  
Last Updated: January 8, 2026  
Document Owner: Cloud Security Operations  
Classification: Internal Use  
Review Cycle: Quarterly  
Next Review Date: April 8, 2026

---

# Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [WAAS Module Overview](#2-waas-module-overview)
3. [API Security Framework](#3-api-security-framework)
4. [OWASP API Top 10 Mapping](#4-owasp-api-top-10-mapping)
5. [CSA CCM Alignment](#5-csa-ccm-alignment)
6. [Implementation Procedures](#6-implementation-procedures)
7. [Policy Configuration](#7-policy-configuration)
8. [Monitoring and Detection](#8-monitoring-and-detection)
9. [Incident Response](#9-incident-response)
10. [Compliance and Reporting](#10-compliance-and-reporting)
11. [Appendices](#11-appendices)

---

# 1. Executive Summary

# 1.1 Purpose

This SOP establishes comprehensive procedures for implementing and managing Prisma Cloud's Web Application and API Security (WAAS) module, with specific focus on API security controls aligned to industry frameworks including OWASP API Security Top 10 and Cloud Security Alliance Cloud Controls Matrix (CSA CCM).

# 1.2 Scope

This document covers:
- WAAS module deployment and configuration for web applications and APIs
- API security controls and threat detection
- Protection mechanisms for containerized, serverless, and host-based applications
- Compliance mapping to OWASP API Top 10 2023 and CSA CCM v4.0
- Operational procedures for monitoring, alerting, and incident response
- Integration with CI/CD pipelines and DevSecOps workflows

# 1.3 Intended Audience

- Cloud Security Engineers
- Application Security Teams
- DevOps/DevSecOps Engineers
- Security Operations Center (SOC) Analysts
- Compliance and Risk Management Teams
- API Product Owners

# 1.4 Definitions and Acronyms

| Term | Definition |
|------|------------|
| WAAS | Web Application and API Security |
| API | Application Programming Interface |
| OWASP | Open Web Application Security Project |
| CSA CCM | Cloud Security Alliance Cloud Controls Matrix |
| BOLA | Broken Object Level Authorization |
| BFLA | Broken Function Level Authorization |
| WAF | Web Application Firewall |
| RASP | Runtime Application Self-Protection |
| CNS | Cloud Native Security |
| DoS | Denial of Service |
| SQLi | SQL Injection |
| XSS | Cross-Site Scripting |
| JWT | JSON Web Token |
| IDOR | Insecure Direct Object Reference |
| SSRF | Server-Side Request Forgery |
| TLS | Transport Layer Security |

---

# 2. WAAS Module Overview

# 2.1 Architecture and Components

Prisma Cloud WAAS provides Layer 7 protection through multiple deployment models:

Deployment Models:

1. Container Defender (In-Line Proxy)
   - Deployed as sidecar or host defender
   - Intercepts traffic before reaching application
   - Suitable for: Kubernetes, Docker, ECS, AKS, GKE
   - Latency impact: 1-3ms typical

2. App-Embedded Defender
   - Integrated within application runtime
   - RASP (Runtime Application Self-Protection) capabilities
   - Suitable for: Java, .NET, Node.js applications
   - Provides context-aware protection

3. Host Defender
   - Protects applications on virtual machines
   - Reverse proxy mode or out-of-band observation
   - Suitable for: EC2, Azure VMs, GCP Compute Engine

4. Serverless Defender
   - Layer protection for FaaS
   - Suitable for: Lambda, Azure Functions, Google Cloud Functions
   - Automatic instrumentation

Protection Layers:

```
┌─────────────────────────────────────────────┐
│         Traffic Flow & Protection           │
├─────────────────────────────────────────────┤
│  Internet/Client                            │
│          ↓                                  │
│  ┌────────────────────────┐                │
│  │   WAAS Defender        │                │
│  │  ┌──────────────────┐  │                │
│  │  │ DDoS Protection  │  │ ← Layer 1      │
│  │  └──────────────────┘  │                │
│  │  ┌──────────────────┐  │                │
│  │  │ Access Control   │  │ ← Layer 2      │
│  │  └──────────────────┘  │                │
│  │  ┌──────────────────┐  │                │
│  │  │ Bot Protection   │  │ ← Layer 3      │
│  │  └──────────────────┘  │                │
│  │  ┌──────────────────┐  │                │
│  │  │ API Protection   │  │ ← Layer 4      │
│  │  └──────────────────┘  │                │
│  │  ┌──────────────────┐  │                │
│  │  │ OWASP Top 10     │  │ ← Layer 5      │
│  │  │ Protection       │  │                │
│  │  └──────────────────┘  │                │
│  │  ┌──────────────────┐  │                │
│  │  │ Custom Rules     │  │ ← Layer 6      │
│  │  └──────────────────┘  │                │
│  └────────────────────────┘                │
│          ↓                                  │
│  Protected Application/API                  │
└─────────────────────────────────────────────┘
```

# 2.2 WAAS Feature Matrix

| Feature | Container | Host | Serverless | App-Embedded |
|---------|-----------|------|------------|--------------|
| SQL Injection Protection | ✓ | ✓ | ✓ | ✓ |
| XSS Protection | ✓ | ✓ | ✓ | ✓ |
| API Discovery | ✓ | ✓ | ✓ | ✓ |
| API Protection (Schema Validation) | ✓ | ✓ | ✓ | ✓ |
| Bot Protection | ✓ | ✓ | ✗ | ✓ |
| DoS Protection | ✓ | ✓ | ✗ | ✓ |
| Custom Rules | ✓ | ✓ | ✓ | ✓ |
| Virtual Patching | ✓ | ✓ | ✓ | ✓ |
| Body Inspection | ✓ | ✓ | Limited | ✓ |
| Advanced Threat Protection | ✓ | ✓ | ✓ | ✓ |
| TLS Inspection | ✓ | ✓ | ✗ | N/A |
| Intelligence-based Detection | ✓ | ✓ | ✓ | ✓ |

# 2.3 Traffic Flow and Inspection

Inspection Process:

1. Connection Establishment
   - TLS termination (if configured)
   - Source IP validation
   - Rate limiting checks
   - Geographic restriction enforcement

2. Request Analysis
   - HTTP method validation
   - Header inspection
   - Content-type verification
   - Body size validation
   - API endpoint matching

3. Threat Detection
   - Pattern matching (signatures)
   - Anomaly detection (behavioral)
   - Machine learning models
   - Custom rule evaluation

4. Response Action
   - Allow (pass through)
   - Alert (log and pass)
   - Prevent (block with custom response)
   - Ban (temporary or permanent IP block)

---

# 3. API Security Framework

# 3.1 API Discovery and Classification

Automated Discovery:

WAAS automatically discovers APIs through traffic observation and analysis:

Discovery Methods:
1. Passive Observation (Default)
   - Analyzes incoming API traffic
   - Identifies endpoints, parameters, data types
   - No impact on application performance
   - Discovery time: 24-48 hours for typical traffic patterns

2. OpenAPI/Swagger Import
   - Import existing API specifications
   - Supports OpenAPI 2.0, 3.0, 3.1
   - Immediate protection based on specification
   - Detects spec drift automatically

3. gRPC and GraphQL Discovery
   - Protocol buffer introspection
   - GraphQL schema analysis
   - Query depth and complexity detection

API Classification:

APIs are automatically classified by:
- Sensitivity Level: Public, Internal, Private, Confidential
- Data Types: PII, PHI, PCI, Financial, Authentication
- Risk Score: 1-10 based on exposure and data sensitivity
- Authentication Method: OAuth, API Key, JWT, Basic Auth, None

API Inventory Structure:

```json
{
  "endpoint": "/api/v2/users/{userId}/profile",
  "methods": ["GET", "PUT", "PATCH"],
  "parameters": {
    "path": ["userId"],
    "query": ["include", "fields"],
    "headers": ["Authorization", "X-API-Version"]
  },
  "dataTypes": ["PII", "Authentication"],
  "sensitivity": "Confidential",
  "riskScore": 8,
  "authentication": "JWT",
  "discoveredDate": "2026-01-05T10:30:00Z",
  "lastSeen": "2026-01-08T14:22:00Z",
  "requestVolume": 15420,
  "uniqueClients": 342
}
```

# 3.2 API Protection Mechanisms

Schema Enforcement:

WAAS validates API requests against defined or discovered schemas:

Validation Types:
1. Structure Validation
   - Request/response format
   - Required fields presence
   - Data type validation
   - Nested object validation

2. Value Validation
   - Enumeration checking
   - Range validation (min/max)
   - Pattern matching (regex)
   - Length constraints

3. Business Logic Validation
   - State machine enforcement
   - Sequential operation validation
   - Resource ownership verification

Example Schema Enforcement Configuration:

```yaml
apiVersion: waas.prismacloud.io/v1
kind: APIProtectionRule
metadata:
  name: user-api-protection
spec:
  endpoint: /api/v2/users/*
  methods: [GET, POST, PUT, DELETE]
  schemaValidation:
    enabled: true
    mode: strict # Options: strict, permissive, learning
    source: openapi # Options: openapi, discovered, custom
    failureAction: block # Options: block, alert, disable
  parameterValidation:
    - name: userId
      type: string
      pattern: "^[a-zA-Z0-9]{8,32}$"
      required: true
      location: path
    - name: email
      type: string
      format: email
      maxLength: 255
      location: body
  responseValidation:
    enabled: true
    preventDataLeakage: true
    maskSensitiveData:
      - creditCard
      - ssn
      - password
```

Rate Limiting and Throttling:

Granular rate limiting prevents abuse and DoS attacks:

Rate Limit Dimensions:
1. Per Client IP: 100 requests/minute default
2. Per API Key: 1000 requests/minute default
3. Per User ID: 500 requests/minute default
4. Per Endpoint: 5000 requests/minute default
5. Global: 50000 requests/minute default

Adaptive Rate Limiting:
- Automatically adjusts based on traffic patterns
- Implements token bucket algorithm
- Supports burst allowances
- Differentiates between authenticated and anonymous users

Configuration Example:

```yaml
rateLimiting:
  enabled: true
  dimensions:
    - type: clientIp
      limit: 100
      period: 1m
      burst: 150
      action: ban
      banDuration: 5m
    - type: apiKey
      limit: 1000
      period: 1m
      action: throttle
    - type: endpoint
      patterns:
        - path: /api/v2/search
          limit: 50
          period: 1m
        - path: /api/v2/export
          limit: 10
          period: 1h
```

# 3.3 Authentication and Authorization Controls

Authentication Validation:

WAAS validates and enforces authentication mechanisms:

Supported Methods:
1. JWT Validation
   - Signature verification
   - Expiration checking
   - Issuer validation
   - Claim validation
   - Algorithm whitelist enforcement

2. OAuth 2.0 / OIDC
   - Token introspection
   - Scope validation
   - Grant type verification

3. API Key Management
   - Key format validation
   - Key rotation enforcement
   - Usage tracking
   - Automatic revocation on suspicious activity

4. mTLS (Mutual TLS)
   - Certificate validation
   - CN/SAN verification
   - Revocation checking (OCSP/CRL)

JWT Validation Configuration:

```yaml
authentication:
  jwt:
    enabled: true
    algorithms: [RS256, ES256] # Whitelist
    issuer: "https://auth.company.com"
    audience: "api.company.com"
    publicKeySource: jwks # Options: jwks, static, vault
    jwksUrl: "https://auth.company.com/.well-known/jwks.json"
    clockSkew: 60s
    requiredClaims:
      - sub
      - exp
      - iat
    customValidation:
      - claim: role
        allowedValues: [admin, user, api_consumer]
      - claim: tenant_id
        required: true
```

Authorization Enforcement (BOLA/IDOR Prevention):

```yaml
authorization:
  objectLevelAccess:
    enabled: true
    rules:
      - endpoint: /api/v2/users/{userId}/*
        methods: [GET, PUT, DELETE]
        requireOwnership: true
        ownershipClaim: sub # JWT claim containing user ID
        parameterToMatch: userId # Path parameter
        action: block
      - endpoint: /api/v2/documents/{documentId}
        methods: [GET, PUT, DELETE]
        requirePermission: true
        permissionClaim: permissions
        requiredPermission: "documents:read"
```

---

# 4. OWASP API Top 10 Mapping

# 4.1 OWASP API Security Top 10 (2023)

Prisma Cloud WAAS provides comprehensive coverage of OWASP API Top 10 vulnerabilities:

# API1:2023 - Broken Object Level Authorization (BOLA)

Vulnerability Description:
APIs expose endpoints that handle object identifiers, creating a wide attack surface for access control issues. Attackers can exploit these endpoints by manipulating object IDs to access unauthorized data.

WAAS Protection Mechanisms:

1. Automatic BOLA Detection
   - Monitors object access patterns
   - Detects anomalous access to resources
   - Identifies horizontal privilege escalation attempts
   - Machine learning models establish baseline behavior

2. Policy Configuration:

```yaml
bolaProtection:
  enabled: true
  mode: prevent # Options: detect, prevent, disable
  sensitivity: high # Options: low, medium, high
  rules:
    - name: user-profile-protection
      endpoints:
        - /api/v2/users/{userId}/profile
        - /api/v2/users/{userId}/settings
      identifierParam: userId
      authenticationRequired: true
      validateOwnership:
        enabled: true
        jwtClaim: sub
        matchParameter: userId
      crossTenantAccess: deny
      anomalyDetection:
        enabled: true
        threshold: 3 # Alert after 3 unauthorized attempts
        timeWindow: 5m
        action: banIP
        banDuration: 30m
```

3. Detection Indicators:
   - Excessive enumeration attempts (scanning object IDs)
   - Access to resources outside user's scope
   - Pattern of sequential ID access
   - High volume of 403/401 responses from single client
   - Access attempts to predictable IDs

4. Response Actions:
   - Alert: Log event for investigation
   - Block Request: Return 403 Forbidden
   - Ban IP: Temporary or permanent ban
   - Custom Response: Return fake data or redirect

CSA CCM Mapping: IAM-02, IAM-05, IAM-11  
Implementation Priority: Critical  
Default Action: Alert (tuning required)

---

# API2:2023 - Broken Authentication

Vulnerability Description:
Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or exploit implementation flaws to assume other users' identities.

WAAS Protection Mechanisms:

1. Authentication Enforcement:

```yaml
authentication:
  enforcement:
    enabled: true
    mode: strict
    endpoints:
      - pattern: /api/*
        exclude: [/api/health, /api/public/*]
        requireAuthentication: true
        methods: [GET, POST, PUT, PATCH, DELETE]
    
  validation:
    jwt:
      enabled: true
      strictValidation: true
      algorithms: [RS256, ES256, ES512]
      rejectWeakAlgorithms: true # Block HS256, none
      validateIssuer: true
      validateAudience: true
      validateExpiration: true
      clockSkewTolerance: 30s
      rejectExpiredTokens: true
      
  credentialStuffing:
    enabled: true
    threshold: 5 # Failed attempts
    timeWindow: 5m
    action: banIP
    banDuration: 1h
    captchaChallenge: true
    
  bruteForce:
    enabled: true
    threshold: 10
    timeWindow: 10m
    progressiveDelay: true # Increase response time
    
  sessionManagement:
    validateSessionToken: true
    enforceTokenRotation: true
    maxSessionDuration: 24h
    idleTimeout: 2h
```

2. Weak Authentication Detection:
   - Basic authentication over non-TLS
   - Weak password patterns (if handling auth)
   - Missing authentication headers
   - Suspicious authentication patterns
   - Token replay attempts

3. Multi-Factor Authentication Validation:

```yaml
mfaValidation:
  enabled: true
  endpoints:
    - /api/v2/admin/*
    - /api/v2/payments/*
  requireMfaClaim: true
  mfaClaimName: amr # Authentication Methods References
  acceptedMethods:
    - otp
    - sms
    - totp
    - webauthn
  enforceStep-Up:
    sensitiveOperations:
      - pattern: /api/v2/users/{id}/delete
        requireFreshAuth: true
        maxAuthAge: 5m
```

CSA CCM Mapping: IAM-01, IAM-06, IAM-08  
Implementation Priority: Critical  
Default Action: Block

---

# API3:2023 - Broken Object Property Level Authorization

Vulnerability Description:
APIs tend to expose all object properties without considering their individual sensitivity, leading to information disclosure or mass assignment vulnerabilities.

WAAS Protection Mechanisms:

1. Response Filtering:

```yaml
propertyLevelAuthorization:
  enabled: true
  mode: enforce
  
  responseSanitization:
    enabled: true
    rules:
      - endpoint: /api/v2/users/{userId}
        sensitiveFields:
          - ssn
          - salary
          - internalNotes
          - passwordHash
        action: redact # Options: redact, remove, hash
        conditionalExposure:
          - field: salary
            requireRole: [manager, hr]
            roleClaimName: role
          - field: ssn
            requirePermission: "users:pii:read"
            
  massAssignment:
    enabled: true
    mode: strict
    rules:
      - endpoint: /api/v2/users/{userId}
        method: [PUT, PATCH]
        readOnlyFields:
          - id
          - createdAt
          - role
          - isVerified
          - accountBalance
        action: block
        stripUnknownFields: true
        
      - endpoint: /api/v2/products/{productId}
        method: POST
        allowedFields:
          - name
          - description
          - price
          - category
        denyUnlisted: true
```

2. Schema-Based Property Control:

```yaml
schemaEnforcement:
  responseValidation:
    enabled: true
    enforceDefinedPropertiesOnly: true
    preventPropertyLeakage: true
    
  propertyVisibility:
    - resource: User
      properties:
        public: [id, username, displayName, avatar]
        authenticated: [email, createdAt, preferences]
        owner: [phoneNumber, address, paymentMethods]
        admin: [ssn, salary, internalNotes, ipAddress]
```

CSA CCM Mapping: IAM-11, DSI-02, DSI-05  
Implementation Priority: High  
Default Action: Alert

---

# API4:2023 - Unrestricted Resource Consumption

Vulnerability Description:
APIs often don't impose restrictions on the size or number of resources that can be requested, leading to denial of service or excessive resource consumption.

WAAS Protection Mechanisms:

1. Resource Limits Configuration:

```yaml
resourceConsumption:
  enabled: true
  
  requestLimits:
    maxPayloadSize: 10MB
    maxHeaderSize: 8KB
    maxQueryParameters: 50
    maxPathLength: 2048
    maxUrlLength: 4096
    
  timeoutControls:
    requestTimeout: 30s
    slowRequestThreshold: 10s
    slowRequestAction: alert
    
  rateLimiting:
    global:
      limit: 10000
      period: 1m
      
    perClient:
      limit: 100
      period: 1m
      burst: 150
      
    perEndpoint:
      - path: /api/v2/search
        limit: 20
        period: 1m
        costFactor: 5 # Higher cost for expensive operations
        
      - path: /api/v2/export
        limit: 5
        period: 1h
        
      - path: /api/v2/reports/generate
        limit: 3
        period: 1h
        requiresToken: true # Token bucket
        
  paginationEnforcement:
    enabled: true
    maxPageSize: 100
    defaultPageSize: 20
    requirePagination:
      - /api/v2/users
      - /api/v2/products
      - /api/v2/orders
      
  batchOperationLimits:
    maxBatchSize: 50
    endpoints:
      - /api/v2/bulk-create
      - /api/v2/bulk-update
      - /api/v2/bulk-delete
      
  dosProtection:
    enabled: true
    slowlorisProtection: true
    connectionLimits:
      perIP: 50
      perAPIKey: 200
    requestQueueSize: 1000
    queueTimeoutAction: reject503
```

2. Cost-Based Rate Limiting:

```yaml
costBasedLimiting:
  enabled: true
  pointsPerMinute: 1000
  endpointCosts:
    - path: /api/v2/simple-query
      cost: 1
    - path: /api/v2/complex-query
      cost: 10
    - path: /api/v2/ml-inference
      cost: 50
    - path: /api/v2/full-export
      cost: 100
  overageBehavior: throttle # Options: reject, throttle, charge
```

CSA CCM Mapping: IVS-06, IVS-08, BCR-01  
Implementation Priority: High  
Default Action: Prevent (for DoS), Alert (for limits)

---

# API5:2023 - Broken Function Level Authorization (BFLA)

Vulnerability Description:
Complex access control policies with different hierarchies, groups, and roles tend to lead to authorization flaws, allowing attackers to access administrative functions.

WAAS Protection Mechanisms:

1. Function-Level Authorization:

```yaml
functionLevelAuthorization:
  enabled: true
  mode: enforce
  
  roleBasedAccess:
    enabled: true
    rules:
      # Administrative endpoints
      - endpoints:
          - /api/v2/admin/*
          - /api/v2/system/*
          - /api/v2/users/*/promote
        methods: [GET, POST, PUT, DELETE]
        requireRoles: [admin, system_admin]
        roleClaim: role
        action: block
        
      # Manager functions
      - endpoints:
          - /api/v2/reports/financial
          - /api/v2/users/*/salary
        requireRoles: [manager, director, admin]
        
      # Standard user restrictions
      - endpoints:
          - /api/v2/internal/*
        denyRoles: [guest, anonymous]
        
  permissionBasedAccess:
    enabled: true
    permissionsClaim: permissions # Array in JWT
    rules:
      - endpoint: /api/v2/documents/{id}/delete
        method: DELETE
        requireAllPermissions:
          - documents:delete
          - documents:own_or_admin
          
      - endpoint: /api/v2/users/*/deactivate
        method: POST
        requireAnyPermission:
          - users:deactivate
          - admin:all
          
  privilegeEscalation:
    detection: true
    rules:
      - name: role-modification-attempt
        endpoints:
          - /api/v2/users/{userId}
        method: [PUT, PATCH]
        monitorFields: [role, permissions, isAdmin]
        validateModifier:
          requireHigherPrivilege: true
          allowSelfModification: false
        action: blockAndAlert
        
  httpMethodRestrictions:
    enabled: true
    rules:
      - endpoints: [/api/v2/public/*]
        allowedMethods: [GET, OPTIONS]
        
      - endpoints: [/api/v2/users/*]
        restrictMethods:
          DELETE: [admin]
          PUT: [owner, admin]
          POST: [authenticated]
```

2. Anomaly Detection for Privilege Escalation:

```yaml
privilegeEscalationDetection:
  enabled: true
  indicators:
    - name: sudden-admin-access
      description: User accessing admin endpoints without prior history
      threshold: 3
      timeWindow: 1h
      action: blockAndAlert
      
    - name: role-enumeration
      description: Multiple attempts to access different privileged endpoints
      threshold: 5
      timeWindow: 5m
      action: ban
      
    - name: horizontal-privilege-testing
      description: Accessing resources across different tenants/accounts
      threshold: 10
      timeWindow: 10m
```

CSA CCM Mapping: IAM-02, IAM-03, IAM-11  
Implementation Priority: Critical  
Default Action: Block

---

# API6:2023 - Unrestricted Access to Sensitive Business Flows

Vulnerability Description:
APIs vulnerable to this risk expose business flows without compensating for how automation could harm the business, such as automated ticket purchasing or high-volume operations.

WAAS Protection Mechanisms:

1. Business Logic Protection:

```yaml
businessFlowProtection:
  enabled: true
  
  criticalFlows:
    - name: payment-processing
      endpoints:
        - /api/v2/payments/process
        - /api/v2/checkout/complete
      protection:
        rateLimiting:
        enabled: true
        perClient: 100/m
        perAPIKey: 1000/m
        perEndpoint: 5000/m
        action: ban
        banDuration: 30m
        
      botProtection:
        enabled: true
        mode: block
        knownBots: challenge
        unknownBots: block
        
      dos:
        enabled: true
        burstSize: 500
        averageRate: 100
        
      advancedProtection:
        intelligenceSources: true
        behavioralModeling: true
        anomalyDetection: true
        
  monitoring:
    realTimeAlerts: true
    detailedLogging: true
    auditTrail: comprehensive
    
  alerting:
    channels:
      - type: pagerduty
        serviceKey: ${PAGERDUTY_KEY}
        severity: [critical, high]
      - type: slack
        webhook: ${SLACK_WEBHOOK}
        severity: [critical, high, medium]
      - type: siem
        endpoint: ${SIEM_ENDPOINT}
        protocol: syslog
        
  compliance:
    frameworks:
      - pci_dss
      - hipaa
      - gdpr
      - owasp_api_top10
      - csa_ccm
    autoRemediate: true
    auditTrail: enabled
```

3. Automated Response Configuration:

```yaml
# automated-response.yaml
automatedResponse:
  enabled: true
  
  actions:
    - trigger:
        event: sqli_detected
        severity: [critical, high]
        threshold: 1
      response:
        - banIP:
            duration: 24h
            scope: global
        - createTicket:
            system: jira
            project: SEC
            assignee: security-team
        - notify:
            channel: pagerduty
            
    - trigger:
        event: bola_attempt
        threshold: 3
        timeWindow: 5m
      response:
        - suspendAPIKey:
            duration: 1h
        - alertOwner:
            method: email
        - logForensics:
            detail: full
            
    - trigger:
        event: rate_limit_exceeded
        severity: high
      response:
        - throttle:
            duration: 10m
            rate: 10/m
        - captchaChallenge: true
        
    - trigger:
        event: api_schema_violation
        count: 10
        timeWindow: 1m
      response:
        - block:
            duration: temporary
        - notify:
            channel: slack
            team: api-team
```

4. Operational Procedures:

Daily Operations:
```bash
#!/bin/bash
# daily-waas-check.sh

# Check defender health
echo "=== Defender Health Check ==="
kubectl get pods -n twistlock -o wide

# Review critical alerts
echo "=== Critical Alerts (Last 24h) ==="
prisma-cloud-cli waas alerts \
  --severity critical \
  --from -24h \
  --format table

# Check false positive rate
echo "=== False Positive Rate ==="
prisma-cloud-cli waas metrics \
  --metric false-positive-rate \
  --period 24h

# Verify policy compliance
echo "=== Policy Compliance ==="
prisma-cloud-cli waas compliance-check \
  --frameworks owasp-api-top10,csa-ccm

# Generate daily report
prisma-cloud-cli waas report \
  --type daily-summary \
  --output /reports/waas-daily-$(date +%Y%m%d).pdf
```

Deliverables:
- [ ] Production policies deployed
- [ ] All applications protected
- [ ] Automated response configured
- [ ] Operational runbooks
- [ ] Monitoring dashboards
- [ ] Escalation procedures

---

# 7. Policy Configuration

# 7.1 Policy Structure and Hierarchy

WAAS policies follow a hierarchical structure with inheritance:

```
Global Settings
  ├── Network Settings
  ├── TLS Configuration
  └── Intelligence Updates
      
Collections (Application Groups)
  ├── Production Apps
  ├── Development Apps
  └── Partner APIs
      
Rules (Ordered by Priority)
  ├── Rule 1: Critical Apps (Priority 1)
  ├── Rule 2: Public APIs (Priority 2)
  ├── Rule 3: Internal APIs (Priority 3)
  └── Rule 4: Catch-All (Priority 999)
      
Individual Rule Components
  ├── App Definition
  ├── Protection Settings
  ├── Access Control
  ├── Bot Management
  ├── Custom Rules
  └── Advanced Settings
```

# 7.2 Best Practices for Policy Configuration

1. Use Collections for Organization:

```yaml
collections:
  - name: production-customer-facing
    description: All customer-facing production APIs
    filters:
      - type: label
        key: environment
        value: production
      - type: label
        key: exposure
        value: public
    inherits: production-baseline
    
  - name: production-internal
    description: Internal production services
    filters:
      - type: label
        key: environment
        value: production
      - type: label
        key: exposure
        value: internal
    inherits: production-baseline
    
  - name: development
    description: All development environments
    filters:
      - type: label
        key: environment
        value: development
    inherits: development-baseline
```

2. Implement Defense in Depth:

```yaml
# Layer 1: Network Access Control
networkACL:
  allowedIPs:
    - 203.0.113.0/24 # Corporate VPN
    - 198.51.100.0/24 # Partner network
  deniedIPs:
    - 192.0.2.0/24 # Known malicious
  geoBlocking:
    mode: deny
    blockedCountries: [KP, IR, SY]
    
# Layer 2: Rate Limiting
rateLimiting:
  global: 10000/m
  perIP: 100/m
  perAPIKey: 1000/m
  
# Layer 3: Bot Protection
botProtection:
  mode: challenge
  javascriptChallenge: true
  
# Layer 4: Authentication
authentication:
  required: true
  methods: [jwt, oauth2]
  
# Layer 5: Authorization
authorization:
  enforceRBAC: true
  enforceABAC: true
  
# Layer 6: Input Validation
inputValidation:
  schemaEnforcement: strict
  parameterValidation: true
  
# Layer 7: Attack Protection
attackProtection:
  owaspTop10: prevent
  customRules: prevent
```

3. Policy Testing Procedure:

```bash
#!/bin/bash
# test-waas-policy.sh

# 1. Deploy to test collection
echo "Deploying policy to test collection..."
prisma-cloud-cli waas policy apply \
  --file new-policy.yaml \
  --collection test-collection \
  --dry-run

# 2. Run attack simulations
echo "Running OWASP ZAP scan..."
docker run -v $(pwd):/zap/wrk/:rw \
  -t owasp/zap2docker-stable zap-baseline.py \
  -t https://test-api.company.com \
  -r zap-report.html

# 3. Validate protection
echo "Validating protection effectiveness..."
prisma-cloud-cli waas test-policy \
  --policy new-policy.yaml \
  --attack-suite owasp-api-top10

# 4. Check false positives
echo "Checking false positive rate..."
prisma-cloud-cli waas validate \
  --policy new-policy.yaml \
  --traffic-sample legitimate-traffic.pcap \
  --threshold 5%

# 5. Performance test
echo "Running performance test..."
ab -n 10000 -c 100 \
  -H "Authorization: Bearer $TOKEN" \
  https://test-api.company.com/api/v2/test

# 6. Generate test report
prisma-cloud-cli waas test-report \
  --output policy-test-report.pdf
```

4. Policy Version Control:

```bash
# Store policies in Git
git init waas-policies
cd waas-policies

# Directory structure
mkdir -p {production,staging,development}/{api,web,serverless}

# Commit policy changes
git add production/api/customer-api-policy.yaml
git commit -m "Update rate limiting for customer API"
git tag -a v1.2.3 -m "Release v1.2.3 - Enhanced BOLA protection"
git push origin main --tags

# Automated deployment via CI/CD
# .github/workflows/deploy-waas-policy.yml
name: Deploy WAAS Policy
on:
  push:
    branches: [main]
    paths:
      - 'production//*.yaml'
      
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Validate Policy
        run: |
          prisma-cloud-cli waas policy validate \
            --file ${{ github.event.head_commit.modified }}
      - name: Deploy to Production
        run: |
          prisma-cloud-cli waas policy apply \
            --file ${{ github.event.head_commit.modified }} \
            --environment production
      - name: Monitor Deployment
        run: |
          prisma-cloud-cli waas monitor-deployment \
            --timeout 300s \
            --rollback-on-error
```

---

# 8. Monitoring and Detection

# 8.1 Real-Time Monitoring Dashboard

Key Metrics to Monitor:

```yaml
dashboards:
  - name: WAAS Security Overview
    widgets:
      - type: timeseries
        title: Attack Volume
        metrics:
          - waas.attacks.total
          - waas.attacks.blocked
          - waas.attacks.alerted
        aggregation: sum
        interval: 1m
        
      - type: pie
        title: Attack Types
        metric: waas.attacks.by_type
        topK: 10
        
      - type: gauge
        title: Protection Health
        metrics:
          - waas.defenders.online
          - waas.defenders.total
        thresholds:
          critical: 0.95
          warning: 0.98
          
      - type: table
        title: Top Attackers
        query: |
          SELECT sourceIP, COUNT(*) as attacks
          FROM waas_events
          WHERE timestamp > NOW() - INTERVAL '1 hour'
          AND effect = 'prevent'
          GROUP BY sourceIP
          ORDER BY attacks DESC
          LIMIT 10
          
      - type: heatmap
        title: Geographic Attack Distribution
        metric: waas.attacks.by_country
        
      - type: line
        title: API Error Rates
        metrics:
          - waas.api.4xx_errors
          - waas.api.5xx_errors
          - waas.api.latency_p95
        
  - name: OWASP API Top 10
    widgets:
      - type: scorecard
        title: OWASP Coverage
        metrics:
          - api1_bola_protected: 100%
          - api2_auth_protected: 100%
          - api3_property_protected: 100%
          - api4_resource_protected: 100%
          - api5_bfla_protected: 100%
          - api6_business_protected: 85%
          - api7_ssrf_protected: 100%
          - api8_config_protected: 95%
          - api9_inventory_protected: 100%
          - api10_unsafe_protected: 90%
```

# 8.2 Alert Configuration

Alert Priority Matrix:

| Severity | Response Time | Escalation | On-Call |
|----------|--------------|------------|---------|
| Critical | Immediate | Yes | Yes |
| High | 30 minutes | After 1 hour | Yes |
| Medium | 4 hours | After 24 hours | No |
| Low | 24 hours | After 1 week | No |

Alert Rules:

```yaml
alertRules:
  - name: mass-sql-injection-attempt
    description: Multiple SQLi attempts from single source
    condition:
      metric: waas.attacks.sqli
      aggregation: count
      threshold: 10
      timeWindow: 5m
      groupBy: sourceIP
    severity: critical
    actions:
      - banIP:
          duration: 24h
          scope: global
      - notify:
          channels: [pagerduty, slack]
      - createIncident:
          system: servicenow
          category: security-incident
          
  - name: api-discovery-new-endpoint
    description: New API endpoint discovered
    condition:
      event: api.endpoint.discovered
      filters:
        - sensitivity: [confidential, restricted]
        - authentication: none
    severity: medium
    actions:
      - notify:
          channels: [slack]
          team: api-security
      - createTask:
          system: jira
          assignee: api-team
          
  - name: bola-attack-pattern
    description: BOLA attack pattern detected
    condition:
      metric: waas.bola.attempts
      threshold: 5
      timeWindow: 5m
      groupBy: [sourceIP, userId]
    severity: high
    actions:
      - suspendAccount:
          duration: 1h
      - notify:
          channels: [pagerduty]
      - forensicCapture:
          duration: 10m
          
  - name: rate-limit-abuse
    description: Sustained rate limit violations
    condition:
      metric: waas.ratelimit.exceeded
      threshold: 100
      timeWindow: 1h
      groupBy: apiKey
    severity: medium
    actions:
      - throttle:
          rate: 10/m
          duration: 1h
      - notify:
          channels: [email]
          recipients: api-owners
```

# 8.3 Log Management

Log Collection Configuration:

```yaml
logging:
  waasAuditLogs:
    enabled: true
    verbosity: detailed
    retention: 90d
    
  attackLogs:
    enabled: true
    includePayload: true
    redactSensitive: true
    retention: 180d
    
  accessLogs:
    enabled: true
    format: json
    fields:
      - timestamp
      - sourceIP
      - method
      - url
      - statusCode
      - responseTime
      - userAgent
      - userId
      - apiKey
    sampling: 100% # Log all requests
    retention: 30d
    
  performanceLogs:
    enabled: true
    metrics:
      - latency
      - throughput
      - errorRate
    aggregation: 1m
    retention: 90d
    
  destinations:
    - type: syslog
      endpoint: siem.company.com:514
      protocol: tcp
      tls: true
      format: cef
      
    - type: s3
      bucket: s3://logs-company/waas/
      prefix: "year=%Y/month=%m/day=%d/"
      compression: gzip
      encryption: AES256
      
    - type: splunk
      endpoint: https://splunk.company.com:8088
      token: ${SPLUNK_HEC_TOKEN}
      index: waas_security
      sourcetype: prismacloud:waas
```

Log Analysis Queries:

```sql
-- Top 10 blocked attacks by type
SELECT 
  attackType,
  COUNT(*) as count,
  COUNT(DISTINCT sourceIP) as uniqueAttackers
FROM waas_events
WHERE effect = 'prevent'
  AND timestamp > NOW() - INTERVAL '24 hours'
GROUP BY attackType
ORDER BY count DESC
LIMIT 10;

-- BOLA attempts analysis
SELECT 
  sourceIP,
  userId,
  COUNT(*) as attempts,
  COUNT(DISTINCT resourceId) as uniqueResources,
  MIN(timestamp) as firstAttempt,
  MAX(timestamp) as lastAttempt
FROM waas_events
WHERE attackType = 'bola'
  AND timestamp > NOW() - INTERVAL '1 hour'
GROUP BY sourceIP, userId
HAVING COUNT(*) >= 5
ORDER BY attempts DESC;

-- API endpoint exposure analysis
SELECT 
  endpoint,
  COUNT(*) as requests,
  COUNT(DISTINCT sourceIP) as uniqueClients,
  AVG(CASE WHEN statusCode >= 400 THEN 1 ELSE 0 END) * 100 as errorRate,
  MAX(CASE WHEN authentication = 'none' THEN 1 ELSE 0 END) as isPublic,
  MAX(sensitivity) as maxSensitivity
FROM api_inventory
JOIN waas_events ON api_inventory.endpoint = waas_events.url
WHERE timestamp > NOW() - INTERVAL '7 days'
GROUP BY endpoint
HAVING isPublic = 1 AND maxSensitivity IN ('confidential', 'restricted')
ORDER BY requests DESC;

-- Rate limiting effectiveness
SELECT 
  DATE_TRUNC('hour', timestamp) as hour,
  SUM(CASE WHEN effect = 'rate-limit' THEN 1 ELSE 0 END) as rateLimited,
  SUM(CASE WHEN effect = 'ban' THEN 1 ELSE 0 END) as banned,
  COUNT(*) as totalRequests,
  SUM(CASE WHEN effect = 'rate-limit' THEN 1 ELSE 0 END)::float / COUNT(*) * 100 as rateLimitPercentage
FROM waas_events
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY hour
ORDER BY hour DESC;
```

---

# 9. Incident Response

# 9.1 Incident Classification

| Level | Description | Examples | Response Time |
|-------|-------------|----------|---------------|
| P0 | Critical security breach | Mass data exfiltration, Active exploitation of zero-day | Immediate |
| P1 | High-risk security event | Successful BOLA attack, Admin account compromise | 15 minutes |
| P2 | Medium-risk event | Multiple failed attack attempts, Policy violations | 1 hour |
| P3 | Low-risk event | Minor policy violations, Performance issues | 4 hours |
| P4 | Informational | Audit findings, Configuration drift | 24 hours |

# 9.2 Incident Response Playbooks

Playbook 1: SQL Injection Attack Response

```yaml
playbook:
  name: SQLi-Attack-Response
  trigger: sqli_detected
  severity: critical
  
  steps:
    - id: 1
      action: isolate
      description: Block attacking IP immediately
      automation:
        - banIP:
            sourceIP: ${event.sourceIP}
            duration: 24h
            scope: global
            
    - id: 2
      action: investigate
      description: Collect forensic evidence
      tasks:
        - captureTraffic:
            duration: 10m
            filter: "host ${event.sourceIP}"
        - queryLogs:
            timeWindow: 1h
            filters:
              - sourceIP: ${event.sourceIP}
        - checkDatabase:
            query: "SELECT * FROM audit_log WHERE ip='${event.sourceIP}'"
            
    - id: 3
      action: assess
      description: Determine impact
      checklist:
        - Was database accessed?
        - Was data modified?
        - Were other systems affected?
        - Is this part of larger campaign?
        
    - id: 4
      action: contain
      description: Prevent further damage
      tasks:
        - reviewRelatedIPs:
            subnet: ${event.sourceIP}/24
        - checkForLateralMovement
        - validateDatabaseIntegrity
        
    - id: 5
      action: notify
      description: Alert stakeholders
      notifications:
        - team: security-incident-response
          channel: pagerduty
          priority: high
        - team: database-team
          channel: slack
        - executive: CISO
          method: email
          condition: dataModified == true
          
    - id: 6
      action: remediate
      description: Fix vulnerabilities
      tasks:
        - patchApplication
        - updateWAASPolicy
        - implementAdditionalControls
        
    - id: 7
      action: document
      description: Create incident report
      artifacts:
        - incidentTimeline
        - forensicEvidence
        - impactAssessment
        - remediationActions
        - lessonsLearned
```

Playbook 2: BOLA Attack Response

```yaml
playbook:
  name: BOLA-Attack-Response
  trigger: bola_pattern_detected
  severity: high
  
  steps:
    - id: 1
      action: validate
      description: Confirm BOLA attempt
      automation:
        - analyzeAccessPattern:
            userId: ${event.userId}
            timeWindow: 15m
        - checkOwnership:
            resourceId: ${event.resourceId}
            userId: ${event.userId}
            
    - id: 2
      action: suspend
      description: Suspend user access
      automation:
        - suspendAPIKey:
            apiKey: ${event.apiKey}
            duration: 1h
        - revokeActiveSessions:
            userId: ${event.userId}
        - requireReauthentication: true
        
    - id: 3
      action: audit
      description: Review all user activity
      tasks:
        - queryAccessLogs:
            userId: ${event.userId}
            timeWindow: 24h
        - identifyAccessedResources
        - checkDataExfiltration
        
    - id: 4
      action: notify
      description: Alert resource owners
      notifications:
        - owners: ${affectedResourceOwners}
          method: email
          urgency: high
        - team: security-team
          channel: slack
          
    - id: 5
      action: remediate
      description: Strengthen authorization
      tasks:
        - implementStricterBOLAPolicy
        - addOwnershipValidation
        - enableAnomalyDetection
```

# 9.3 Forensic Analysis Procedures

Evidence Collection:

```bash
#!/bin/bash
# collect-waas-forensics.sh

INCIDENT_ID=$1
OUTPUT_DIR="/forensics/${INCIDENT_ID}"
mkdir -p "${OUTPUT_DIR}"

echo "Collecting WAAS forensic evidence for incident ${INCIDENT_ID}..."

# 1. Export WAAS events
echo "Exporting WAAS events..."
curl -k -X GET \
  -H "Authorization: Bearer $TOKEN" \
  "https://console.company.com/api/v1/audits/firewall/app/container?incidentId=${INCIDENT_ID}" \
  > "${OUTPUT_DIR}/waas-events.json"

# 2. Capture network traffic
echo "Capturing network traffic..."
kubectl exec -n twistlock defender-pod -- \
  tcpdump -i any -w /tmp/capture.pcap \
  "host ${ATTACKER_IP}" &
TCPDUMP_PID=$!
sleep 300
kill $TCPDUMP_PID
kubectl cp twistlock/defender-pod:/tmp/capture.pcap \
  "${OUTPUT_DIR}/network-capture.pcap"

# 3. Export application logs
echo "Exporting application logs..."
kubectl logs -n production \
  --selector="app=${AFFECTED_APP}" \
  --since=1h \
  > "${OUTPUT_DIR}/app-logs.txt"

# 4. Database query logs
echo "Exporting database logs..."
psql -h db.company.com -U readonly -d production \
  -c "COPY (SELECT * FROM pg_stat_statements WHERE query_start > NOW() - INTERVAL '1 hour') TO STDOUT CSV HEADER" \
  > "${OUTPUT_DIR}/db-queries.csv"

# 5. Generate timeline
echo "Generating timeline..."
prisma-cloud-cli waas forensics timeline \
  --incident ${INCIDENT_ID} \
  --output "${OUTPUT_DIR}/timeline.html"

# 6. Create forensics package
echo "Creating forensics package..."
tar -czf "${OUTPUT_DIR}.tar.gz" "${OUTPUT_DIR}"
sha256sum "${OUTPUT_DIR}.tar.gz" > "${OUTPUT_DIR}.tar.gz.sha256"

echo "Forensics collection complete: ${OUTPUT_DIR}.tar.gz"
```

---

# 10. Compliance and Reporting

# 10.1 Compliance Reporting

Automated Compliance Reports:

```yaml
complianceReports:
  - name: OWASP-API-Top-10-Monthly
    schedule: "0 0 1 * *" # First day of month
    frameworks:
      - owasp_api_top10_2023
    scope:
      - environment: production
      - criticality: [high, critical]
    content:
      - executiveSummary
      - controlCoverage
      - vulnerabilityStatus
      - remediationProgress
      - trendsAnalysis
    format: pdf
    distribution:
      - ciso@company.com
      - security-leadership@company.com
      
  - name: CSA-CCM-Quarterly
    schedule: "0 0 1 */3 *" # Quarterly
    frameworks:
      - csa_ccm_v4
    scope:
      - allEnvironments
    content:
      - controlMapping
      - evidenceCollection
      - gapAnalysis
      - actionPlan
    format: [pdf, excel]
    distribution:
      - compliance@company.com
      - auditors@company.com
      
  - name: PCI-DSS-Requirement-6
    schedule: "0 0 * * 0" # Weekly on Sunday
    frameworks:
      - pci_dss_4.0
    requirements:
      - "6.4.3" # Secure coding
      - "6.5" # Common coding vulnerabilities
      - "11.3.2" # Internal vulnerability scans
    scope:
      - applications: payment-processing
    content:
      - requirementStatus
      - vulnerabilityScan
      - remediationTracking
    format: pdf
    distribution:
      - qsa@company.com
      - payment-team@company.com
```

Compliance Dashboard:

```yaml
dashboards:
  - name: Compliance-Overview
    widgets:
      - type: scorecard
        title: Framework Compliance
        metrics:
          - name: OWASP API Top 10
            score: 98%
            status: compliant
            trend: +2%
          - name: CSA CCM
            score: 95%
            status: compliant
            trend: +5%
          - name: PCI DSS
            score: 100%
            status: compliant
            trend: 0%
            
      - type: table
        title: Control Status
        columns:
          - Control ID
          - Description
          - Status
          - Evidence
          - Last Validated
        data: query_control_status()
        
      - type: timeline
        title: Remediation Progress
        showMilestones: true
        showDeadlines: true
        
      - type: matrix
        title: Risk Heat Map
        xAxis: likelihood
        yAxis: impact
        dataPoints: open_findings()
```

# 10.2 Audit Trail and Evidence

Evidence Collection:

```yaml
evidenceCollection:
  automated: true
  
  artifacts:
    - type: policy-configuration
      frequency: daily
      retention: 7y
      format: json
      storage: s3://compliance-evidence/policies/
      
    - type: protection-logs
      frequency: continuous
      retention: 7y
      format: json
      storage: s3://compliance-evidence/logs/
      
    - type: incident-reports
      frequency: per-incident
      retention: 7y
      format: pdf
      storage: s3://compliance-evidence/incidents/
      
    - type: vulnerability-scans
      frequency: weekly
      retention: 3y
      format: json
      storage: s3://compliance-evidence/scans/
      
    - type: access-reviews
      frequency: quarterly
      retention: 7y
      format: pdf
      storage: s3://compliance-evidence/reviews/
      
  chainOfCustody:
    enabled: true
    cryptographicSigning: true
    timestamping: trusted
    immutableStorage: true
```

---

# 11. Appendices

# Appendix A: API Security Checklist

Pre-Deployment:
- [ ] API endpoints documented (OpenAPI/Swagger)
- [ ] Authentication mechanism defined
- [ ] Authorization model designed
- [ ] Data classification completed
- [ ] Rate limits determined
- [ ] Error handling standardized
- [ ] Security testing completed

WAAS Configuration:
- [ ] Defender deployed to target environment
- [ ] API discovery enabled and verified
- [ ] Schema validation configured
- [ ] OWASP Top 10 protection enabled
- [ ] Custom rules implemented
- [ ] Rate limiting configured
- [ ] Bot protection enabled
- [ ] Alert channels configured

Post-Deployment:
- [ ] Baseline traffic established (14 days)
- [ ] False positives analyzed and addressed
- [ ] Performance impact validated (<5ms)
- [ ] Monitoring dashboards configured
- [ ] Incident response procedures tested
- [ ] Team training completed
- [ ] Documentation updated

# Appendix B: Troubleshooting Guide

Issue: High latency after WAAS deployment

Troubleshooting Steps:
1. Check defender resource usage
   ```bash
   kubectl top pods -n twistlock
   ```
2. Review policy complexity (number of rules)
3. Disable body inspection temporarily
4. Analyze request size distribution
5. Check TLS termination configuration

Resolution:
- Optimize regex patterns in custom rules
- Implement request size limits
- Use defender anti-affinity rules
- Enable hardware TLS acceleration

---

Issue: False positive alerts for legitimate traffic

Troubleshooting Steps:
1. Review alert details and payload
2. Check if pattern matches legitimate use case
3. Analyze user agent and source IP
4. Verify API specification accuracy

Resolution:
- Create exception rule for specific pattern
- Adjust detection sensitivity
- Update API schema definition
- Implement allowlist for known good sources

---

# Appendix C: Reference Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Internet / Users                      │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────────┐
│               CDN / Global Load Balancer                 │
│                  (CloudFlare / Route53)                  │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────────┐
│            Regional Load Balancer (ALB/NLB)             │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────────┐
│              Prisma Cloud WAAS Defender                  │
│   ┌──────────────────────────────────────────────┐     │
│   │  ┌─────────────┐  ┌─────────────┐  ┌──────┐ │     │
│   │  │ DDoS        │  │ Bot         │  │ Rate │ │     │
│   │  │ Protection  │  │ Protection  │  │ Limit│ │     │
│   │  └─────────────┘  └─────────────┘  └──────┘ │     │
│   │  ┌─────────────┐  ┌─────────────┐  ┌──────┐ │     │
│   │  │ OWASP Top10 │  │ API         │  │Custom│ │     │
│   │  │ Protection  │  │ Protection  │  │ Rules│ │     │
│   │  └─────────────┘  └─────────────┘  └──────┘ │     │
│   └──────────────────────────────────────────────┘     │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────────┐
│           Kubernetes Cluster / Container Platform        │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│   │  API Pod 1   │  │  API Pod 2   │  │  API Pod N   │ │
│   │              │  │              │  │              │ │
│   │  Defender    │  │  Defender    │  │  Defender    │ │
│   │  Sidecar     │  │  Sidecar     │  │  Sidecar     │ │
│   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
│          └──────────────────┴──────────────────┘        │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────────┐
│                  Backend Services                        │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│   │ Database │  │  Cache   │  │ Message  │            │
│   │          │  │  (Redis) │  │  Queue   │            │
│   └──────────┘  └──────────┘  └──────────┘            │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│            Prisma Cloud Management Plane                 │
│                                                          │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│   │   Console    │  │  Intelligence│  │   Analytics  │ │
│   │              │  │    Stream    │  │   Engine     │ │
│   └──────────────┘  └──────────────┘  └──────────────┘ │
│                                                          │
│   ┌──────────────────────────────────────────────────┐  │
│   │         Logging & SIEM Integration               │  │
│   │   ┌──────────┐  ┌──────────┐  ┌──────────┐     │  │
│   │   │ Splunk   │  │   ELK    │  │  Syslog  │     │  │
│   │   └──────────┘  └──────────┘  └──────────┘     │  │
│   └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

# Appendix D: Quick Reference Commands

Common WAAS Operations:

```bash
# Check WAAS policy status
prisma-cloud-cli waas policy list --format table

# Get defender status
kubectl get pods -n twistlock -o wide

# View recent alerts
prisma-cloud-cli waas alerts --severity critical --limit 50

# Export WAAS events
curl -k -X GET \
  -H "Authorization: Bearer $TOKEN" \
  "https://console/api/v1/audits/firewall/app/container?limit=1000" \
  | jq '.' > waas-events.json

# Test WAAS policy
curl -X POST https://api.company.com/api/test \
  -H "User-Agent: sqlmap" \
  -d "id=1' OR '1'='1"

# Update WAAS rule via API
curl -k -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @updated-policy.json \
  https://console/api/v1/policies/firewall/app/container/{id}

# Generate compliance report
prisma-cloud-cli waas compliance-report \
  --framework owasp-api-top10 \
  --output report.pdf

# Ban IP address
prisma-cloud-cli waas ban-ip \
  --ip 203.0.113.100 \
  --duration 24h \
  --reason "SQL injection attempts"

# Clear API discovery cache
prisma-cloud-cli waas clear-discovery-cache \
  --application customer-api

# Export API inventory
prisma-cloud-cli waas export-inventory \
  --format csv \
  --output api-inventory.csv
```

# Appendix E: Integration Examples

SIEM Integration (Splunk):

```xml
<!-- inputs.conf -->
[http://waas_events]
disabled = 0
token = your-hec-token-here
sourcetype = prismacloud:waas
index = security

<!-- props.conf -->
[prismacloud:waas]
SHOULD_LINEMERGE = false
KV_MODE = json
TRUNCATE = 0
TIME_PREFIX = \"timestamp\":\"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3NZ
MAX_TIMESTAMP_LOOKAHEAD = 32

<!-- savedsearches.conf -->
[WAAS - Critical SQLi Attempts]
search = index=security sourcetype=prismacloud:waas attackType=sqli severity=critical | stats count by sourceIP, url
cron_schedule = */5 * * * *
action.email.to = security@company.com
alert.severity = 4
alert.expires = 24h
```

SOAR Integration (Cortex XSOAR):

```python
# waas_integration.py

import requests
from CommonServerPython import *

class PrismaCloudWAASClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.token = self._authenticate(username, password)
    
    def _authenticate(self, username, password):
        response = requests.post(
            f"{self.base_url}/api/v1/authenticate",
            json={"username": username, "password": password},
            verify=False
        )
        return response.json().get("token")
    
    def get_waas_events(self, severity=None, limit=100):
        headers = {"Authorization": f"Bearer {self.token}"}
        params = {"limit": limit}
        if severity:
            params["severity"] = severity
        
        response = requests.get(
            f"{self.base_url}/api/v1/audits/firewall/app/container",
            headers=headers,
            params=params,
            verify=False
        )
        return response.json()
    
    def ban_ip(self, ip_address, duration="24h"):
        headers = {"Authorization": f"Bearer {self.token}"}
        payload = {
            "ip": ip_address,
            "duration": duration,
            "scope": "global"
        }
        
        response = requests.post(
            f"{self.base_url}/api/v1/waas/ban",
            headers=headers,
            json=payload,
            verify=False
        )
        return response.json()

def fetch_waas_incidents_command(client, args):
    severity = args.get('severity')
    limit = int(args.get('limit', 50))
    
    events = client.get_waas_events(severity, limit)
    
    incidents = []
    for event in events:
        incident = {
            'name': f"WAAS Alert - {event['attackType']}",
            'occurred': event['timestamp'],
            'severity': event['severity'],
            'rawJSON': json.dumps(event)
        }
        incidents.append(incident)
    
    return incidents

def ban_ip_command(client, args):
    ip = args.get('ip')
    duration = args.get('duration', '24h')
    
    result = client.ban_ip(ip, duration)
    
    return CommandResults(
        outputs_prefix='PrismaCloud.WAAS.BannedIP',
        outputs=result,
        readable_output=f"Successfully banned IP {ip} for {duration}"
    )
```

CI/CD Integration (GitLab CI):

```yaml
# .gitlab-ci.yml

stages:
  - build
  - test
  - security
  - deploy

waas_api_security_scan:
  stage: security
  image: prismacloud/twistcli:latest
  script:
    # Download twistcli
    - curl -k -u $PRISMA_USER:$PRISMA_PASS https://$PRISMA_CONSOLE/api/v1/util/twistcli > twistcli
    - chmod +x twistcli
    
    # Scan API specification
    - |
      ./twistcli api-scan \
        --address https://$PRISMA_CONSOLE \
        --user $PRISMA_USER \
        --password $PRISMA_PASS \
        --spec openapi.yaml \
        --severity critical,high \
        --compliance-threshold 90
    
    # Generate report
    - |
      ./twistcli api-report \
        --address https://$PRISMA_CONSOLE \
        --user $PRISMA_USER \
        --password $PRISMA_PASS \
        --output api-security-report.json
  
  artifacts:
    reports:
      junit: api-security-report.json
    paths:
      - api-security-report.json
  
  only:
    - merge_requests
    - main

deploy_waas_policy:
  stage: deploy
  image: alpine:latest
  before_script:
    - apk add --no-cache curl jq
  script:
    # Authenticate
    - |
      TOKEN=$(curl -k -X POST \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$PRISMA_USER\",\"password\":\"$PRISMA_PASS\"}" \
        https://$PRISMA_CONSOLE/api/v1/authenticate | jq -r '.token')
    
    # Deploy WAAS policy
    - |
      curl -k -X PUT \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d @waas-policy-$CI_ENVIRONMENT_NAME.json \
        https://$PRISMA_CONSOLE/api/v1/policies/firewall/app/container
    
    # Verify deployment
    - |
      sleep 10
      curl -k -X GET \
        -H "Authorization: Bearer $TOKEN" \
        https://$PRISMA_CONSOLE/api/v1/policies/firewall/app/container | jq '.'
  
  only:
    - main
  environment:
    name: production
```

# Appendix F: Performance Tuning Guide

Optimization Checklist:

1. Defender Placement:
   - Use node affinity for high-performance nodes
   - Configure anti-affinity for HA
   - Allocate sufficient resources (2 CPU, 2GB RAM minimum)

2. Policy Optimization:
   - Consolidate similar rules
   - Use specific patterns instead of wildcards
   - Disable unused protection modules
   - Implement rule caching

3. Network Optimization:
   - Enable connection pooling
   - Configure appropriate timeout values
   - Use HTTP/2 where possible
   - Enable TLS session resumption

4. Logging Optimization:
   - Use sampling for high-volume endpoints
   - Implement log aggregation
   - Use asynchronous logging
   - Configure appropriate retention

Performance Targets:

| Metric | Target | Critical Threshold |
|--------|--------|-------------------|
| Request Latency (P50) | <2ms | >10ms |
| Request Latency (P95) | <5ms | >20ms |
| Request Latency (P99) | <10ms | >50ms |
| Throughput | >10,000 req/s | <5,000 req/s |
| CPU Usage | <50% | >80% |
| Memory Usage | <1GB | >2GB |
| False Positive Rate | <2% | >5% |

---

# Document Revision History

| Version | Date | Author | Changes | Approved By |
|---------|------|--------|---------|-------------|
| 1.0 | 2025-08-15 | Security Team | Initial draft | CISO |
| 1.5 | 2025-11-20 | Security Team | Added OWASP 2023 updates | CISO |
| 2.0 | 2026-01-08 | Security Ops | Complete revision with CSA CCM v4 | CISO |

---

# Approval Signatures

Prepared By:  
Name: ___________________  
Title: Cloud Security Engineer  
Date: ___________________  
Signature: ___________________

Reviewed By:  
Name: ___________________  
Title: Security Architect  
Date: ___________________  
Signature: ___________________

Approved By:  
Name: ___________________  
Title: Chief Information Security Officer  
Date: ___________________  
Signature: ___________________

---

# Contact Information

Security Operations Center:
- Email: soc@company.com
- Phone: +1-555-0123 (24/7)
- Slack: #security-ops

WAAS Support:
- Email: waas-support@company.com
- Ticket System: https://jira.company.com/browse/SEC
- Documentation: https://docs.company.com/security/waas

Vendor Support:
- Prisma Cloud Support: support.paloaltonetworks.com
- TAM Contact: tam@paloaltonetworks.com
- Emergency Hotline: 1-866-698-9401

---

END OF DOCUMENT  perUser: 5
          period: 1h
        requireHumanVerification: true
        botProtection: strict
        sequenceValidation: true
        requiredPriorSteps:
          - /api/v2/cart/review
          - /api/v2/address/confirm
        maxRetries: 3
        cooldownPeriod: 5m
        
    - name: account-creation
      endpoints: [/api/v2/users/register]
      protection:
        rateLimiting:
          perIP: 3
          period: 1h
        requireCaptcha: true
        emailVerification: required
        phoneVerification: recommended
        preventDisposableEmails: true
        deviceFingerprinting: true
        
    - name: password-reset
      endpoints: [/api/v2/auth/reset-password]
      protection:
        rateLimiting:
          perEmail: 3
          period: 1h
        requireSecurityQuestions: true
        notificationOnReset: true
        cooldownEnforcement: 5m
        
    - name: bulk-operations
      endpoints:
        - /api/v2/bulk-download
        - /api/v2/export
      protection:
        rateLimiting:
          perUser: 5
          period: 1d
        requireApproval: true
        auditLog: mandatory
        
  sequentialAccessValidation:
    enabled: true
    flows:
      - name: checkout-flow
        sequence:
          - step: 1
            endpoint: /api/v2/cart
            method: GET
          - step: 2
            endpoint: /api/v2/checkout/initiate
            method: POST
            maxTimeSincePrevious: 10m
          - step: 3
            endpoint: /api/v2/payment/process
            method: POST
            maxTimeSincePrevious: 5m
        enforceSequence: true
        allowSkipSteps: false
```

2. Bot and Automation Detection:

```yaml
botProtection:
  enabled: true
  mode: challenge # Options: monitor, challenge, block
  
  detectionMethods:
    - browserFingerprinting: true
    - behavioralAnalysis: true
    - trafficPatternAnalysis: true
    - knownBotSignatures: true
    
  indicators:
    - missingBrowserHeaders: true
    - suspiciousUserAgents: true
    - impossibleTravelSpeed: true
    - uniformRequestTiming: true
    - headlessBrowserDetection: true
    
  protectedEndpoints:
    - /api/v2/auth/login
    - /api/v2/users/register
    - /api/v2/checkout/*
    - /api/v2/tickets/purchase
    
  challengeTypes:
    - captcha
    - javascript_challenge
    - proof_of_work
    
  whitelisting:
    allowedBots:
      - googlebot
      - bingbot
    verifyLegitimateBot: true
```

CSA CCM Mapping: TVM-01, TVM-02, IVS-06  
Implementation Priority: High  
Default Action: Challenge (for sensitive flows)

---

# API7:2023 - Server Side Request Forgery (SSRF)

Vulnerability Description:
SSRF flaws occur when an API fetches a remote resource without validating the user-supplied URL, allowing attackers to coerce the application to send crafted requests to unexpected destinations.

WAAS Protection Mechanisms:

1. SSRF Protection Configuration:

```yaml
ssrfProtection:
  enabled: true
  mode: prevent
  
  urlValidation:
    enabled: true
    rules:
      # Whitelist approach
      allowedDomains:
        - api.trusted-partner.com
        - cdn.company.com
        - storage.googleapis.com
      allowedSchemes: [https]
      denyPrivateIPs: true
      denyLoopback: true
      denyLinkLocal: true
      denyMulticast: true
      
  blockedDestinations:
    privateIPRanges:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - 127.0.0.0/8
    metadataEndpoints:
      - 169.254.169.254/32 # AWS, Azure, GCP metadata
      - 169.254.169.253/32 # AWS link-local
    internalServices:
      - localhost
      - 0.0.0.0
      
  protectedParameters:
    - url
    - callback_url
    - webhook
    - redirect_uri
    - image_url
    - fetch_url
    - proxy
    
  redirectProtection:
    maxRedirects: 2
    validateRedirectDestination: true
    blockOpenRedirects: true
    
  dnsRebindingProtection:
    enabled: true
    validateDNSBeforeRequest: true
    cacheDNSResults: true
    recheckInterval: 5m
```

2. SSRF Detection Patterns:

```yaml
ssrfDetection:
  patterns:
    # URL encoding bypass attempts
    - pattern: "%(?:25)?2[Ff]"
      description: Double URL encoding
      action: block
      
    # IP address obfuscation
    - pattern: "(?:0x[0-9a-fA-F]+|0[0-7]+|[0-9]+)"
      description: Non-decimal IP representation
      action: block
      
    # DNS rebinding indicators
    - pattern: "(?:localhost|127\\.0\\.0\\.1).*\\..*"
      description: DNS rebinding pattern
      action: block
```

CSA CCM Mapping: AIS-04, DSI-01, IVS-01  
Implementation Priority: High  
Default Action: Block

---

# API8:2023 - Security Misconfiguration

Vulnerability Description:
APIs and systems supporting them typically contain complex configurations meant to make them more customizable, often leaving them exposed to security misconfigurations.

WAAS Protection Mechanisms:

1. Security Headers Enforcement:

```yaml
securityHeaders:
  enforcement:
    enabled: true
    action: inject # Options: inject, validate, alert
    
  requiredHeaders:
    response:
      Strict-Transport-Security: "max-age=31536000; includeSubDomains"
      X-Content-Type-Options: "nosniff"
      X-Frame-Options: "DENY"
      Content-Security-Policy: "default-src 'self'"
      X-XSS-Protection: "1; mode=block"
      Referrer-Policy: "strict-origin-when-cross-origin"
      Permissions-Policy: "geolocation=(), microphone=(), camera=()"
      
    removeHeaders:
      - X-Powered-By
      - Server
      - X-AspNet-Version
      - X-AspNetMvc-Version
      
  corsConfiguration:
    validateOrigin: true
    allowedOrigins:
      - https://app.company.com
      - https://mobile.company.com
    denyWildcard: true
    allowCredentials: false
    maxAge: 3600
    
  tlsConfiguration:
    enforceHTTPS: true
    minimumVersion: TLS1.2
    preferredVersion: TLS1.3
    cipherSuiteValidation: true
    allowedCiphers:
      - TLS_AES_256_GCM_SHA384
      - TLS_CHACHA20_POLY1305_SHA256
      - TLS_AES_128_GCM_SHA256
    blockWeakCiphers: true
    requirePerfectForwardSecrecy: true
    
  errorHandling:
    suppressDetailedErrors: true
    customErrorPages: true
    preventStackTraceLeakage: true
    sanitizeErrorMessages: true
```

2. Misconfiguration Detection:

```yaml
misconfigurationDetection:
  enabled: true
  
  checks:
    - name: debug-mode-detection
      patterns:
        - X-Debug
        - X-Debug-Token
        - debug=true
      action: alert
      severity: high
      
    - name: verbose-error-messages
      detectStackTraces: true
      detectSQLErrors: true
      detectSystemPaths: true
      action: blockAndRedact
      
    - name: default-credentials
      endpoints:
        - /api/admin
        - /api/debug
      checkCommonCredentials: true
      action: alert
      
    - name: unnecessary-http-methods
      allowedMethods: [GET, POST, PUT, PATCH, DELETE, OPTIONS]
      blockMethods: [TRACE, TRACK, CONNECT]
      
    - name: sensitive-data-exposure
      scanResponses: true
      patterns:
        - api[_-]?key
        - secret
        - password
        - private[_-]?key
        - aws[_-]?access
      action: redact
```

CSA CCM Mapping: CCC-02, GRM-06, IAM-13, IVS-01  
Implementation Priority: High  
Default Action: Alert and Inject Headers

---

# API9:2023 - Improper Inventory Management

Vulnerability Description:
APIs tend to expose more endpoints than traditional web applications, making proper documentation highly important. Hosts and deployed API versions also need to be properly inventoried.

WAAS Protection Mechanisms:

1. Automated API Inventory:

```yaml
apiInventory:
  discovery:
    enabled: true
    mode: continuous
    learningPeriod: 7d
    
  tracking:
    endpoints: true
    versions: true
    hosts: true
    authentication: true
    dataTypes: true
    
  versionManagement:
    detectVersions: true
    versionSources:
      - urlPath # /api/v1/, /api/v2/
      - header # X-API-Version, API-Version
      - parameter # ?version=1.0
      
    deprecationPolicy:
      warnOnOldVersions: true
      deprecationThreshold: 180d # 6 months
      blockDeprecatedAfter: 365d # 1 year
      notifyOwners: true
      
    enforceVersioning:
      requireVersionHeader: true
      rejectUnversioned: false
      defaultVersion: latest
      
  shadowAPIDetection:
    enabled: true
    alertOnUndocumented: true
    compareToSpecification: true
    specificationSource: openapi
    
  zombieAPIDetection:
    enabled: true
    inactivityThreshold: 90d
    alertOnZombieAPI: true
    considerForDecommission: true
    
  documentationSync:
    autoUpdateSpecs: true
    validateAgainstSpec: true
    specFormat: openapi_3.0
    specLocation: /api/docs/openapi.yaml
    
  sensitivityClassification:
    autoClassify: true
    factors:
      - authenticationRequired
      - dataTypesExposed
      - externalAccess
      - changeFrequency
    labels:
      - public
      - internal
      - confidential
      - restricted
```

2. Non-Production Environment Protection:

```yaml
environmentProtection:
  enabled: true
  
  identification:
    methods:
      - hostname # dev.api.company.com, staging.api.company.com
      - header # X-Environment
      - certificate # Subject CN
      
  developmentEnvironments:
    restrictAccess: true
    allowedIPs:
      - 10.0.0.0/8 # Corporate network
      - 203.0.113.0/24 # VPN
    requireVPN: true
    blockPublicAccess: true
    
  stagingEnvironments:
    restrictAccess: true
    requireAuthentication: true
    limitedDataAccess: true
    syntheticDataOnly: true
    
  preventionRules:
    - name: prod-data-in-nonprod
      detect: true
      dataTypes: [PII, PCI, PHI]
      action: blockAndAlert
      
    - name: nonprod-version-in-prod
      detectBetaEndpoints: true
      detectDebugEndpoints: true
      action: block
```

CSA CCM Mapping: GRM-01, GRM-02, GRM-10, TVM-01  
Implementation Priority: Medium  
Default Action: Alert

---

# API10:2023 - Unsafe Consumption of APIs

Vulnerability Description:
Developers tend to trust data received from third-party APIs more than user input, leading to weaker security standards. Attackers can target integrated third-party APIs to compromise applications.

WAAS Protection Mechanisms:

1. Third-Party API Security:

```yaml
thirdPartyAPISecurity:
  enabled: true
  
  outboundValidation:
    enabled: true
    validateResponses: true
    
  trustedSources:
    whitelist:
      - domain: api.stripe.com
        tlsRequired: true
        certificateValidation: strict
        pinCertificate: true
        
      - domain: api.twilio.com
        tlsRequired: true
        rateLimit: 100/m
        
  responseValidation:
    enabled: true
    rules:
      - source: api.payment-provider.com
        validateSchema: true
        schemaFile: /schemas/payment-response.json
        rejectOnValidationFailure: true
        
      - source: api.data-provider.com
        maxResponseSize: 5MB
        scanForMaliciousContent: true
        validateDataTypes: true
        
  dataIntegrityChecks:
    enabled: true
    verifySignatures: true
    validateChecksums: true
    enforceContentType: true
    
  redirectProtection:
    followRedirects: false
    validateRedirectDestination: true
    maxRedirects: 0
    
  timeoutConfiguration:
    connectionTimeout: 5s
    readTimeout: 30s
    failureHandling: graceful
    
  circuitBreaker:
    enabled: true
    failureThreshold: 5
    timeWindow: 1m
    openStateDuration: 30s
    halfOpenRequests: 3
```

2. API Integration Security:

```yaml
integrationSecurity:
  credentialManagement:
    rotateAPIKeys: true
    rotationFrequency: 90d
    storeInVault: true
    encryptInTransit: true
    
  minimumSecurityStandards:
    requireHTTPS: true
    validateCertificates: true
    minimumTLSVersion: TLS1.2
    rejectSelfSignedCerts: true
    
  dataValidation:
    inputSanitization: true
    outputEncoding: true
    typeValidation: strict
    
  monitoringAndAlerting:
    logAllInteractions: true
    alertOnAnomalies: true
    detectDataPoisoning: true
    validateDataIntegrity: true
```

CSA CCM Mapping: DSI-01, DSI-02, DSI-07, IVS-01  
Implementation Priority: High  
Default Action: Alert

---

# 4.2 OWASP API Top 10 Coverage Matrix

| OWASP Risk | WAAS Feature | Protection Level | Default Mode | Tuning Required |
|------------|--------------|------------------|--------------|-----------------|
| API1: BOLA | Object-level access control, Anomaly detection | High | Alert | Yes |
| API2: Broken Authentication | JWT validation, MFA enforcement, Credential stuffing protection | Very High | Block | Minimal |
| API3: Broken Property Authorization | Response filtering, Mass assignment protection | Medium | Alert | Yes |
| API4: Unrestricted Resource Consumption | Rate limiting, DoS protection, Resource quotas | High | Mixed | Yes |
| API5: BFLA | Role-based access, Permission validation | High | Block | Minimal |
| API6: Business Flow | Sequential validation, Bot protection | Medium | Challenge | Yes |
| API7: SSRF | URL validation, IP blocking, Redirect control | High | Block | Minimal |
| API8: Security Misconfiguration | Header injection, TLS enforcement, Error suppression | Medium | Alert/Inject | Minimal |
| API9: Improper Inventory | API discovery, Version tracking, Shadow API detection | Low | Alert | Minimal |
| API10: Unsafe API Consumption | Response validation, Third-party monitoring | Medium | Alert | Yes |

---

# 5. CSA CCM Alignment

# 5.1 Cloud Security Alliance CCM v4.0 Mapping

Prisma Cloud WAAS aligns with multiple CSA CCM control domains:

# Application & Interface Security (AIS)

AIS-01: Application Security
- WAAS Coverage: OWASP Top 10 protection, Secure coding validation
- Implementation: Enable all OWASP protection modules
- Evidence: WAAS security audit logs, Protection reports

AIS-02: Application Security - Customer Access
- WAAS Coverage: API authentication, Authorization controls
- Implementation: JWT validation, OAuth enforcement
- Evidence: Authentication logs, Access control matrices

AIS-03: Application Security - Data Integrity
- WAAS Coverage: Input validation, Output encoding
- Implementation: Schema validation, Content-type enforcement
- Evidence: Validation reports, Integrity check logs

AIS-04: Application Security - Application Programming Interface (API)
- WAAS Coverage: Complete API security suite
- Implementation: All WAAS API protection features
- Evidence: API inventory, Security assessment reports

# Data Security & Privacy (DSI)

DSI-01: Data Inventory / Flows
- WAAS Coverage: API discovery, Data classification
- Implementation: Automatic data type detection
- Evidence: API inventory with data classifications

DSI-02: Data Leakage Prevention
- WAAS Coverage: Response filtering, Sensitive data redaction
- Implementation: DLP rules in WAAS policies
- Evidence: Redaction logs, Data leakage alerts

DSI-05: Data Sovereignty
- WAAS Coverage: Geographic routing, Regional enforcement
- Implementation: Location-based access controls
- Evidence: Geographic access logs

DSI-07: Secure Disposal
- WAAS Coverage: Log retention policies, Data purging
- Implementation: Automated log cleanup
- Evidence: Disposal audit trail

# Identity & Access Management (IAM)

IAM-01: Audit Tools Access
- WAAS Coverage: RBAC for WAAS console, API access controls
- Implementation: Role-based access to WAAS features
- Evidence: Access logs, Permission matrices

IAM-02: Credential Lifecycle Management
- WAAS Coverage: API key rotation, Token management
- Implementation: Automated credential rotation
- Evidence: Rotation logs, Lifecycle reports

IAM-05: Credential Management System
- WAAS Coverage: Integration with secret managers
- Implementation: Vault integration for API credentials
- Evidence: Secret manager audit logs

IAM-06: Third Party Access
- WAAS Coverage: Third-party API monitoring
- Implementation: Outbound API security controls
- Evidence: Third-party interaction logs

IAM-08: User Access Reviews
- WAAS Coverage: API access analytics, Usage tracking
- Implementation: Periodic access reviews
- Evidence: Access review reports

IAM-11: Least Privilege
- WAAS Coverage: Fine-grained authorization, Permission enforcement
- Implementation: Minimal permission policies
- Evidence: Permission audit logs

# Infrastructure & Virtualization Security (IVS)

IVS-01: Audit Logging / Intrusion Detection
- WAAS Coverage: Comprehensive logging, Threat detection
- Implementation: Full WAAS audit trail
- Evidence: Security event logs, IDS alerts

IVS-06: Network Security
- WAAS Coverage: Layer 7 firewall, Network-based protection
- Implementation: WAAS network controls
- Evidence: Network traffic analysis

IVS-08: Production / Non-Production Environments
- WAAS Coverage: Environment separation, Access controls
- Implementation: Environment-specific policies
- Evidence: Environment configuration docs

# Threat & Vulnerability Management (TVM)

TVM-01: Threat Intelligence
- WAAS Coverage: Threat feed integration, Attack signatures
- Implementation: Automatic signature updates
- Evidence: Threat intelligence reports

TVM-02: Vulnerability Management
- WAAS Coverage: WAAS configuration scanning, Policy assessment
- Implementation: Regular vulnerability assessments
- Evidence: Vulnerability scan reports

# 5.2 CCM Compliance Dashboard

```yaml
complianceReporting:
  enabled: true
  frameworks:
    - csa_ccm_v4
    - owasp_api_top10_2023
    - pci_dss_4.0
    - hipaa
    - gdpr
    
  reportGeneration:
    frequency: weekly
    format: [pdf, json, csv]
    distribution:
      - security-team@company.com
      - compliance@company.com
    
  controlMapping:
    autoMap: true
    validateCoverage: true
    trackGaps: true
    
  evidenceCollection:
    automaticCapture: true
    retentionPeriod: 7y
    storageLocation: s3://compliance-evidence/
```

---

# 6. Implementation Procedures

# 6.1 Phase 1: Planning and Assessment (Weeks 1-2)

Objectives:
- Define scope and requirements
- Identify critical APIs and applications
- Establish success criteria
- Prepare infrastructure

Activities:

1. Application Inventory:
```bash
# Create inventory of all applications requiring WAAS protection
# Template: applications-inventory.yaml

applications:
  - name: customer-portal-api
    type: container
    platform: kubernetes
    criticality: high
    apis:
      - /api/v2/customers
      - /api/v2/orders
    authentication: jwt
    dataClassification: confidential
    
  - name: mobile-backend
    type: serverless
    platform: aws-lambda
    criticality: critical
    apis:
      - /api/v3/auth
      - /api/v3/payments
    authentication: oauth2
    dataClassification: restricted
```

2. Risk Assessment:
- Identify high-risk APIs (public-facing, handling sensitive data)
- Document current security posture
- Map existing vulnerabilities to OWASP API Top 10
- Prioritize protection requirements

3. Architecture Review:
```
Current State Analysis:
- Network topology documentation
- Traffic flow diagrams
- Load balancer configurations
- SSL/TLS termination points
- Authentication mechanisms
- Current WAF/security controls
```

4. Success Metrics Definition:
| Metric | Baseline | Target | Timeline |
|--------|----------|--------|----------|
| API Coverage | 0% | 100% | 8 weeks |
| OWASP Top 10 Protection | 0% | 100% | 6 weeks |
| False Positive Rate | N/A | <5% | 12 weeks |
| MTTR for Critical Alerts | N/A | <30 min | 12 weeks |
| Blocked Attacks/Day | 0 | Track | Ongoing |

Deliverables:
- [ ] Application inventory spreadsheet
- [ ] Risk assessment report
- [ ] Architecture diagrams
- [ ] Implementation plan
- [ ] Resource allocation plan
- [ ] Success criteria document

---

# 6.2 Phase 2: Pilot Deployment (Weeks 3-4)

Objectives:
- Deploy WAAS to pilot applications
- Validate deployment architecture
- Establish baseline policies
- Train security team

Activities:

1. Defender Deployment:

For Kubernetes Applications:
```yaml
# waas-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: twistlock-defender
  namespace: twistlock
spec:
  selector:
    matchLabels:
      app: twistlock-defender
  template:
    metadata:
      labels:
        app: twistlock-defender
    spec:
      serviceAccountName: twistlock-defender
      containers:
      - name: twistlock-defender
        image: registry.twistlock.com/twistlock/defender:defender_<version>
        env:
        - name: DEFENDER_TYPE
          value: "appEmbedded"
        - name: WS_ADDRESS
          value: "wss://console.company.com:8084"
        volumeMounts:
        - name: data
          mountPath: /var/lib/twistlock
```

Deployment Commands:
```bash
# Download defender from Console
curl -k -u <user>:<password> \
  https://<console>/api/v1/scripts/defender.sh > defender.sh

# Deploy to Kubernetes
bash defender.sh --cluster --namespace twistlock

# Verify deployment
kubectl get pods -n twistlock
kubectl logs -n twistlock -l app=twistlock-defender
```

For Serverless (AWS Lambda):
```bash
# Download serverless defender layer
aws lambda publish-layer-version \
  --layer-name prisma-cloud-defender \
  --zip-file fileb://prisma-cloud-defender.zip \
  --compatible-runtimes python3.9 nodejs16.x

# Attach to Lambda function
aws lambda update-function-configuration \
  --function-name my-api-function \
  --layers arn:aws:lambda:region:account:layer:prisma-cloud-defender:1
```

2. Initial Policy Configuration:

```yaml
# pilot-waas-policy.yaml
apiVersion: waas.prismacloud.io/v1
kind: WAASPolicy
metadata:
  name: pilot-api-protection
spec:
  appScope:
    applications:
      - customer-portal-api
    environments:
      - development
      - staging
      
  protectionMode: alert # Start in alert-only mode
  
  rulesets:
    - name: baseline-protection
      priority: 1
      
      httpProtection:
        enabled: true
        sqli: alert
        xss: alert
        attackTools: alert
        shellshock: alert
        malformedRequest: alert
        cmdi: alert
        lfi: alert
        codeInjection: alert
        
      apiProtection:
        enabled: true
        apiDiscovery: true
        schemaValidation: alert
        endpointBasedAccess: alert
        
      accessControl:
        enabled: true
        allowedIPs: []
        deniedIPs: []
        allowedCountries: []
        deniedCountries: []
        
      rateLimiting:
        enabled: true
        limit: 1000
        period: 1m
        action: alert
        
      botProtection:
        enabled: true
        mode: detect
        knownBots: allow
        unknownBots: alert
        
  alerting:
    channels:
      - type: email
        recipients:
          - security-team@company.com
      - type: slack
        webhook: https://hooks.slack.com/services/XXX
      - type: syslog
        endpoint: siem.company.com:514
        
  logging:
    enabled: true
    detailedAudit: true
    retainLogs: 90d
```

Apply Policy:
```bash
# Via Console UI
# Navigate to: Defend > WAAS > In-line > Add Rule

# Via API
curl -k -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @pilot-waas-policy.json \
  https://console.company.com/api/v1/policies/firewall/app/container
```

3. Baseline Establishment:

Monitor for 7-14 days to establish normal traffic patterns:

```bash
# Query WAAS events
curl -k -X GET \
  -H "Authorization: Bearer $TOKEN" \
  "https://console.company.com/api/v1/audits/firewall/app/container?limit=1000" \
  | jq '.[] | select(.effect == "alert")'

# Generate baseline report
prisma-cloud-cli waas generate-baseline \
  --application customer-portal-api \
  --period 14d \
  --output baseline-report.json
```

4. Training Sessions:

Conduct training for security team covering:
- WAAS Console navigation
- Policy configuration
- Alert investigation
- Incident response procedures
- API documentation

Deliverables:
- [ ] Defenders deployed to pilot apps
- [ ] Baseline policies configured
- [ ] Alert channels configured
- [ ] Baseline traffic report
- [ ] Team training completed
- [ ] Runbook documentation

---

# 6.3 Phase 3: Policy Tuning (Weeks 5-8)

Objectives:
- Analyze baseline data
- Reduce false positives
- Implement custom rules
- Optimize performance

Activities:

1. False Positive Analysis:

```bash
# Export WAAS alerts for analysis
curl -k -X GET \
  -H "Authorization: Bearer $TOKEN" \
  "https://console.company.com/api/v1/audits/firewall/app/container?from=$(date -d '7 days ago' +%s)000" \
  | jq -r '.[] | [.time, .effect, .attackType, .url, .sourceIP] | @csv' \
  > waas-alerts-7days.csv

# Identify top false positives
cat waas-alerts-7days.csv | cut -d',' -f3,4 | sort | uniq -c | sort -rn | head -20
```

2. Custom Exception Rules:

```yaml
# exceptions-policy.yaml
exceptions:
  - name: allow-admin-scanner
    description: Allow Qualys vulnerability scanner
    scope:
      sourceIPs:
        - 64.39.96.0/20
        - 64.39.112.0/20
    effect: allow
    
  - name: allow-health-checks
    description: Allow load balancer health checks
    scope:
      paths:
        - /health
        - /healthz
        - /ready
      userAgents:
        - "ELB-HealthChecker*"
        - "GoogleHC*"
    effect: allow
    
  - name: allow-legitimate-bot
    description: Allow Google Search bot
    scope:
      userAgents:
        - "Googlebot"
    validation:
      verifyDNS: true
      verifyIP: true
    effect: allow
```

3. Custom Detection Rules:

```yaml
customRules:
  - name: detect-api-key-in-url
    description: Detect API keys exposed in URL parameters
    pattern: "[?&]api[_-]?key=[a-zA-Z0-9]{20,}"
    scope: url
    action: block
    severity: high
    
  - name: detect-sql-injection-advanced
    description: Advanced SQL injection patterns
    pattern: "(?i)(union.*select|select.*from|insert.*into|delete.*from|update.*set|drop.*table)"
    scope: body
    action: prevent
    severity: critical
    
  - name: detect-sensitive-data-exposure
    description: Detect credit card numbers in responses
    pattern: "\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b"
    scope: response
    action: alert
    severity: high
    
  - name: rate-limit-expensive-endpoint
    description: Strict rate limit for ML inference
    scope:
      paths:
        - /api/v2/ml/inference
    rateLimit:
      limit: 10
      period: 1m
    action: ban
    banDuration: 10m
```

4. Performance Optimization:

Monitor and optimize WAAS performance:

```bash
# Check defender resource usage
kubectl top pods -n twistlock

# Analyze request latency
curl -k -X GET \
  -H "Authorization: Bearer $TOKEN" \
  "https://console.company.com/api/v1/stats/app/timeseries?from=-24h" \
  | jq '.data[] | {time, avgLatency}'

# Optimize rules based on performance
# - Consolidate similar rules
# - Use more specific patterns
# - Disable unused protection modules
```

Performance Targets:
- Latency overhead: <5ms (P95)
- CPU overhead: <10%
- Memory overhead: <100MB per defender
- False positive rate: <5%

5. Gradual Enforcement:

```yaml
# Phase 3A: Enable blocking for critical threats
protectionMode: prevent
highRiskActions:
  sqli: prevent
  cmdi: prevent
  lfi: prevent
  codeInjection: prevent
  
mediumRiskActions:
  xss: alert
  shellshock: alert
  attackTools: alert

# Phase 3B: Enable API protection
apiProtection:
  schemaValidation: prevent
  bola: prevent
  excessiveDataExposure: alert

# Phase 3C: Enable rate limiting
rateLimiting:
  enabled: true
  action: ban
```

Deliverables:
- [ ] False positive analysis report
- [ ] Custom exception rules documented
- [ ] Custom detection rules implemented
- [ ] Performance optimization report
- [ ] Updated policy configurations
- [ ] Tuning playbook

---

# 6.4 Phase 4: Production Rollout (Weeks 9-12)

Objectives:
- Deploy to all production applications
- Enable full enforcement mode
- Establish operational procedures
- Implement automated response

Activities:

1. Phased Rollout Plan:

| Week | Applications | Risk Level | Mode |
|------|--------------|------------|------|
| 9 | Internal APIs | Low | Alert |
| 10 | Customer APIs (read-only) | Medium | Mixed |
| 11 | Customer APIs (write) | High | Mixed |
| 12 | Payment/Critical APIs | Critical | Prevent |

2. Production Policy Template:

```yaml
# production-waas-policy.yaml
apiVersion: waas.prismacloud.io/v1
kind: WAASPolicy
metadata:
  name: production-api-protection
  labels:
    environment: production
    criticality: high
    
spec:
  appScope:
    applications: ["*"]
    environments: ["production"]
    labels:
      waas-protection: enabled
      
  protectionMode: prevent
  
  rulesets:
    - name: critical-protection
      priority: 1
      applicationMatch:
        criticality: [critical, high]
        
      httpProtection:
        enabled: true
        sqli: prevent
        xss: prevent
        attackTools: prevent
        shellshock: prevent
        malformedRequest: prevent
        cmdi: prevent
        lfi: prevent
        codeInjection: prevent
        xxe: prevent
        
      apiProtection:
        enabled: true
        mode: enforce
        discovery: true
        schemaValidation: prevent
        bola: prevent
        bfla: prevent
        excessiveDataExposure: prevent
        resourceConsumption: prevent
        ssrf: prevent
        
      authentication:
        jwt:
          enabled: true
          strictValidation: true
          enforce: true
        oauth:
          enabled: true
          validateScopes: true
          
      authorization:
        objectLevel: prevent
        functionLevel: prevent
        
      rateLimiting:
        