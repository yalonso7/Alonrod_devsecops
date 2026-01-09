Prisma Cloud DSPM (Data Security Posture Management) Configuration Guide

Comprehensive Step-by-Step SOP for Cloud Data Protection

1\. DSPM ARCHITECTURE & CORE CONCEPTS

1.1 DSPM Data Protection Framework

\`\`\`  
Prisma Cloud DSPM \= Data Discovery \+ Classification \+ Risk Assessment \+ Protection  
                   ↓  
├── \*\*Data Discovery Engine\*\*  
│   ├→ Storage Discovery: S3, RDS, DynamoDB, Blob Storage, BigQuery  
│   ├→ Database Discovery: MySQL, PostgreSQL, SQL Server, MongoDB  
│   └→ File Share Discovery: EFS, FSx, Azure Files  
├── \*\*Classification Engine\*\*  
│   ├→ Pattern Matching: Regex, Keywords  
│   ├→ ML-based: Contextual Analysis  
│   └→ Custom Classifiers: Business-specific  
├── \*\*Risk Assessment Engine\*\*  
│   ├→ Exposure Analysis: Public/External access  
│   ├→ Compliance Mapping: GDPR, PCI, HIPAA  
│   └→ Data Flow Mapping: Lineage tracking  
└── \*\*Protection Engine\*\*  
    ├→ Encryption Assessment  
    ├→ Access Control Analysis  
    └→ Remediation Automation  
\`\`\`

1.2 Data Classification Taxonomy

\`\`\`yaml  
data\_classification\_framework:  
    
  sensitivity\_levels:  
    \- level: "Restricted"  
      examples:  
        \- Encryption Keys  
        \- API Secrets  
        \- SSH Private Keys  
      handling\_requirements:  
        \- encryption: required  
        \- access\_logging: required  
        \- retention: 7 years  
          
    \- level: "Confidential"  
      examples:  
        \- PII: SSN, Passport, Driver's License  
        \- Financial: Credit Cards, Bank Accounts  
        \- Health: Medical Records, PHI  
      handling\_requirements:  
        \- encryption: required  
        \- access\_control: strict  
        \- mask\_in\_logs: yes  
          
    \- level: "Internal"  
      examples:  
        \- Employee IDs  
        \- Internal Communications  
        \- Project Documentation  
      handling\_requirements:  
        \- encryption: recommended  
        \- access\_control: role-based  
          
    \- level: "Public"  
      examples:  
        \- Marketing Materials  
        \- Published Documentation  
        \- Open Source Code  
      handling\_requirements:  
        \- encryption: optional  
        \- access\_control: minimal  
\`\`\`

2\. PRE-IMPLEMENTATION ASSESSMENT

Step 1: Data Inventory & Discovery Planning

\`\`\`  
✅ Prerequisites Checklist:  
☐ Prisma Cloud Enterprise License with DSPM  
☐ Required Cloud Permissions:  
   \- AWS: s3:List\*, rds:Describe\*, dynamodb:List\*  
   \- Azure: Storage Blob Data Reader, SQL DB Contributor  
   \- GCP: BigQuery Data Viewer, Cloud SQL Viewer  
☐ Network Access:  
   \- Outbound to cloud APIs  
   \- VPC endpoints for private access  
☐ Storage Considerations:  
   \- 100GB+ for metadata storage  
   \- Encryption keys for sensitive data  
☐ Compliance Requirements:  
   \- GDPR Article 30 (Records of Processing)  
   \- PCI DSS Requirement 3 (Protect Cardholder Data)  
   \- HIPAA Security Rule (PHI Protection)  
\`\`\`

Step 2: Data Governance Framework Definition

\`\`\`yaml  
\# data-governance-policy.yaml  
data\_governance:  
  data\_owners:  
    finance\_data:  
      owner: "finance-director@company.com"  
      steward: "data-analyst-finance@company.com"  
      classification: "Confidential"  
        
    customer\_data:  
      owner: "cio@company.com"  
      steward: "data-protection-officer@company.com"  
      classification: "Restricted"  
        
    employee\_data:  
      owner: "hr-director@company.com"  
      steward: "hr-analytics@company.com"  
      classification: "Confidential"  
    
  retention\_policies:  
    customer\_pii:  
      retention\_period: "7y"  
      legal\_hold: true  
      disposal\_method: "secure\_deletion"  
        
    financial\_records:  
      retention\_period: "10y"  
      legal\_hold: true  
      disposal\_method: "archival"  
        
    application\_logs:  
      retention\_period: "1y"  
      legal\_hold: false  
      disposal\_method: "deletion"  
    
  geographic\_restrictions:  
    eu\_citizen\_data:  
      storage\_regions: \["eu-west-1", "eu-central-1"\]  
      processing\_regions: \["EU"\]  
      transfer\_restrictions: true  
        
    healthcare\_data:  
      storage\_regions: \["us-east-1", "us-west-2"\]  
      processing\_regions: \["US"\]  
      hipaa\_compliant: true  
\`\`\`

3\. DSPM INITIAL CONFIGURATION

Step 3: Enable DSPM Module

\`\`\`  
1\. Navigate: Settings → Subscription → Features  
2\. Enable DSPM Module:  
   \- Toggle: Data Security Posture Management  
   \- License Validation: Verify  
   \- Save Configuration  
3\. Configure Data Collection:  
   \- Settings → Data Collection → DSPM  
   \- Scan Frequency:  
     \* Standard: 12 hours  
     \* Continuous: Real-time (requires CloudWatch/EventHub)  
   \- Scan Depth:  
     \* Metadata only (fast)  
     \* Sample data (recommended)  
     \* Full content (comprehensive)  
   \- Storage Regions: All regions  
4\. Enable Advanced Features:  
   \- Data Lineage Tracking: ✓  
   \- Cross-cloud Data Flow: ✓  
   \- ML-based Classification: ✓  
   \- Anomaly Detection: ✓  
\`\`\`

Step 4: Configure Cloud Data Sources

AWS Data Source Configuration:

\`\`\`bash  
\#\!/bin/bash  
\# aws-dspm-setup.sh  
ACCOUNT\_ID=$(aws sts get-caller-identity \--query Account \--output text)

\# Create DSPM IAM Role  
aws iam create-role \\  
  \--role-name PrismaCloud-DSPM-Role \\  
  \--assume-role-policy-document '{  
    "Version": "2012-10-17",  
    "Statement": \[{  
      "Effect": "Allow",  
      "Principal": {  
        "AWS": "arn:aws:iam::\<prisma-account-id\>:root"  
      },  
      "Action": "sts:AssumeRole",  
      "Condition": {  
        "StringEquals": {  
          "sts:ExternalId": "\<unique-external-id\>"  
        }  
      }  
    }\]  
  }'

\# Attach DSPM Permissions Policy  
cat \> dspm-policy.json \<\< EOF  
{  
  "Version": "2012-10-17",  
  "Statement": \[  
    {  
      "Sid": "StorageReadAccess",  
      "Effect": "Allow",  
      "Action": \[  
        "s3:List\*",  
        "s3:GetObject",  
        "s3:GetBucketPolicy",  
        "s3:GetBucketEncryption",  
        "s3:GetBucketPublicAccessBlock"  
      \],  
      "Resource": "\*"  
    },  
    {  
      "Sid": "DatabaseReadAccess",  
      "Effect": "Allow",  
      "Action": \[  
        "rds:Describe\*",  
        "rds:ListTagsForResource",  
        "dynamodb:ListTables",  
        "dynamodb:DescribeTable",  
        "dynamodb:GetItem"  
      \],  
      "Resource": "\*"  
    },  
    {  
      "Sid": "LogAccess",  
      "Effect": "Allow",  
      "Action": \[  
        "logs:DescribeLogGroups",  
        "logs:FilterLogEvents"  
      \],  
      "Resource": "\*"  
    }  
  \]  
}  
EOF

aws iam put-role-policy \\  
  \--role-name PrismaCloud-DSPM-Role \\  
  \--policy-name DSPM-ReadAccess \\  
  \--policy-document file://dspm-policy.json

\# Enable S3 Inventory for large buckets  
aws s3api put-bucket-inventory-configuration \\  
  \--bucket large-data-bucket \\  
  \--id DSPM-Inventory \\  
  \--inventory-configuration '{  
    "Destination": {  
      "S3BucketDestination": {  
        "Bucket": "arn:aws:s3:::dspm-inventory-bucket",  
        "Format": "CSV"  
      }  
    },  
    "IsEnabled": true,  
    "Id": "DSPM-Inventory",  
    "IncludedObjectVersions": "Current",  
    "Schedule": {  
      "Frequency": "Daily"  
    }  
  }'  
\`\`\`

Azure Data Source Configuration:

\`\`\`powershell  
\# Configure Azure DSPM Permissions  
Connect-AzAccount

\# Create Service Principal for DSPM  
$sp \= New-AzADServicePrincipal \-DisplayName "PrismaCloud-DSPM"

\# Assign Reader Role at Subscription Level  
New-AzRoleAssignment \`  
  \-ObjectId $sp.Id \`  
  \-RoleDefinitionName "Reader" \`  
  \-Scope "/subscriptions/$subscriptionId"

\# Assign Storage Blob Data Reader  
New-AzRoleAssignment \`  
  \-ObjectId $sp.Id \`  
  \-RoleDefinitionName "Storage Blob Data Reader" \`  
  \-Scope "/subscriptions/$subscriptionId"

\# Assign SQL Security Manager  
New-AzRoleAssignment \`  
  \-ObjectId $sp.Id \`  
  \-RoleDefinitionName "SQL Security Manager" \`  
  \-Scope "/subscriptions/$subscriptionId"

\# Enable Diagnostic Settings for Storage Accounts  
$storageAccounts \= Get-AzStorageAccount  
foreach ($sa in $storageAccounts) {  
  Set-AzDiagnosticSetting \`  
    \-ResourceId $sa.Id \`  
    \-Enabled $true \`  
    \-Category "StorageRead" \`  
    \-RetentionEnabled $true \`  
    \-RetentionInDays 90  
}  
\`\`\`

Step 5: Initial Data Discovery Scan

\`\`\`python  
\# initial-discovery-scan.py  
import prismacloud.dspm as dspm  
from datetime import datetime, timedelta

client \= dspm.DataSecurityClient(tenant='\<tenant\>.prismacloud.io')

\# Configure initial discovery scan  
scan\_config \= {  
    "scan\_type": "full\_discovery",  
    "cloud\_providers": \["aws", "azure", "gcp"\],  
    "resource\_types": \[  
        "s3", "rds", "dynamodb", "redshift",  
        "blob\_storage", "sql\_database", "cosmos\_db",  
        "bigquery", "cloud\_sql", "cloud\_storage"  
    \],  
    "sampling\_strategy": {  
        "enabled": True,  
        "sample\_size": 1000,  \# records per table/bucket  
        "confidence\_level": 0.95  
    },  
    "classification\_rules": "all\_built\_in",  
    "schedule": {  
        "immediate": True,  
        "recurring": "12h"  
    }  
}

\# Start discovery scan  
scan\_job \= client.start\_discovery\_scan(config=scan\_config)

\# Monitor progress  
while not scan\_job.completed:  
    progress \= client.get\_scan\_progress(scan\_job.id)  
    print(f"Progress: {progress.percent\_complete}%")  
    print(f"Resources discovered: {progress.resources\_discovered}")  
    print(f"Data classified: {progress.data\_classified\_gb} GB")  
    time.sleep(60)

\# Generate discovery report  
report \= client.generate\_discovery\_report(  
    scan\_id=scan\_job.id,  
    formats=\["pdf", "csv", "json"\],  
    sections=\["executive\_summary", "data\_inventory", "risk\_assessment"\]  
)

print(f"Discovery completed. Total data assets: {report.total\_assets}")  
print(f"Sensitive data found: {report.sensitive\_data\_count} items")  
\`\`\`

4\. DATA CLASSIFICATION CONFIGURATION

Step 6: Configure Built-in Classifiers

\`\`\`  
1\. Navigate: Data Security → Classification → Built-in Classifiers  
2\. Enable Standard Classifiers:

   A. \*\*PII (Personally Identifiable Information):\*\*  
      \- Social Security Numbers (SSN): \\d{3}-\\d{2}-\\d{4}  
      \- Credit Card Numbers: \\d{4}\[- \]?\\d{4}\[- \]?\\d{4}\[- \]?\\d{4}  
      \- Email Addresses: \[\\w\\.-\]+@\[\\w\\.-\]+\\.\\w+  
      \- Phone Numbers: \\(\\d{3}\\) \\d{3}-\\d{4}  
        
   B. \*\*PHI (Protected Health Information):\*\*  
      \- Medical Record Numbers: MR\\d{6,8}  
      \- Health Insurance Numbers: HI\\d{9}  
      \- ICD Codes: \[A-Z\]\\d{2}\\.\\d{1,2}  
        
   C. \*\*Financial Information:\*\*  
      \- Bank Account Numbers: \\d{8,17}  
      \- SWIFT Codes: \[A-Z\]{6}\[A-Z0-9\]{2}(\[A-Z0-9\]{3})?  
      \- IBAN: \[A-Z\]{2}\\d{2}\[A-Z0-9\]{4}\\d{7}(\[A-Z0-9\]?){0,16}  
        
   D. \*\*Corporate Secrets:\*\*  
      \- API Keys: \[A-Za-z0-9\]{32,64}  
      \- Database Connection Strings: (jdbc|postgresql|mongodb)://  
      \- SSH Private Keys: \-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----  
        
3\. Configure Confidence Levels:  
   \- High confidence: 95% threshold  
   \- Medium confidence: 80% threshold  
   \- Low confidence: 60% threshold  
     
4\. Enable Contextual Analysis:  
   \- Column name analysis: "ssn", "credit\_card", "password"  
   \- Metadata analysis: Tags, descriptions  
   \- Neighboring data context  
\`\`\`

Step 7: Create Custom Classifiers

\`\`\`yaml  
\# custom-classifiers.yaml  
custom\_classifiers:  
    
  \- name: "employee\_internal\_id"  
    description: "Company-specific employee identifier format"  
    regex\_patterns:  
      \- "EMP-\\d{6}-\[A-Z\]{2}"  
      \- "EID\\d{8}"  
    confidence: 0.90  
    classification: "Internal"  
    applies\_to:  
      \- column\_names: \["employee\_id", "emp\_no", "staff\_id"\]  
      \- file\_names: \["\*employees\*", "\*staff\*", "\*hr\*"\]  
        
  \- name: "product\_sku\_format"  
    description: "Company product SKU format"  
    regex\_patterns:  
      \- "\[A-Z\]{3}-\\d{3}-\[A-Z\]{2}"  
    confidence: 0.85  
    classification: "Internal"  
    applies\_to:  
      \- table\_names: \["products", "inventory", "sku\*"\]  
        
  \- name: "api\_endpoint\_pattern"  
    description: "Internal API endpoint patterns"  
    regex\_patterns:  
      \- "/api/v\[0-9\]+/\[a-z\]+/\[0-9a-f\]{8}-"  
      \- "https://internal\\.api\\.company\\.com/"  
    confidence: 0.80  
    classification: "Internal"  
    applies\_to:  
      \- file\_types: \["json", "yaml", "properties"\]  
      \- column\_names: \["endpoint", "url", "service\_url"\]  
        
  \- name: "ml\_model\_config"  
    description: "Machine learning model configuration patterns"  
    regex\_patterns:  
      \- "model\_type: (xgboost|randomforest|neuralnetwork)"  
      \- "hyperparameters:"  
      \- "training\_data\_path:"  
    confidence: 0.75  
    classification: "Confidential"  
    applies\_to:  
      \- file\_types: \["yaml", "json", "py"\]  
      \- file\_names: \["\*model\*", "\*train\*", "\*config\*"\]  
\`\`\`

Step 8: Configure ML-based Classification

\`\`\`python  
\# ml-classification-config.py  
from prismacloud.dspm.ml import ClassificationModel

model\_config \= {  
    "model\_name": "contextual\_classifier\_v2",  
    "algorithm": "bert",  \# or "roberta", "distilbert"  
    "training\_data": {  
        "source": "labeled\_datasets",  
        "samples\_per\_class": 10000,  
        "validation\_split": 0.2  
    },  
    "features": \[  
        "column\_name",  
        "data\_type",  
        "surrounding\_columns",  
        "table\_description",  
        "data\_patterns",  
        "access\_patterns"  
    \],  
    "confidence\_thresholds": {  
        "restricted": 0.95,  
        "confidential": 0.85,  
        "internal": 0.70,  
        "public": 0.50  
    },  
    "continuous\_learning": {  
        "enabled": True,  
        "feedback\_loop": True,  
        "retraining\_schedule": "weekly"  
    }  
}

\# Train model with existing data  
classifier \= ClassificationModel(config=model\_config)  
classifier.train(  
    training\_data="s3://company-data/classified-samples/",  
    epochs=10,  
    batch\_size=32  
)

\# Deploy model for classification  
classifier.deploy(  
    environment="production",  
    scaling={  
        "min\_instances": 2,  
        "max\_instances": 10,  
        "target\_utilization": 0.7  
    }  
)  
\`\`\`

5\. DATA RISK ASSESSMENT CONFIGURATION

Step 9: Configure Data Risk Policies

\`\`\`sql  
\-- Built-in Risk Policy: Publicly Accessible Sensitive Data  
POLICY: "S3 Bucket with PII Publicly Accessible"  
SEVERITY: Critical  
RQL:   
config where cloud.type \= 'aws' and  
api.name \= 'aws-s3-get-bucket-acl' and  
json.rule \= "$.Grants\[?(  
  grantee.URI \== 'http://acs.amazonaws.com/groups/global/AllUsers' and  
  permission in \['READ', 'FULL\_CONTROL'\]  
)\] exists" and  
resource.data.classification contains 'PII'

\-- Built-in Risk Policy: Unencrypted Financial Data  
POLICY: "RDS Instance with Financial Data Unencrypted"  
SEVERITY: High  
RQL:  
config where cloud.type \= 'aws' and  
api.name \= 'aws-rds-describe-db-instances' and  
json.rule \= "storageEncrypted \== false" and  
resource.data.classification contains 'Financial'

\-- Built-in Risk Policy: Excessive Data Retention  
POLICY: "Data Retention Exceeds Policy"  
SEVERITY: Medium  
RQL:  
config where cloud.type \= 'azure' and  
api.name \= 'azure-storage-account-list' and  
json.rule \= "$.properties.policies.retention.days \> retention\_policy\_limit" and  
resource.data.classification in \['PII', 'PHI', 'Financial'\]  
\`\`\`

Step 10: Configure Data Exposure Analysis

\`\`\`yaml  
\# exposure-analysis-config.yaml  
exposure\_analysis:  
  enabled: true  
    
  public\_access\_analysis:  
    check\_types:  
      \- internet\_accessible: true  
      \- cross\_account\_access: true  
      \- public\_policy\_statements: true  
      \- anonymous\_access: true  
    risk\_scoring:  
      public\_internet: 100  
      cross\_account: 75  
      authenticated\_users: 50  
        
  data\_sharing\_analysis:  
    analyze:  
      \- third\_party\_sharing: true  
      \- data\_exports: true  
      \- api\_exposure: true  
    whitelist:  
      \- approved\_vendors: \["snowflake", "databricks", "tableau"\]  
      \- internal\_domains: \["\*.company.com"\]  
        
  access\_pattern\_analysis:  
    baseline\_period: "30d"  
    anomaly\_detection:  
      \- unusual\_access\_times: true  
      \- geographic\_anomalies: true  
      \- volume\_spikes: true  
      \- new\_user\_access: true  
    thresholds:  
      anomaly\_confidence: 0.85  
      risk\_score\_increase: 20  
        
  data\_flow\_mapping:  
    track:  
      \- ingress\_points: \["api\_gateways", "load\_balancers"\]  
      \- egress\_points: \["data\_exports", "api\_calls"\]  
      \- processing\_points: \["lambda", "emr", "databricks"\]  
    lineage\_depth: 3  \# levels of dependency  
\`\`\`

Step 11: Configure Compliance Mapping

\`\`\`python  
\# compliance-mapping.py  
from prismacloud.dspm.compliance import ComplianceMapper

mapper \= ComplianceMapper()

\# Map data classifications to compliance requirements  
compliance\_mappings \= {  
    "GDPR": {  
        "article\_30": {  
            "data\_elements": \["PII", "Personal Data"\],  
            "requirements": \["inventory", "processing\_records"\],  
            "controls": \["data\_classification", "access\_logging"\]  
        },  
        "article\_32": {  
            "data\_elements": \["Special Categories"\],  
            "requirements": \["security\_measures"\],  
            "controls": \["encryption", "access\_control", "pseudonymization"\]  
        }  
    },  
      
    "PCI\_DSS": {  
        "requirement\_3": {  
            "data\_elements": \["Credit Card Numbers", "CVV", "Track Data"\],  
            "requirements": \["encryption", "masking", "key\_management"\],  
            "controls": \["encryption\_at\_rest", "encryption\_in\_transit", "key\_rotation"\]  
        }  
    },  
      
    "HIPAA": {  
        "security\_rule": {  
            "data\_elements": \["PHI", "Medical Records"\],  
            "requirements": \["access\_control", "audit\_controls", "integrity"\],  
            "controls": \["role\_based\_access", "activity\_logging", "data\_integrity"\]  
        }  
    }  
}

\# Apply compliance mappings  
for framework, requirements in compliance\_mappings.items():  
    mapper.map\_framework(  
        framework=framework,  
        requirements=requirements,  
        data\_sources="all\_discovered"  
    )

\# Generate compliance gap analysis  
gap\_analysis \= mapper.analyze\_compliance\_gaps()  
print(f"GDPR Compliance: {gap\_analysis.gdpr.compliance\_percentage}%")  
print(f"PCI DSS Compliance: {gap\_analysis.pci.compliance\_percentage}%")  
print(f"HIPAA Compliance: {gap\_analysis.hipaa.compliance\_percentage}%")  
\`\`\`

6\. DATA PROTECTION & REMEDIATION

Step 12: Configure Auto-Remediation Policies

\`\`\`yaml  
\# auto-remediation-policies.yaml  
remediation\_policies:  
    
  encryption\_remediation:  
    \- name: "auto\_enable\_s3\_encryption"  
      trigger: "s3\_bucket\_unencrypted\_with\_sensitive\_data"  
      conditions:  
        \- data\_classification: \["Restricted", "Confidential"\]  
        \- encryption\_status: "disabled"  
      actions:  
        \- step\_1:  
            action: "enable\_sse\_s3"  
            parameters:  
              algorithm: "AES256"  
            dry\_run\_first: true  
        \- step\_2:  
            action: "notify\_data\_owner"  
            parameters:  
              template: "encryption\_enabled\_notification"  
        \- step\_3:  
            action: "update\_cmdb"  
            parameters:  
              field: "encryption\_status"  
              value: "enabled"  
                
  access\_control\_remediation:  
    \- name: "remove\_public\_access\_from\_sensitive\_bucket"  
      trigger: "s3\_bucket\_public\_with\_pii"  
      conditions:  
        \- public\_access: true  
        \- data\_classification: \["PII", "PHI"\]  
      actions:  
        \- step\_1:  
            action: "block\_public\_access"  
            parameters:  
              block\_public\_acls: true  
              block\_public\_policy: true  
        \- step\_2:  
            action: "remove\_public\_grants"  
        \- step\_3:  
            action: "enable\_access\_logging"  
              
  retention\_remediation:  
    \- name: "apply\_retention\_policy\_to\_old\_data"  
      trigger: "data\_retention\_violation"  
      conditions:  
        \- data\_age: "\> retention\_policy\_limit"  
        \- legal\_hold: false  
      actions:  
        \- step\_1:  
            action: "notify\_data\_owner\_retention"  
            parameters:  
              days\_before\_action: 30  
        \- step\_2:  
            action: "apply\_glacier\_transition"  
            parameters:  
              transition\_days: 365  
              storage\_class: "GLACIER"  
        \- step\_3:  
            action: "apply\_expiration"  
            parameters:  
              expiration\_days: 1095  \# 3 years  
\`\`\`

Step 13: Configure Data Masking & Tokenization

\`\`\`python  
\# data-masking-configuration.py  
from prismacloud.dspm.protection import DataMaskingEngine

masking\_config \= {  
    "masking\_strategies": {  
        "full\_masking": {  
            "method": "fixed\_string",  
            "mask\_character": "\*",  
            "preserve\_length": True  
        },  
        "partial\_masking": {  
            "method": "partial",  
            "unmasked\_first": 4,  
            "unmasked\_last": 4,  
            "mask\_character": "\*"  
        },  
        "hash\_masking": {  
            "method": "hash",  
            "algorithm": "sha256",  
            "salt": "company\_specific\_salt"  
        },  
        "encryption\_masking": {  
            "method": "encryption",  
            "algorithm": "aes-256-gcm",  
            "key\_id": "kms\_key\_arn"  
        }  
    },  
      
    "classification\_masking\_rules": {  
        "Restricted": {  
            "methods": \["encryption\_masking", "hash\_masking"\],  
            "environments": {  
                "production": "encryption\_masking",  
                "staging": "hash\_masking",  
                "development": "partial\_masking"  
            }  
        },  
        "Confidential": {  
            "methods": \["partial\_masking", "hash\_masking"\],  
            "environments": {  
                "production": "partial\_masking",  
                "non\_production": "full\_masking"  
            }  
        },  
        "Internal": {  
            "methods": \["partial\_masking"\],  
            "environments": {  
                "all": "partial\_masking"  
            }  
        }  
    },  
      
    "auto\_apply\_scenarios": {  
        "non\_production\_copies": True,  
        "analytics\_environment": True,  
        "developer\_access": True,  
        "third\_party\_sharing": True  
    }  
}

\# Initialize masking engine  
masking\_engine \= DataMaskingEngine(config=masking\_config)

\# Apply masking to sensitive data  
masking\_job \= masking\_engine.apply\_masking(  
    data\_source="s3://customer-data/prod/",  
    target\_environment="analytics",  
    classification\_level="Confidential"  
)  
\`\`\`

Step 14: Configure Data Loss Prevention (DLP)

\`\`\`yaml  
\# dlp-policies.yaml  
dlp\_policies:  
    
  detection\_policies:  
    \- name: "pii\_exfiltration\_detection"  
      description: "Detect PII leaving the organization"  
      conditions:  
        \- data\_classification: \["PII", "PHI", "Financial"\]  
        \- destination:  
            \- external\_domains: true  
            \- personal\_email\_providers: true  
            \- unauthorized\_cloud\_storage: true  
        \- volume\_threshold: "\> 100 records"  
      actions:  
        \- block\_transfer: true  
        \- alert\_security\_team: true  
        \- quarantine\_data: true  
        \- notify\_data\_owner: true  
          
    \- name: "source\_code\_leak\_detection"  
      description: "Detect source code leaving via email/cloud"  
      conditions:  
        \- file\_types: \[".py", ".java", ".js", ".go", ".cpp"\]  
        \- file\_size: "\> 1MB"  
        \- destination: external  
      actions:  
        \- block\_transfer: true  
        \- alert\_engineering\_lead: true  
        \- scan\_for\_secrets: true  
          
  prevention\_policies:  
    \- name: "prevent\_unencrypted\_data\_transfer"  
      description: "Block transfer of unencrypted sensitive data"  
      conditions:  
        \- data\_classification: \["Restricted", "Confidential"\]  
        \- encryption\_status: "unencrypted"  
        \- transfer\_method: \["s3\_copy", "database\_export", "api\_call"\]  
      actions:  
        \- block\_transfer: true  
        \- require\_encryption: true  
        \- log\_attempt: true  
          
  monitoring\_policies:  
    \- name: "monitor\_data\_sharing\_with\_third\_parties"  
      description: "Monitor and log data shared with vendors"  
      conditions:  
        \- destination\_domain: \["vendor1.com", "vendor2.com"\]  
        \- data\_volume: "\> 1GB per day"  
      actions:  
        \- enable\_audit\_logging: true  
        \- periodic\_review: "weekly"  
        \- require\_business\_approval: true  
\`\`\`

7\. DATA LINEAGE & FLOW MAPPING

Step 15: Configure Data Lineage Tracking

\`\`\`python  
\# data-lineage-config.py  
from prismacloud.dspm.lineage import DataLineageTracker

lineage\_config \= {  
    "tracking\_depth": 5,  \# Levels of dependency  
    "capture\_frequency": "hourly",  
    "storage\_backend": "neptune",  \# or "elasticsearch", "snowflake"  
      
    "extraction\_methods": {  
        "etl\_jobs": {  
            "glue\_jobs": True,  
            "emr\_steps": True,  
            "databricks\_jobs": True,  
            "airflow\_dags": True  
        },  
        "database\_operations": {  
            "dml\_statements": True,  
            "stored\_procedures": True,  
            "etl\_processes": True  
        },  
        "api\_calls": {  
            "rest\_apis": True,  
            "graphql": True,  
            "grpc": True  
        }  
    },  
      
    "lineage\_rules": {  
        "propagate\_classification": True,  
        "track\_transformations": True,  
        "capture\_data\_quality\_metrics": True,  
        "link\_business\_metadata": True  
    }  
}

\# Initialize lineage tracker  
tracker \= DataLineageTracker(config=lineage\_config)

\# Start lineage capture  
tracker.start\_capture(  
    data\_sources=\["all\_discovered"\],  
    real\_time=True,  
    historical\_backfill=True  
)

\# Query lineage  
lineage \= tracker.query\_lineage(  
    data\_element="s3://customer-data/transactions.csv",  
    direction="both",  \# upstream and downstream  
    max\_depth=3  
)

print(f"Upstream sources: {lineage.upstream\_count}")  
print(f"Downstream consumers: {lineage.downstream\_count}")  
print(f"Transformation steps: {lineage.transformation\_steps}")  
\`\`\`

Step 16: Configure Data Flow Analytics

\`\`\`yaml  
\# data-flow-analytics.yaml  
flow\_analytics:  
  enabled: true  
    
  ingress\_points:  
    \- type: "api\_gateway"  
      monitor: true  
      classify\_incoming: true  
        
    \- type: "file\_upload"  
      monitor: true  
      scan\_for\_sensitive\_data: true  
        
    \- type: "database\_replication"  
      monitor: true  
      validate\_encryption: true  
        
  processing\_points:  
    \- type: "etl\_jobs"  
      track\_transformations: true  
      monitor\_classification\_changes: true  
        
    \- type: "ml\_pipelines"  
      track\_data\_usage: true  
      monitor\_model\_training: true  
        
    \- type: "stream\_processing"  
      real\_time\_monitoring: true  
      alert\_on\_anomalies: true  
        
  egress\_points:  
    \- type: "data\_exports"  
      require\_approval: true  
      enforce\_encryption: true  
        
    \- type: "api\_responses"  
      mask\_sensitive\_data: true  
      rate\_limit: true  
        
    \- type: "reports"  
      apply\_watermarking: true  
      track\_distribution: true  
      
  anomaly\_detection:  
    baseline\_period: "30d"  
    detect:  
      \- unusual\_data\_volumes: true  
      \- new\_data\_paths: true  
      \- classification\_drift: true  
      \- access\_pattern\_changes: true  
    alert\_thresholds:  
      volume\_change: "\> 200%"  
      new\_consumers: "\> 3"  
      classification\_drift: "\> 10%"  
\`\`\`

8\. MONITORING & ALERTING CONFIGURATION

Step 17: Configure DSPM Alerts

\`\`\`yaml  
\# dspm-alert-config.yaml  
alerts:  
    
  critical\_alerts:  
    \- name: "public\_exposure\_of\_sensitive\_data"  
      conditions:  
        \- data\_classification: \["Restricted", "Confidential"\]  
        \- exposure\_level: "public\_internet"  
        \- data\_volume: "\> 100 records"  
      actions:  
        \- page\_oncall\_security: true  
        \- auto\_remediate: true  
        \- create\_incident: true  
        \- notify\_ciso: true  
          
    \- name: "data\_exfiltration\_attempt"  
      conditions:  
        \- sensitive\_data: true  
        \- destination: "external"  
        \- bypass\_attempt: true  
      actions:  
        \- block\_immediately: true  
        \- isolate\_source: true  
        \- forensic\_capture: true  
        \- legal\_notification: true  
          
  high\_alerts:  
    \- name: "unencrypted\_sensitive\_data"  
      conditions:  
        \- data\_classification: \["Restricted", "Confidential"\]  
        \- encryption\_status: "disabled"  
        \- environment: "production"  
      actions:  
        \- notify\_data\_owner: true  
        \- auto\_enable\_encryption: true  
        \- security\_review: true  
          
    \- name: "excessive\_data\_retention"  
      conditions:  
        \- data\_age: "\> policy\_limit"  
        \- data\_classification: \["PII", "PHI"\]  
        \- legal\_hold: false  
      actions:  
        \- notify\_legal\_team: true  
        \- schedule\_deletion: true  
        \- compliance\_audit: true  
          
  medium\_alerts:  
    \- name: "new\_sensitive\_data\_discovered"  
      conditions:  
        \- new\_classification: true  
        \- data\_classification: \["PII", "PHI", "Financial"\]  
        \- no\_owner\_assigned: true  
      actions:  
        \- assign\_review\_task: true  
        \- notify\_data\_governance: true  
        \- update\_inventory: true  
          
  monitoring\_alerts:  
    \- name: "data\_classification\_drift"  
      conditions:  
        \- classification\_changes: "\> 10%"  
        \- time\_period: "24h"  
      actions:  
        \- review\_classification\_rules: true  
        \- notify\_data\_analysts: true  
        \- adjust\_thresholds: true  
\`\`\`

Step 18: Configure DSPM Dashboards

\`\`\`python  
\# dspm-dashboard-config.py  
from prismacloud.dspm.dashboard import DashboardBuilder

\# Create Executive Dashboard  
executive\_dashboard \= DashboardBuilder.create\_dashboard(  
    name="Data Security Executive View",  
    type="executive",  
    widgets=\[  
        {  
            "type": "risk\_score",  
            "title": "Overall Data Risk Score",  
            "size": "large",  
            "refresh\_interval": "1h"  
        },  
        {  
            "type": "sensitive\_data\_inventory",  
            "title": "Sensitive Data by Classification",  
            "size": "medium",  
            "group\_by": \["classification", "cloud\_provider"\]  
        },  
        {  
            "type": "compliance\_status",  
            "title": "Compliance Framework Status",  
            "size": "medium",  
            "frameworks": \["GDPR", "PCI\_DSS", "HIPAA", "SOX"\]  
        },  
        {  
            "type": "top\_risks",  
            "title": "Top 10 Data Risks",  
            "size": "large",  
            "sort\_by": "severity"  
        },  
        {  
            "type": "remediation\_progress",  
            "title": "Remediation Progress",  
            "size": "medium",  
            "time\_range": "30d"  
        }  
    \]  
)

\# Create Operational Dashboard  
operational\_dashboard \= DashboardBuilder.create\_dashboard(  
    name="Data Security Operations",  
    type="operational",  
    widgets=\[  
        {  
            "type": "active\_alerts",  
            "title": "Active Alerts by Severity",  
            "size": "medium",  
            "refresh\_interval": "5m"  
        },  
        {  
            "type": "data\_discovery\_status",  
            "title": "Discovery Scan Status",  
            "size": "small",  
            "show\_last\_scan": True  
        },  
        {  
            "type": "data\_flow\_map",  
            "title": "Critical Data Flows",  
            "size": "large",  
            "interactive": True  
        },  
        {  
            "type": "classification\_accuracy",  
            "title": "Classification Performance",  
            "size": "small",  
            "metrics": \["precision", "recall", "f1\_score"\]  
        },  
        {  
            "type": "dlp\_events",  
            "title": "DLP Events Timeline",  
            "size": "medium",  
            "time\_range": "24h"  
        }  
    \]  
)

\# Deploy dashboards  
executive\_dashboard.deploy(  
    access\_roles=\["executive", "security\_lead", "compliance"\]  
)  
operational\_dashboard.deploy(  
    access\_roles=\["security\_analyst", "data\_engineer", "soc\_analyst"\]  
)  
\`\`\`

9\. INTEGRATION CONFIGURATION

Step 19: Configure SIEM Integration

\`\`\`yaml  
\# siem-integration.yaml  
siem\_integrations:  
    
  splunk:  
    enabled: true  
    endpoint: "https://splunk.company.com:8088"  
    token: "\<hec-token\>"  
    log\_types:  
      \- data\_discovery\_events  
      \- classification\_events  
      \- risk\_assessment\_results  
      \- remediation\_actions  
      \- dlp\_events  
    format: "cef"  
    fields\_mapping:  
      data\_classification: "classification"  
      data\_source: "source"  
      risk\_score: "risk"  
        
  elastic:  
    enabled: true  
    endpoint: "https://elastic.company.com:9200"  
    index\_pattern: "prisma-dspm-\*"  
    pipeline: "dspm-processor"  
    data\_streams:  
      \- "dspm\_alerts"  
      \- "dspm\_metrics"  
      \- "dspm\_discovery"  
        
  qradar:  
    enabled: true  
    endpoint: "https://qradar.company.com"  
    protocol: "syslog"  
    port: 514  
    facility: "local4"  
      
  sentinel:  
    enabled: true  
    workspace\_id: "\<workspace-id\>"  
    shared\_key: "\<shared-key\>"  
    log\_type: "PrismaCloudDSPM\_CL"  
\`\`\`

Step 20: Configure Data Catalog Integration

\`\`\`python  
\# data-catalog-integration.py  
from prismacloud.dspm.integrations import DataCatalogConnector

\# AWS Glue Data Catalog Integration  
glue\_integration \= DataCatalogConnector(  
    catalog\_type="aws\_glue",  
    region="us-east-1",  
    database\_filter="\*"  \# All databases  
)

\# Sync DSPM metadata to Glue  
sync\_job \= glue\_integration.sync\_metadata(  
    dspm\_data="all\_classified",  
    sync\_direction="bidirectional",  
    fields\_to\_sync=\[  
        "data\_classification",  
        "sensitivity\_level",  
        "pii\_fields",  
        "encryption\_status",  
        "data\_owner",  
        "retention\_policy"  
    \]  
)

\# Collibra Integration  
collibra\_integration \= DataCatalogConnector(  
    catalog\_type="collibra",  
    endpoint="https://collibra.company.com",  
    api\_key="\<collibra-api-key\>"  
)

\# Create business glossary entries  
glossary\_entries \= collibra\_integration.create\_glossary\_entries(  
    data\_assets=dspm\_client.get\_data\_assets(),  
    community="Data Security",  
    domain="Sensitive Data Management"  
)

\# Alation Integration  
alation\_integration \= DataCatalogConnector(  
    catalog\_type="alation",  
    endpoint="https://alation.company.com",  
    token="\<alation-token\>"  
)

\# Enrich existing catalog with DSPM findings  
enrichment\_job \= alation\_integration.enrich\_catalog(  
    dspm\_findings="all",  
    overwrite\_fields=\["data\_classification", "risk\_score"\],  
    append\_fields=\["compliance\_mappings", "remediation\_history"\]  
)  
\`\`\`

Step 21: Configure Ticketing System Integration

\`\`\`yaml  
\# ticketing-integrations.yaml  
ticketing\_integrations:  
    
  servicenow:  
    enabled: true  
    instance: "company.service-now.com"  
    username: "prisma\_integration"  
    password: "\<encrypted-password\>"  
    mappings:  
      incident\_template: "DSPM Security Incident"  
      task\_template: "Data Remediation Task"  
      cmdb\_class: "cmdb\_ci\_cloud\_data\_asset"  
    auto\_create:  
      critical\_risks: true  
      public\_exposure: true  
      compliance\_violations: true  
        
  jira:  
    enabled: true  
    url: "https://company.atlassian.net"  
    project\_key: "DSPM"  
    issue\_type: "Security Task"  
    workflows:  
      risk\_remediation:  
        create\_issue: true  
        assign\_to: "data\_owner"  
        due\_date: "7d"  
        priority\_mapping:  
          critical: "Highest"  
          high: "High"  
          medium: "Medium"  
            
  salesforce:  
    enabled: true  
    instance: "company.my.salesforce.com"  
    object: "Security\_Incident\_\_c"  
    fields\_mapping:  
      data\_classification: "Data\_Sensitivity\_\_c"  
      risk\_score: "Risk\_Level\_\_c"  
      remediation\_status: "Status\_\_c"  
\`\`\`

10\. OPERATIONAL PROCEDURES

Daily DSPM Operations:

\`\`\`  
🔍 \*\*Morning Check (8:00 AM):\*\*  
1\. Review overnight alerts:  
   \- Critical/High severity alerts  
   \- Data exposure incidents  
   \- DLP violations  
     
2\. Check system health:  
   \- Discovery scan status  
   \- Classification engine health  
   \- Integration connectivity  
     
3\. Review new data discoveries:  
   \- New sensitive data identified  
   \- Classification changes  
   \- Owner assignment needed

📊 \*\*Afternoon Review (2:00 PM):\*\*  
1\. Monitor active risks:  
   \- Open remediation tasks  
   \- Aging violations  
   \- Compliance gaps  
     
2\. Analyze trends:  
   \- Data growth patterns  
   \- Risk score trends  
   \- False positive analysis  
     
3\. Team coordination:  
   \- Data owner notifications  
   \- Remediation progress  
   \- Stakeholder updates  
\`\`\`

Weekly DSPM Operations:

\`\`\`  
📈 \*\*Monday: Metrics Review\*\*  
1\. Weekly risk score calculation  
2\. Compliance status update  
3\. Remediation progress report  
4\. Team performance metrics

🔄 \*\*Wednesday: Process Optimization\*\*  
1\. Classification rule tuning  
2\. Alert threshold adjustment  
3\. False positive reduction  
4\. Process improvement review

📋 \*\*Friday: Compliance & Reporting\*\*  
1\. Weekly compliance report generation  
2\. Data inventory updates  
3\. Audit log review  
4\. Next week planning  
\`\`\`

Monthly DSPM Operations:

\`\`\`  
🎯 \*\*First Week: Strategic Review\*\*  
1\. Monthly risk assessment  
2\. Compliance framework updates  
3\. Executive reporting  
4\. Budget and resource planning

🔧 \*\*Second Week: System Maintenance\*\*  
1\. Software updates  
2\. Rule optimization  
3\. Performance tuning  
4\. Backup verification

👥 \*\*Third Week: Stakeholder Engagement\*\*  
1\. Data owner meetings  
2\. Compliance reviews  
3\. Training sessions  
4\. Process workshops

📊 \*\*Fourth Week: Audit Preparation\*\*  
1\. Internal audit support  
2\. Evidence collection  
3\. Control testing  
4\. Gap analysis  
\`\`\`

11\. INCIDENT RESPONSE PLAYBOOKS

Playbook: Data Exposure Incident

\`\`\`  
INCIDENT: Sensitive data publicly exposed  
SEVERITY: Critical

PHASE 1: CONTAINMENT (0-15 minutes)  
1\. Immediate Actions:  
   \- Auto-remediate: Block public access  
   \- Isolate affected resource  
   \- Capture forensic snapshot  
     
2\. Notifications:  
   \- Page security on-call  
   \- Alert data owner  
   \- Notify legal/compliance

PHASE 2: ASSESSMENT (15-60 minutes)  
1\. Impact Analysis:  
   \- Determine data sensitivity  
   \- Identify exposed records  
   \- Check access logs  
     
2\. Root Cause:  
   \- Misconfigured ACL  
   \- Public policy  
   \- Third-party misconfiguration

PHASE 3: REMEDIATION (1-4 hours)  
1\. Data Protection:  
   \- Apply encryption  
   \- Enable logging  
   \- Update access controls  
     
2\. Communication:  
   \- Internal stakeholders  
   \- Legal requirements  
   \- Regulatory notifications

PHASE 4: RECOVERY & PREVENTION (4-24 hours)  
1\. Process Improvements:  
   \- Update policies  
   \- Enhance monitoring  
   \- Implement guardrails  
     
2\. Documentation:  
   \- Incident report  
   \- Lessons learned  
   \- Action items  
\`\`\`

Playbook: Data Exfiltration Attempt

\`\`\`  
INCIDENT: Unauthorized data transfer detected  
SEVERITY: High

DETECTION TRIGGERS:  
\- Large volume sensitive data transfer  
\- Unusual destination  
\- Bypass attempts  
\- Off-hours activity

RESPONSE WORKFLOW:  
1\. Block transfer immediately  
2\. Isolate source system  
3\. Preserve evidence  
4\. Investigate source  
5\. Identify affected data  
6\. Contain spread  
7\. Eradicate threat  
8\. Recover systems  
9\. Post-incident analysis  
\`\`\`

12\. ADVANCED CONFIGURATIONS

Step 22: Configure Machine Learning for Anomaly Detection

\`\`\`python  
\# ml-anomaly-detection.py  
from prismacloud.dspm.ml import AnomalyDetectionModel

model\_config \= {  
    "model\_type": "ensemble",  
    "algorithms": \["isolation\_forest", "autoencoder", "lstm"\],  
      
    "features": \[  
        "data\_access\_frequency",  
        "access\_time\_patterns",  
        "data\_volume\_changes",  
        "user\_behavior\_baseline",  
        "geographic\_access\_patterns",  
        "classification\_changes"  
    \],  
      
    "training\_data": {  
        "normal\_period": "90d",  
        "anomaly\_samples": "labeled\_incidents",  
        "validation\_split": 0.3  
    },  
      
    "detection\_settings": {  
        "confidence\_threshold": 0.85,  
        "false\_positive\_rate\_target": 0.05,  
        "adaptation\_rate": "continuous"  
    },  
      
    "scaling": {  
        "auto\_scaling": True,  
        "min\_instances": 2,  
        "max\_instances": 20,  
        "target\_utilization": 0.7  
    }  
}

\# Train anomaly detection model  
anomaly\_model \= AnomalyDetectionModel(config=model\_config)  
anomaly\_model.train(  
    training\_data="s3://security-data/access-logs/",  
    validation\_data="s3://security-data/validation/"  
)

\# Deploy for real-time detection  
anomaly\_model.deploy(  
    endpoint="https://dspm-anomaly.company.com",  
    monitoring={  
        "drift\_detection": True,  
        "performance\_alerts": True,  
        "auto\_retraining": True  
    }  
)  
\`\`\`

Step 23: Configure Data Security Posture Scoring

\`\`\`yaml  
\# posture-scoring-config.yaml  
posture\_scoring:  
  enabled: true  
    
  scoring\_model: "weighted\_composite"  
    
  components:  
      
    data\_protection:  
      weight: 0.35  
      metrics:  
        \- encryption\_coverage:  
            weight: 0.4  
            calculation: "encrypted\_sensitive\_data / total\_sensitive\_data"  
              
        \- access\_control\_effectiveness:  
            weight: 0.3  
            calculation: "principle\_of\_least\_privilege\_compliance"  
              
        \- logging\_coverage:  
            weight: 0.3  
            calculation: "logged\_data\_access / total\_data\_access"  
              
    data\_governance:  
      weight: 0.25  
      metrics:  
        \- classification\_coverage:  
            weight: 0.4  
            calculation: "classified\_data / total\_data"  
              
        \- owner\_assignment:  
            weight: 0.3  
            calculation: "owned\_data\_assets / total\_data\_assets"  
              
        \- policy\_compliance:  
            weight: 0.3  
            calculation: "compliant\_data\_assets / total\_data\_assets"  
              
    risk\_management:  
      weight: 0.20  
      metrics:  
        \- open\_high\_risks:  
            weight: 0.5  
            calculation: "1 \- (open\_high\_risks / total\_risks)"  
              
        \- mttr:  
            weight: 0.5  
            calculation: "average\_remediation\_time"  
              
    compliance:  
      weight: 0.20  
      metrics:  
        \- framework\_coverage:  
            weight: 0.6  
            calculation: "implemented\_controls / required\_controls"  
              
        \- audit\_readiness:  
            weight: 0.4  
            calculation: "audit\_evidence\_completeness"  
              
  scoring\_scale:  
    excellent: 90-100  
    good: 75-89  
    fair: 60-74  
    poor: 40-59  
    critical: 0-39  
\`\`\`

13\. PERFORMANCE OPTIMIZATION

Step 24: Tune DSPM Performance

\`\`\`yaml  
\# performance-tuning.yaml  
performance:  
    
  discovery\_tuning:  
    concurrency:  
      aws: 20  
      azure: 15  
      gcp: 18  
    batch\_sizes:  
      s3\_objects: 1000  
      database\_tables: 100  
      file\_shares: 500  
    sampling:  
      enabled: true  
      sample\_rate: 0.1  \# 10% sampling  
      minimum\_records: 1000  
        
  classification\_tuning:  
    parallel\_processing: true  
    worker\_count: 8  
    cache\_size: "10GB"  
    cache\_ttl: "1h"  
      
  scanning\_optimization:  
    incremental\_scans: true  
    change\_detection: true  
    priority\_queuing: true  
    resource\_based\_throttling: true  
      
  api\_optimization:  
    rate\_limit\_utilization: 0.8  
    retry\_config:  
      max\_attempts: 5  
      backoff\_factor: 2  
      jitter: true  
    connection\_pooling: true  
\`\`\`

Step 25: Cost Optimization Strategies

\`\`\`python  
\# cost-optimization.py  
from prismacloud.dspm.optimization import CostOptimizer

optimizer \= CostOptimizer()

\# Analyze current costs  
cost\_analysis \= optimizer.analyze\_costs(  
    time\_period="30d",  
    breakdown\_by=\["component", "cloud\_provider", "region"\]  
)

print(f"Total DSPM costs: ${cost\_analysis.total\_cost:.2f}")  
print(f"Largest cost component: {cost\_analysis.top\_component}")

\# Apply optimization strategies  
optimizations \= optimizer.recommend\_optimizations()

for opt in optimizations:  
    if opt.savings\_potential \> 100:  \# $100+ savings  
        print(f"Optimization: {opt.name}")  
        print(f"Potential savings: ${opt.savings\_potential:.2f}")  
        print(f"Implementation effort: {opt.effort}")  
          
        \# Apply optimization  
        if opt.effort \== "low":  
            optimizer.apply\_optimization(opt.id)

\# Cost-saving strategies implemented:  
\# 1\. Smart sampling for large datasets  
\# 2\. Staggered scanning schedules  
\# 3\. Compression of metadata  
\# 4\. Tiered storage for historical data  
\# 5\. Reserved instance purchasing  
\`\`\`

14\. DISASTER RECOVERY & BACKUP

Step 26: DSPM Configuration Backup

\`\`\`bash  
\#\!/bin/bash  
\# dspm-backup.sh  
BACKUP\_DIR="/backups/prisma-dspm"  
DATE=$(date \+%Y%m%d\_%H%M%S)  
ENCRYPTION\_KEY="backup-key-$(date \+%Y%m)"

\# Create backup directory  
mkdir \-p $BACKUP\_DIR/$DATE

\# Backup DSPM configuration  
curl \-H "Authorization: Bearer $PRISMA\_TOKEN" \\  
  "https://\<tenant\>.prismacloud.io/api/v1/data-security/settings" \\  
  \-o "$BACKUP\_DIR/$DATE/settings\_$DATE.json"

\# Backup classification rules  
curl \-H "Authorization: Bearer $PRISMA\_TOKEN" \\  
  "https://\<tenant\>.prismacloud.io/api/v1/data-security/classification/rules" \\  
  \-o "$BACKUP\_DIR/$DATE/classification\_rules\_$DATE.json"

\# Backup risk policies  
curl \-H "Authorization: Bearer $PRISMA\_TOKEN" \\  
  "https://\<tenant\>.prismacloud.io/api/v1/data-security/policies" \\  
  \-o "$BACKUP\_DIR/$DATE/risk\_policies\_$DATE.json"

\# Backup remediation configurations  
curl \-H "Authorization: Bearer $PRISMA\_TOKEN" \\  
  "https://\<tenant\>.prismacloud.io/api/v1/data-security/remediation/config" \\  
  \-o "$BACKUP\_DIR/$DATE/remediation\_config\_$DATE.json"

\# Backup ML models  
curl \-H "Authorization: Bearer $PRISMA\_TOKEN" \\  
  "https://\<tenant\>.prismacloud.io/api/v1/data-security/ml/models" \\  
  \-o "$BACKUP\_DIR/$DATE/ml\_models\_$DATE.tar.gz"

\# Create backup manifest  
cat \> "$BACKUP\_DIR/$DATE/manifest.json" \<\< EOF  
{  
  "backup\_id": "$DATE",  
  "timestamp": "$(date \-u \+"%Y-%m-%dT%H:%M:%SZ")",  
  "components": \[  
    "settings",  
    "classification\_rules",  
    "risk\_policies",  
    "remediation\_config",  
    "ml\_models"  
  \],  
  "version": "$(curl \-s \-H "Authorization: Bearer $PRISMA\_TOKEN" https://\<tenant\>.prismacloud.io/api/v1/version)",  
  "size\_bytes": $(du \-sb $BACKUP\_DIR/$DATE | cut \-f1)  
}  
EOF

\# Encrypt backup  
gpg \--symmetric \--cipher-algo AES256 \\  
  \--output "$BACKUP\_DIR/$DATE/backup\_$DATE.tar.gz.gpg" \\  
  \--passphrase "$ENCRYPTION\_KEY" \\  
  "$BACKUP\_DIR/$DATE"

\# Upload to secure storage  
aws s3 cp "$BACKUP\_DIR/$DATE/backup\_$DATE.tar.gz.gpg" \\  
  "s3://company-backup/prisma-dspm/$DATE/" \\  
  \--sse aws:kms

\# Cleanup local files older than 7 days  
find $BACKUP\_DIR \-type f \-mtime \+7 \-delete  
\`\`\`

Step 27: Disaster Recovery Runbook

\`\`\`  
PHASE 0: PREPARATION (Always)  
\- Maintain current backups  
\- Document recovery procedures  
\- Train recovery team  
\- Test recovery quarterly

PHASE 1: DETECTION & ASSESSMENT (0-30 minutes)  
1\. Detect DSPM service failure  
2\. Assess impact:  
   \- Data discovery disruption  
   \- Classification engine down  
   \- Alerting system failure  
3\. Determine recovery strategy

PHASE 2: CONTAINMENT & RECOVERY (30 minutes \- 4 hours)  
1\. Restore from latest backup  
2\. Re-establish cloud connections  
3\. Restart data collection  
4\. Verify core functionality

PHASE 3: DATA RESYNCHRONIZATION (4-24 hours)  
1\. Backfill missing discovery data  
2\. Re-run classification on new data  
3\. Recalculate risk scores  
4\. Update compliance status

PHASE 4: VALIDATION & MONITORING (24-48 hours)  
1\. Complete functional testing  
2\. Validate data accuracy  
3\. Monitor system stability  
4\. Document recovery process  
\`\`\`

APPENDIX: DSPM QUICK REFERENCE

DSPM API Reference:

\`\`\`python  
\# Key DSPM API Endpoints  
ENDPOINTS \= {  
    \# Data Discovery  
    "discover\_data": "/api/v1/data-security/discover",  
    "get\_data\_asset": "/api/v1/data-security/assets/{id}",  
    "list\_data\_assets": "/api/v1/data-security/assets",  
      
    \# Classification  
    "classify\_data": "/api/v1/data-security/classify",  
    "get\_classification": "/api/v1/data-security/classification/{id}",  
    "update\_classification": "/api/v1/data-security/classification/{id}",  
      
    \# Risk Assessment  
    "assess\_risk": "/api/v1/data-security/risk/assess",  
    "get\_risk\_score": "/api/v1/data-security/assets/{id}/risk",  
    "list\_risky\_assets": "/api/v1/data-security/risk/top",  
      
    \# Remediation  
    "remediate\_risk": "/api/v1/data-security/remediate",  
    "get\_remediation\_status": "/api/v1/data-security/remediation/{id}",  
    "list\_remediation\_tasks": "/api/v1/data-security/remediation",  
      
    \# DLP  
    "detect\_dlp": "/api/v1/data-security/dlp/detect",  
    "get\_dlp\_events": "/api/v1/data-security/dlp/events",  
    "block\_dlp": "/api/v1/data-security/dlp/block",  
      
    \# Lineage  
    "get\_lineage": "/api/v1/data-security/lineage/{id}",  
    "trace\_data\_flow": "/api/v1/data-security/lineage/trace",  
    "update\_lineage": "/api/v1/data-security/lineage/update"  
}  
\`\`\`

DSPM CLI Commands:

\`\`\`bash  
\# Install DSPM CLI  
curl \-o prisma-dspm https://\<tenant\>.prismacloud.io/download/dspm-cli  
chmod \+x prisma-dspm

\# Common commands  
prisma-dspm discover \--cloud aws \--region us-east-1  
prisma-dspm classify \--asset s3://bucket/path \--output json  
prisma-dspm risk assess \--asset-id asset123 \--detailed  
prisma-dspm dlp scan \--source s3://data \--destination external  
prisma-dspm lineage trace \--asset s3://customer-data \--depth 3  
prisma-dspm remediate \--risk-id risk456 \--auto-approve  
\`\`\`

DSPM KPIs & Metrics:

\`\`\`  
Data Security Metrics:  
  \- Sensitive data discovered: 100% coverage  
  \- Data classification accuracy: \>95%  
  \- Encryption coverage: 100% for sensitive data  
  \- Public exposure incidents: 0  
  \- Mean time to remediate: \<24 hours  
  \- DLP false positive rate: \<5%  
  \- Compliance framework coverage: \>90%  
  \- Data owner assignment: 100%  
  \- Risk score improvement: 20% quarterly  
\`\`\`

Troubleshooting Guide:

Issue Symptoms Resolution  
Discovery failures No new data assets found Verify IAM permissions, check API rate limits  
Classification errors High false positive/negative rate Adjust confidence thresholds, retrain ML models  
Performance issues Slow scans, timeouts Increase concurrency, optimize sampling  
Integration failures SIEM/CMDB sync failing Verify credentials, check network connectivity  
Alert noise Too many false positives Tune detection rules, adjust thresholds

\---

DSPM IMPLEMENTATION SIGN-OFF

Implementation Checklist:

· Prerequisites validated  
· Cloud permissions configured  
· Data discovery completed  
· Classification rules configured  
· Risk policies established  
· Remediation workflows tested  
· Integration validated  
· Team training completed  
· DR procedures documented  
· Performance benchmarks established

Approval Matrix:

Role Responsibilities Sign-off  
CISO Overall data security strategy   
Data Protection Officer Regulatory compliance   
Cloud Security Architect Technical implementation   
Data Governance Lead Data classification framework   
SOC Manager Operational readiness 

Go-Live Criteria:

· ✅ All critical data assets discovered  
· ✅ Classification accuracy \>95%  
· ✅ Risk scoring validated  
· ✅ Alerting tested and operational  
· ✅ Team trained on procedures  
· ✅ DR plan tested  
· ✅ Performance meets SLAs

\---

Document Control:

· Version: 3.0  
· Last Updated: \[Date\]  
· Next Review: \[Date \+ 90 days\]  
· Owner: Data Security Team  
· Classification: Restricted

This DSPM SOP should be reviewed quarterly. Regular updates required based on new data regulations, cloud provider features, and organizational changes.