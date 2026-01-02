"""
SAST & PII/PHI Data Security Scanner
Comprehensive security scanner for source code and data files
Detects PII/PHI, security vulnerabilities, and generates compliance reports
Aligned with HIPAA, NIST, ISO27001, SOC2, PCI-DSS
"""

import os
import re
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Tuple, Set
from dataclasses import dataclass, asdict, field
from collections import defaultdict
import mimetypes

# Data processing and ML
import pandas as pd
import numpy as np

# Visualization
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
from io import BytesIO
import base64

# NLP for context analysis
from collections import Counter

# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class DataSensitivityFinding:
    """Represents a PII/PHI data finding"""
    id: str
    finding_type: str  # PII, PHI, CREDENTIALS, API_KEY
    sensitivity_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    data_category: str  # SSN, CREDIT_CARD, EMAIL, MEDICAL_RECORD, etc.
    file_path: str
    line_number: int
    column_start: int
    column_end: int
    matched_pattern: str
    context: str  # Surrounding code/text
    confidence_score: float
    compliance_violations: List[str]
    remediation: str
    risk_score: float = 0.0

@dataclass
class SecurityVulnerability:
    """Represents a security vulnerability in code"""
    id: str
    vulnerability_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cwe_id: str
    owasp_category: str
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    recommendation: str
    compliance_impact: List[str]
    cvss_score: float
    exploitability: float = 0.0

@dataclass
class ComplianceReport:
    """Compliance assessment report"""
    framework: str
    total_controls: int
    passed_controls: int
    failed_controls: int
    compliance_score: float
    critical_gaps: List[str]
    findings_by_control: Dict[str, List[str]]

# ============================================================================
# PII/PHI PATTERN DEFINITIONS
# ============================================================================

class SensitiveDataPatterns:
    """Regex patterns for detecting sensitive data"""
    
    # US Social Security Numbers
    SSN = r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'
    
    # Credit Card Numbers (Visa, MasterCard, Amex, Discover)
    CREDIT_CARD = r'\b(?:4\d{3}|5[1-5]\d{2}|6(?:011|5\d{2})|3[47]\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
    
    # Email addresses
    EMAIL = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    # Phone numbers (US format)
    PHONE = r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b'
    
    # IP Addresses
    IP_ADDRESS = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    
    # Driver's License (various formats)
    DRIVERS_LICENSE = r'\b[A-Z]{1,2}\d{5,8}\b'
    
    # Passport Numbers
    PASSPORT = r'\b[A-Z]\d{8}\b'
    
    # Medical Record Numbers
    MEDICAL_RECORD = r'\bMRN[-:]?\s*\d{6,10}\b'
    
    # Health Insurance Numbers
    INSURANCE_NUMBER = r'\b(?:Policy|Member|Subscriber)[-:]?\s*[A-Z0-9]{6,15}\b'
    
    # Bank Account Numbers
    BANK_ACCOUNT = r'\b\d{8,17}\b'
    
    # API Keys and Secrets
    API_KEY = r'(?i)(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?'
    
    # AWS Keys
    AWS_ACCESS_KEY = r'(?i)AKIA[0-9A-Z]{16}'
    AWS_SECRET_KEY = r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?'
    
    # Private Keys
    PRIVATE_KEY = r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'
    
    # Database Connection Strings
    DB_CONNECTION = r'(?i)(?:mysql|postgresql|mongodb|mssql):\/\/[^\s;]+(?:password|pwd)=([^;@\s]+)'
    
    # Passwords in code
    PASSWORD = r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{3,})["\']'
    
    # Date of Birth
    DOB = r'\b(?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])[-/](?:19|20)\d{2}\b'
    
    # Medicare Numbers
    MEDICARE = r'\b\d{4}[-\s]?\d{3}[-\s]?\d{3}[-\s]?[A-Z]\b'
    
    # Biometric Data References
    BIOMETRIC = r'(?i)\b(?:fingerprint|iris[_-]?scan|facial[_-]?recognition|biometric[_-]?data)\b'
    
    # Genetic Data References
    GENETIC = r'(?i)\b(?:dna|genetic[_-]?data|genome|genotype)\b'

class SecurityVulnerabilityPatterns:
    """Patterns for detecting security vulnerabilities in code"""
    
    # SQL Injection
    SQL_INJECTION = [
        r'execute\s*\(\s*["\'].*?\+.*?["\']',  # String concatenation in SQL
        r'cursor\.execute\s*\(\s*f["\']',  # F-strings in SQL
        r'\.format\s*\(.*?\)\s*\)',  # String formatting in SQL
    ]
    
    # Command Injection
    COMMAND_INJECTION = [
        r'os\.system\s*\([^)]*\+',
        r'subprocess\.(?:call|run|Popen)\s*\([^)]*\+',
        r'eval\s*\(',
        r'exec\s*\(',
    ]
    
    # Path Traversal
    PATH_TRAVERSAL = [
        r'open\s*\([^)]*\+',
        r'os\.path\.join\s*\([^)]*user',
    ]
    
    # XSS Vulnerabilities
    XSS = [
        r'innerHTML\s*=',
        r'document\.write\s*\(',
        r'\.html\s*\([^)]*\+',
    ]
    
    # Hardcoded Secrets
    HARDCODED_SECRETS = [
        r'(?i)password\s*=\s*["\'][^"\']{3,}["\']',
        r'(?i)api[_-]?key\s*=\s*["\'][^"\']{10,}["\']',
        r'(?i)secret\s*=\s*["\'][^"\']{10,}["\']',
    ]
    
    # Insecure Cryptography
    WEAK_CRYPTO = [
        r'(?i)md5\s*\(',
        r'(?i)sha1\s*\(',
        r'(?i)DES\s*\(',
        r'(?i)RC4',
    ]
    
    # Insecure Deserialization
    INSECURE_DESERIAL = [
        r'pickle\.loads?\s*\(',
        r'yaml\.load\s*\(',
        r'eval\s*\(',
    ]
    
    # SSRF
    SSRF = [
        r'requests\.get\s*\([^)]*user',
        r'urllib\.request\.urlopen\s*\([^)]*user',
    ]

# ============================================================================
# COMPLIANCE FRAMEWORK MAPPINGS
# ============================================================================

COMPLIANCE_FRAMEWORKS = {
    "HIPAA": {
        "controls": {
            "164.308(a)(1)": "Security Management Process",
            "164.308(a)(3)": "Workforce Security",
            "164.308(a)(4)": "Information Access Management",
            "164.310(a)(1)": "Facility Access Controls",
            "164.310(d)": "Device and Media Controls",
            "164.312(a)(1)": "Access Control",
            "164.312(a)(2)(iv)": "Encryption and Decryption",
            "164.312(b)": "Audit Controls",
            "164.312(c)(1)": "Integrity",
            "164.312(d)": "Person or Entity Authentication",
            "164.312(e)(1)": "Transmission Security",
        },
        "phi_categories": ["MEDICAL_RECORD", "INSURANCE_NUMBER", "MEDICARE", "BIOMETRIC", "GENETIC"]
    },
    "PCI-DSS": {
        "controls": {
            "3.2": "Do not store sensitive authentication data after authorization",
            "3.4": "Render PAN unreadable",
            "4.1": "Use strong cryptography for transmission",
            "8.2": "Ensure proper user authentication",
            "10.1": "Implement audit trails",
        },
        "pii_categories": ["CREDIT_CARD", "BANK_ACCOUNT"]
    },
    "NIST-800-53": {
        "controls": {
            "AC-2": "Account Management",
            "AC-3": "Access Enforcement",
            "AU-2": "Audit Events",
            "IA-2": "Identification and Authentication",
            "SC-8": "Transmission Confidentiality",
            "SC-13": "Cryptographic Protection",
            "SI-10": "Information Input Validation",
        }
    },
    "ISO27001": {
        "controls": {
            "A.9.1": "Access Control Policy",
            "A.9.4": "System and Application Access Control",
            "A.10.1": "Cryptographic Controls",
            "A.12.3": "Information Backup",
            "A.14.2": "Security in Development",
            "A.18.1": "Compliance with Legal Requirements",
        }
    },
    "SOC2": {
        "controls": {
            "CC6.1": "Logical and Physical Access Controls",
            "CC6.6": "Encryption of Data",
            "CC7.1": "Detection of Security Events",
            "CC7.2": "Monitoring of System Components",
        }
    }
}

# ============================================================================
# MAIN SCANNER CLASS
# ============================================================================

class SASTDataSecurityScanner:
    """Main scanner for SAST and data security analysis"""
    
    def __init__(self, scan_path: str):
        self.scan_path = scan_path
        self.pii_phi_findings: List[DataSensitivityFinding] = []
        self.security_vulnerabilities: List[SecurityVulnerability] = []
        self.compliance_reports: Dict[str, ComplianceReport] = {}
        self.file_stats = {
            'total_files': 0,
            'scanned_files': 0,
            'skipped_files': 0,
            'total_lines': 0
        }
        
        # Initialize patterns
        self.sensitivity_patterns = self._compile_sensitivity_patterns()
        self.security_patterns = self._compile_security_patterns()
        
        # Supported file extensions
        self.code_extensions = {'.py', '.js', '.java', '.cs', '.cpp', '.c', '.rb', '.php', 
                               '.go', '.rs', '.ts', '.jsx', '.tsx', '.sql', '.sh', '.yaml', 
                               '.yml', '.json', '.xml', '.properties', '.conf', '.ini'}
        
        self.data_extensions = {'.csv', '.txt', '.log', '.dat', '.json', '.xml'}
    
    def _compile_sensitivity_patterns(self) -> Dict[str, Tuple[re.Pattern, str, str, List[str]]]:
        """Compile all sensitivity detection patterns"""
        patterns = {}
        
        pattern_definitions = [
            ('SSN', SensitiveDataPatterns.SSN, 'CRITICAL', 'PHI', ['HIPAA', 'PCI-DSS']),
            ('CREDIT_CARD', SensitiveDataPatterns.CREDIT_CARD, 'CRITICAL', 'PII', ['PCI-DSS']),
            ('EMAIL', SensitiveDataPatterns.EMAIL, 'MEDIUM', 'PII', ['GDPR', 'HIPAA']),
            ('PHONE', SensitiveDataPatterns.PHONE, 'MEDIUM', 'PII', ['GDPR', 'HIPAA']),
            ('MEDICAL_RECORD', SensitiveDataPatterns.MEDICAL_RECORD, 'CRITICAL', 'PHI', ['HIPAA']),
            ('INSURANCE_NUMBER', SensitiveDataPatterns.INSURANCE_NUMBER, 'CRITICAL', 'PHI', ['HIPAA']),
            ('MEDICARE', SensitiveDataPatterns.MEDICARE, 'CRITICAL', 'PHI', ['HIPAA']),
            ('API_KEY', SensitiveDataPatterns.API_KEY, 'CRITICAL', 'CREDENTIALS', ['ALL']),
            ('AWS_ACCESS_KEY', SensitiveDataPatterns.AWS_ACCESS_KEY, 'CRITICAL', 'CREDENTIALS', ['ALL']),
            ('PRIVATE_KEY', SensitiveDataPatterns.PRIVATE_KEY, 'CRITICAL', 'CREDENTIALS', ['ALL']),
            ('PASSWORD', SensitiveDataPatterns.PASSWORD, 'HIGH', 'CREDENTIALS', ['ALL']),
            ('DB_CONNECTION', SensitiveDataPatterns.DB_CONNECTION, 'CRITICAL', 'CREDENTIALS', ['ALL']),
            ('DOB', SensitiveDataPatterns.DOB, 'HIGH', 'PII', ['HIPAA', 'GDPR']),
            ('BIOMETRIC', SensitiveDataPatterns.BIOMETRIC, 'CRITICAL', 'PHI', ['HIPAA']),
            ('GENETIC', SensitiveDataPatterns.GENETIC, 'CRITICAL', 'PHI', ['HIPAA']),
        ]
        
        for name, pattern, severity, category, compliance in pattern_definitions:
            patterns[name] = (re.compile(pattern, re.IGNORECASE), severity, category, compliance)
        
        return patterns
    
    def _compile_security_patterns(self) -> Dict[str, List[Tuple[re.Pattern, str, str, str, float]]]:
        """Compile all security vulnerability patterns"""
        patterns = defaultdict(list)
        
        # SQL Injection
        for pattern in SecurityVulnerabilityPatterns.SQL_INJECTION:
            patterns['SQL_INJECTION'].append((
                re.compile(pattern, re.IGNORECASE),
                'CRITICAL',
                'CWE-89',
                'A03:2021 – Injection',
                9.8
            ))
        
        # Command Injection
        for pattern in SecurityVulnerabilityPatterns.COMMAND_INJECTION:
            patterns['COMMAND_INJECTION'].append((
                re.compile(pattern, re.IGNORECASE),
                'CRITICAL',
                'CWE-78',
                'A03:2021 – Injection',
                9.1
            ))
        
        # Path Traversal
        for pattern in SecurityVulnerabilityPatterns.PATH_TRAVERSAL:
            patterns['PATH_TRAVERSAL'].append((
                re.compile(pattern, re.IGNORECASE),
                'HIGH',
                'CWE-22',
                'A01:2021 – Broken Access Control',
                7.5
            ))
        
        # XSS
        for pattern in SecurityVulnerabilityPatterns.XSS:
            patterns['XSS'].append((
                re.compile(pattern, re.IGNORECASE),
                'HIGH',
                'CWE-79',
                'A03:2021 – Injection',
                7.2
            ))
        
        # Weak Crypto
        for pattern in SecurityVulnerabilityPatterns.WEAK_CRYPTO:
            patterns['WEAK_CRYPTO'].append((
                re.compile(pattern, re.IGNORECASE),
                'HIGH',
                'CWE-327',
                'A02:2021 – Cryptographic Failures',
                7.5
            ))
        
        # Insecure Deserialization
        for pattern in SecurityVulnerabilityPatterns.INSECURE_DESERIAL:
            patterns['INSECURE_DESERIAL'].append((
                re.compile(pattern, re.IGNORECASE),
                'CRITICAL',
                'CWE-502',
                'A08:2021 – Software and Data Integrity Failures',
                9.8
            ))
        
        return patterns
    
    def scan_directory(self):
        """Scan entire directory recursively"""
        print(f"Starting scan of: {self.scan_path}")
        print("=" * 80)
        
        for root, _, files in os.walk(self.scan_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                self.file_stats['total_files'] += 1
                
                # Skip binary files and certain directories
                if self._should_skip_file(file_path):
                    self.file_stats['skipped_files'] += 1
                    continue
                
                try:
                    self.scan_file(file_path)
                    self.file_stats['scanned_files'] += 1
                except Exception as e:
                    print(f"Error scanning {file_path}: {str(e)}")
        
        # Generate compliance reports
        self._generate_compliance_reports()
        
        print(f"\n✓ Scan complete!")
        print(f"  Files scanned: {self.file_stats['scanned_files']}/{self.file_stats['total_files']}")
        print(f"  PII/PHI findings: {len(self.pii_phi_findings)}")
        print(f"  Security vulnerabilities: {len(self.security_vulnerabilities)}")
    
    def _should_skip_file(self, file_path: str) -> bool:
        """Determine if file should be skipped"""
        skip_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build'}
        skip_extensions = {'.exe', '.dll', '.so', '.dylib', '.bin', '.jpg', '.png', '.gif', '.pdf'}
        
        # Check if in skip directory
        path_parts = file_path.split(os.sep)
        if any(skip_dir in path_parts for skip_dir in skip_dirs):
            return True
        
        # Check extension
        _, ext = os.path.splitext(file_path)
        if ext.lower() in skip_extensions:
            return True
        
        # Check if binary
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                if b'\x00' in chunk:  # Null bytes indicate binary
                    return True
        except:
            return True
        
        return False
    
    def scan_file(self, file_path: str):
        """Scan a single file for sensitive data and vulnerabilities"""
        _, ext = os.path.splitext(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                self.file_stats['total_lines'] += len(lines)
                
                for line_num, line in enumerate(lines, 1):
                    # Scan for PII/PHI
                    self._scan_line_for_sensitive_data(file_path, line_num, line)
                    
                    # Scan for security vulnerabilities in code files
                    if ext in self.code_extensions:
                        self._scan_line_for_vulnerabilities(file_path, line_num, line)
        
        except Exception as e:
            print(f"Error reading {file_path}: {str(e)}")
    
    def _scan_line_for_sensitive_data(self, file_path: str, line_num: int, line: str):
        """Scan a line for PII/PHI"""
        for pattern_name, (pattern, severity, category, compliance) in self.sensitivity_patterns.items():
            matches = pattern.finditer(line)
            
            for match in matches:
                # Extract context (surrounding text)
                start = max(0, match.start() - 20)
                end = min(len(line), match.end() + 20)
                context = line[start:end].strip()
                
                # Calculate confidence score based on context
                confidence = self._calculate_confidence(pattern_name, context, line)
                
                # Skip low confidence matches
                if confidence < 0.5:
                    continue
                
                finding_id = self._generate_finding_id(file_path, line_num, pattern_name)
                
                finding = DataSensitivityFinding(
                    id=finding_id,
                    finding_type=category,
                    sensitivity_level=severity,
                    data_category=pattern_name,
                    file_path=file_path,
                    line_number=line_num,
                    column_start=match.start(),
                    column_end=match.end(),
                    matched_pattern=match.group(0),
                    context=context,
                    confidence_score=confidence,
                    compliance_violations=compliance,
                    remediation=self._get_remediation(pattern_name),
                    risk_score=self._calculate_risk_score(severity, confidence, category)
                )
                
                self.pii_phi_findings.append(finding)
    
    def _scan_line_for_vulnerabilities(self, file_path: str, line_num: int, line: str):
        """Scan a line for security vulnerabilities"""
        for vuln_type, pattern_list in self.security_patterns.items():
            for pattern, severity, cwe, owasp, cvss in pattern_list:
                if pattern.search(line):
                    vuln_id = self._generate_finding_id(file_path, line_num, vuln_type)
                    
                    vulnerability = SecurityVulnerability(
                        id=vuln_id,
                        vulnerability_type=vuln_type,
                        severity=severity,
                        cwe_id=cwe,
                        owasp_category=owasp,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                        description=self._get_vulnerability_description(vuln_type),
                        recommendation=self._get_vulnerability_recommendation(vuln_type),
                        compliance_impact=self._get_compliance_impact(vuln_type),
                        cvss_score=cvss,
                        exploitability=self._estimate_exploitability(vuln_type, cvss)
                    )
                    
                    self.security_vulnerabilities.append(vulnerability)
    
    def _calculate_confidence(self, pattern_name: str, context: str, full_line: str) -> float:
        """Calculate confidence score for a match"""
        confidence = 0.7  # Base confidence
        
        # Check for test/mock data indicators
        test_indicators = ['test', 'mock', 'example', 'sample', 'dummy', 'fake']
        if any(indicator in full_line.lower() for indicator in test_indicators):
            confidence *= 0.5
        
        # Check for variable names that suggest real data
        real_indicators = ['customer', 'patient', 'user', 'account', 'production', 'prod']
        if any(indicator in full_line.lower() for indicator in real_indicators):
            confidence *= 1.2
        
        # Pattern-specific adjustments
        if pattern_name == 'EMAIL':
            if '@example.com' in context.lower() or '@test.com' in context.lower():
                confidence *= 0.3
        
        if pattern_name in ['SSN', 'CREDIT_CARD']:
            # Check for common test numbers
            if '000-00-0000' in context or '1234-5678' in context:
                confidence *= 0.1
        
        return min(confidence, 1.0)
    
    def _calculate_risk_score(self, severity: str, confidence: float, category: str) -> float:
        """Calculate risk score for a finding"""
        severity_scores = {'CRITICAL': 10, 'HIGH': 7.5, 'MEDIUM': 5.0, 'LOW': 2.5}
        category_multipliers = {'PHI': 1.5, 'CREDENTIALS': 1.4, 'PII': 1.2}
        
        base_score = severity_scores.get(severity, 5.0)
        multiplier = category_multipliers.get(category, 1.0)
        
        return round(base_score * confidence * multiplier, 2)
    
    def _estimate_exploitability(self, vuln_type: str, cvss: float) -> float:
        """Estimate exploitability of a vulnerability"""
        base_exploit = cvss / 10.0
        
        # Adjust based on vulnerability type
        high_exploit_vulns = ['SQL_INJECTION', 'COMMAND_INJECTION', 'INSECURE_DESERIAL']
        if vuln_type in high_exploit_vulns:
            base_exploit *= 1.2
        
        return min(base_exploit, 1.0)
    
    def _get_remediation(self, pattern_name: str) -> str:
        """Get remediation guidance for a finding"""
        remediations = {
            'SSN': 'Remove SSN or encrypt with AES-256. Use tokenization for storage.',
            'CREDIT_CARD': 'Implement PCI-DSS compliant storage. Never log credit card numbers.',
            'PASSWORD': 'Remove hardcoded passwords. Use environment variables or secrets manager.',
            'API_KEY': 'Remove API keys from code. Use environment variables or secrets management service.',
            'MEDICAL_RECORD': 'Encrypt PHI data at rest and in transit. Implement HIPAA-compliant controls.',
            'EMAIL': 'Consider hashing or pseudonymizing email addresses. Implement access controls.',
            'PRIVATE_KEY': 'Remove private keys from code. Use secure key management system.',
        }
        return remediations.get(pattern_name, 'Review and secure sensitive data according to compliance requirements.')
    
    def _get_vulnerability_description(self, vuln_type: str) -> str:
        """Get description for vulnerability type"""
        descriptions = {
            'SQL_INJECTION': 'SQL Injection vulnerability detected. User input is concatenated into SQL query.',
            'COMMAND_INJECTION': 'Command Injection vulnerability. User input may be executed as system command.',
            'PATH_TRAVERSAL': 'Path Traversal vulnerability. User input used in file path operations.',
            'XSS': 'Cross-Site Scripting (XSS) vulnerability. User input rendered without sanitization.',
            'WEAK_CRYPTO': 'Weak cryptographic algorithm detected. Using deprecated or insecure hashing.',
            'INSECURE_DESERIAL': 'Insecure deserialization detected. May allow arbitrary code execution.',
        }
        return descriptions.get(vuln_type, 'Security vulnerability detected.')
    
    def _get_vulnerability_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for vulnerability type"""
        recommendations = {
            'SQL_INJECTION': 'Use parameterized queries or prepared statements. Never concatenate user input.',
            'COMMAND_INJECTION': 'Avoid system calls with user input. Use subprocess with shell=False and validate input.',
            'PATH_TRAVERSAL': 'Validate and sanitize file paths. Use os.path.abspath and check against whitelist.',
            'XSS': 'Sanitize and escape user input. Use templating engines with auto-escaping.',
            'WEAK_CRYPTO': 'Use SHA-256 or SHA-3 for hashing. Use AES-256-GCM for encryption.',
            'INSECURE_DESERIAL': 'Avoid pickle for untrusted data. Use JSON or implement signature verification.',
        }
        return recommendations.get(vuln_type, 'Follow secure coding best practices.')
    
    def _get_compliance_impact(self, vuln_type: str) -> List[str]:
        """Get compliance frameworks impacted by vulnerability"""
        impacts = {
            'SQL_INJECTION': ['PCI-DSS 6.5.1', 'HIPAA 164.312(a)', 'SOC2 CC6.1'],
            'COMMAND_INJECTION': ['PCI-DSS 6.5.1', 'SOC2 CC6.1', 'NIST SI-10'],
            'WEAK_CRYPTO': ['PCI-DSS 4.1', 'HIPAA 164.312(a)(2)(iv)', 'NIST SC-13', 'ISO27001 A.10.1'],
            'INSECURE_DESERIAL': ['SOC2 CC6.1', 'NIST SI-10', 'ISO27001 A.14.2'],
        }
        return impacts.get(vuln_type, ['SOC2 CC6.1', 'ISO27001 A.14.2'])
    
    def _generate_finding_id(self, file_path: str, line_num: int, finding_type: str) -> str:
        """Generate unique finding ID"""
        data = f"{file_path}:{line_num}:{finding_type}"
        hash_obj = hashlib.md5(data.encode())
        return f"{finding_type}-{hash_obj.hexdigest()[:12]}"
    
    def _generate_compliance_reports(self):
        """Generate compliance assessment reports"""
        for framework, config in COMPLIANCE_FRAMEWORKS.items():
            controls = config.get('controls', {})
            total_controls = len(controls)
            
            # Assess each control
            failed_controls = 0
            critical_gaps = []
            findings_by_control = defaultdict(list)
            
            # Check PII/PHI findings against this framework
            phi_categories = config.get('phi_categories', [])
            pii_categories = config.get('pii_categories', [])
            
            for finding in self.pii_phi_findings:
                if framework in finding.compliance_violations:
                    # Map to specific control if possible, otherwise generic
                    control_id = "General Data Protection"
                    findings_by_control[control_id].append(f"Sensitive Data: {finding.data_category} found in {finding.file_path}")
                    failed_controls += 1

            # Check Security Vulnerabilities against this framework
            for vuln in self.security_vulnerabilities:
                for impact in vuln.compliance_impact:
                    if framework in impact:
                        # Extract control ID from impact string (e.g., "SOC2 CC6.1" -> "CC6.1")
                        parts = impact.split()
                        if len(parts) > 1:
                            control_id = parts[-1]
                            findings_by_control[control_id].append(f"Vulnerability: {vuln.vulnerability_type} ({vuln.severity}) in {vuln.file_path}")
                            failed_controls += 1

            # Calculate score
            passed_controls = total_controls - min(failed_controls, total_controls) # Simplified logic
            compliance_score = (passed_controls / total_controls * 100) if total_controls > 0 else 0.0
            
            self.compliance_reports[framework] = ComplianceReport(
                framework=framework,
                total_controls=total_controls,
                passed_controls=passed_controls,
                failed_controls=failed_controls,
                compliance_score=compliance_score,
                critical_gaps=list(findings_by_control.keys()),
                findings_by_control=dict(findings_by_control)
            )

    def generate_visualizations(self) -> Dict[str, str]:
        """Generate visualizations for the report"""
        plots = {}
        
        # 1. Findings by Severity (Pie Chart)
        plt.figure(figsize=(10, 6))
        severities = [f.sensitivity_level for f in self.pii_phi_findings] + \
                     [v.severity for v in self.security_vulnerabilities]
        
        if severities:
            counts = Counter(severities)
            colors = {'CRITICAL': '#ff4d4d', 'HIGH': '#ff9933', 'MEDIUM': '#ffff66', 'LOW': '#66ff66'}
            plt.pie(counts.values(), labels=counts.keys(), autopct='%1.1f%%', 
                   colors=[colors.get(k, '#cccccc') for k in counts.keys()])
            plt.title('Security Findings by Severity')
            
            buf = BytesIO()
            plt.savefig(buf, format='png')
            plots['severity_dist'] = base64.b64encode(buf.getvalue()).decode('utf-8')
            plt.close()
        
        # 2. Findings by Type (Bar Chart)
        plt.figure(figsize=(12, 6))
        types = [f.finding_type for f in self.pii_phi_findings] + \
                [v.vulnerability_type for v in self.security_vulnerabilities]
        
        if types:
            counts = Counter(types)
            sns.barplot(x=list(counts.keys()), y=list(counts.values()))
            plt.xticks(rotation=45)
            plt.title('Findings by Category')
            plt.tight_layout()
            
            buf = BytesIO()
            plt.savefig(buf, format='png')
            plots['type_dist'] = base64.b64encode(buf.getvalue()).decode('utf-8')
            plt.close()
            
        # 3. Compliance Scorecard (Bar Chart)
        plt.figure(figsize=(10, 6))
        frameworks = list(self.compliance_reports.keys())
        scores = [r.compliance_score for r in self.compliance_reports.values()]
        
        sns.barplot(x=frameworks, y=scores, hue=frameworks, legend=False, palette='viridis')
        plt.ylim(0, 100)
        plt.title('Compliance Score by Framework')
        plt.ylabel('Compliance Score (%)')
        
        buf = BytesIO()
        plt.savefig(buf, format='png')
        plots['compliance_scores'] = base64.b64encode(buf.getvalue()).decode('utf-8')
        plt.close()

        return plots

    def generate_html_report(self, output_path: str = 'security_report.html'):
        """Generate comprehensive HTML report"""
        plots = self.generate_visualizations()
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SAST & Data Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
                h1, h2, h3 {{ color: #333; }}
                .dashboard {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }}
                .metric-card {{ background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }}
                .metric-value {{ font-size: 24px; font-weight: bold; color: #007bff; }}
                .finding {{ border-left: 5px solid #ddd; padding: 10px; margin-bottom: 10px; background: #fff; }}
                .finding.CRITICAL {{ border-left-color: #dc3545; }}
                .finding.HIGH {{ border-left-color: #fd7e14; }}
                .finding.MEDIUM {{ border-left-color: #ffc107; }}
                .finding.LOW {{ border-left-color: #28a745; }}
                table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
                th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; }}
                th {{ background-color: #f8f9fa; }}
                img {{ max-width: 100%; height: auto; display: block; margin: 0 auto; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>SAST & Data Security Assessment Report</h1>
                <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <div class="dashboard">
                    <div class="metric-card">
                        <h3>Files Scanned</h3>
                        <div class="metric-value">{self.file_stats['scanned_files']}</div>
                    </div>
                    <div class="metric-card">
                        <h3>Total Findings</h3>
                        <div class="metric-value">{len(self.pii_phi_findings) + len(self.security_vulnerabilities)}</div>
                    </div>
                </div>

                <h2>Executive Summary</h2>
                <div class="dashboard">
                    <div>
                        <img src="data:image/png;base64,{plots.get('severity_dist', '')}" style="width: 100%">
                    </div>
                    <div>
                        <img src="data:image/png;base64,{plots.get('type_dist', '')}" style="width: 100%">
                    </div>
                </div>

                <h2>Compliance Status</h2>
                <div>
                    <img src="data:image/png;base64,{plots.get('compliance_scores', '')}" style="width: 100%; max-width: 800px;">
                </div>
                
                <table>
                    <tr>
                        <th>Framework</th>
                        <th>Score</th>
                        <th>Controls Passed</th>
                        <th>Critical Gaps</th>
                    </tr>
                    {''.join(f'''
                    <tr>
                        <td>{r.framework}</td>
                        <td>{r.compliance_score:.1f}%</td>
                        <td>{r.passed_controls}/{r.total_controls}</td>
                        <td>{len(r.critical_gaps)}</td>
                    </tr>
                    ''' for r in self.compliance_reports.values())}
                </table>

                <h2>Detailed Findings</h2>
                
                <h3>Sensitive Data (PII/PHI)</h3>
                {''.join(f'''
                <div class="finding {f.sensitivity_level}">
                    <strong>[{f.sensitivity_level}] {f.finding_type} - {f.data_category}</strong><br>
                    File: {f.file_path}:{f.line_number}<br>
                    Context: <code>{f.context}</code><br>
                    Remediation: {f.remediation}
                </div>
                ''' for f in self.pii_phi_findings)}

                <h3>Security Vulnerabilities</h3>
                {''.join(f'''
                <div class="finding {v.severity}">
                    <strong>[{v.severity}] {v.vulnerability_type}</strong><br>
                    File: {v.file_path}:{v.line_number}<br>
                    CWE: {v.cwe_id} | OWASP: {v.owasp_category}<br>
                    Description: {v.description}<br>
                    Recommendation: {v.recommendation}
                </div>
                ''' for v in self.security_vulnerabilities)}
            </div>
        </body>
        </html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"Report generated: {output_path}")

if __name__ == "__main__":
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description='SAST & Data Security Scanner')
    parser.add_argument('path', help='Path to scan')
    parser.add_argument('--output', '-o', default='security_report.html', help='Output report path')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"Error: Path {args.path} does not exist")
        sys.exit(1)
        
    scanner = SASTDataSecurityScanner(args.path)
    scanner.scan_directory()
    scanner.generate_html_report(args.output)