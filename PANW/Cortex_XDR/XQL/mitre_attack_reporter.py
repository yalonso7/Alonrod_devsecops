#!/usr/bin/env python3
"""
Cortex XDR XQL MITRE ATT&CK Report Generator

This tool generates HTML reports from XQL query results and maps
behaviors and attacks to the MITRE ATT&CK framework.

Author: Security Operations
Version: 1.0
Date: January 9, 2026
"""

import json
import csv
import argparse
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import re

try:
    from jinja2 import Template
except ImportError:
    print("Error: jinja2 is required. Install with: pip install jinja2")
    exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MitreTactic(Enum):
    """MITRE ATT&CK Tactics"""
    RECONNAISSANCE = ("TA0043", "Reconnaissance")
    RESOURCE_DEVELOPMENT = ("TA0042", "Resource Development")
    INITIAL_ACCESS = ("TA0001", "Initial Access")
    EXECUTION = ("TA0002", "Execution")
    PERSISTENCE = ("TA0003", "Persistence")
    PRIVILEGE_ESCALATION = ("TA0004", "Privilege Escalation")
    DEFENSE_EVASION = ("TA0005", "Defense Evasion")
    CREDENTIAL_ACCESS = ("TA0006", "Credential Access")
    DISCOVERY = ("TA0007", "Discovery")
    LATERAL_MOVEMENT = ("TA0008", "Lateral Movement")
    COLLECTION = ("TA0009", "Collection")
    COMMAND_AND_CONTROL = ("TA0011", "Command and Control")
    EXFILTRATION = ("TA0010", "Exfiltration")
    IMPACT = ("TA0040", "Impact")


class MitreTechnique:
    """MITRE ATT&CK Technique mapping"""
    
    TECHNIQUE_MAP = {
        # Lateral Movement
        "T1021.001": {
            "id": "T1021.001",
            "name": "Remote Desktop Protocol",
            "tactic": MitreTactic.LATERAL_MOVEMENT,
            "description": "Adversaries may use Remote Desktop Protocol (RDP) to move laterally."
        },
        "T1021.002": {
            "id": "T1021.002",
            "name": "SMB/Windows Admin Shares",
            "tactic": MitreTactic.LATERAL_MOVEMENT,
            "description": "Adversaries may use SMB to move laterally."
        },
        "T1078": {
            "id": "T1078",
            "name": "Valid Accounts",
            "tactic": MitreTactic.LATERAL_MOVEMENT,
            "description": "Adversaries may steal and use valid account credentials."
        },
        # Credential Access
        "T1003.001": {
            "id": "T1003.001",
            "name": "LSASS Memory",
            "tactic": MitreTactic.CREDENTIAL_ACCESS,
            "description": "Adversaries may attempt to access credential material stored in LSASS memory."
        },
        "T1003.002": {
            "id": "T1003.002",
            "name": "Security Account Manager",
            "tactic": MitreTactic.CREDENTIAL_ACCESS,
            "description": "Adversaries may attempt to extract credential material from the SAM database."
        },
        "T1555.003": {
            "id": "T1555.003",
            "name": "Credentials from Web Browsers",
            "tactic": MitreTactic.CREDENTIAL_ACCESS,
            "description": "Adversaries may acquire credentials from web browsers."
        },
        # Exfiltration
        "T1041": {
            "id": "T1041",
            "name": "Exfiltration Over C2 Channel",
            "tactic": MitreTactic.EXFILTRATION,
            "description": "Adversaries may steal data by exfiltrating it over an existing C2 channel."
        },
        "T1567.002": {
            "id": "T1567.002",
            "name": "Exfiltration to Cloud Storage",
            "tactic": MitreTactic.EXFILTRATION,
            "description": "Adversaries may exfiltrate data to cloud storage services."
        },
        "T1020": {
            "id": "T1020",
            "name": "Automated Exfiltration",
            "tactic": MitreTactic.EXFILTRATION,
            "description": "Adversaries may exfiltrate data using automated methods."
        },
        "T1071.004": {
            "id": "T1071.004",
            "name": "DNS",
            "tactic": MitreTactic.EXFILTRATION,
            "description": "Adversaries may use DNS for data exfiltration."
        },
        # Privilege Escalation
        "T1548.002": {
            "id": "T1548.002",
            "name": "Bypass User Account Control",
            "tactic": MitreTactic.PRIVILEGE_ESCALATION,
            "description": "Adversaries may bypass UAC mechanisms to elevate privileges."
        },
        "T1543.003": {
            "id": "T1543.003",
            "name": "Create or Modify System Process: Windows Service",
            "tactic": MitreTactic.PRIVILEGE_ESCALATION,
            "description": "Adversaries may create or modify Windows services to escalate privileges."
        },
        "T1053.005": {
            "id": "T1053.005",
            "name": "Scheduled Task/Job: Scheduled Task",
            "tactic": MitreTactic.PRIVILEGE_ESCALATION,
            "description": "Adversaries may abuse task scheduling functionality to escalate privileges."
        },
        "T1134": {
            "id": "T1134",
            "name": "Access Token Manipulation",
            "tactic": MitreTactic.PRIVILEGE_ESCALATION,
            "description": "Adversaries may modify access tokens to escalate privileges."
        },
        "T1112": {
            "id": "T1112",
            "name": "Modify Registry",
            "tactic": MitreTactic.PRIVILEGE_ESCALATION,
            "description": "Adversaries may modify the registry to escalate privileges."
        },
        # Defense Evasion
        "T1055": {
            "id": "T1055",
            "name": "Process Injection",
            "tactic": MitreTactic.DEFENSE_EVASION,
            "description": "Adversaries may inject code into processes to evade defenses."
        },
        "T1070.001": {
            "id": "T1070.001",
            "name": "Indicator Removal: Clear Windows Event Logs",
            "tactic": MitreTactic.DEFENSE_EVASION,
            "description": "Adversaries may clear Windows event logs to hide their activity."
        },
        "T1218.005": {
            "id": "T1218.005",
            "name": "System Binary Proxy Execution: Mshta",
            "tactic": MitreTactic.DEFENSE_EVASION,
            "description": "Adversaries may abuse mshta.exe to execute malicious code."
        },
        # Persistence
        "T1547.001": {
            "id": "T1547.001",
            "name": "Boot or Logon Autostart Execution: Registry Run Keys",
            "tactic": MitreTactic.PERSISTENCE,
            "description": "Adversaries may modify registry run keys to maintain persistence."
        },
        # Execution
        "T1059.001": {
            "id": "T1059.001",
            "name": "Command and Scripting Interpreter: PowerShell",
            "tactic": MitreTactic.EXECUTION,
            "description": "Adversaries may abuse PowerShell to execute commands."
        },
        "T1059.003": {
            "id": "T1059.003",
            "name": "Command and Scripting Interpreter: Windows Command Shell",
            "tactic": MitreTactic.EXECUTION,
            "description": "Adversaries may abuse Windows command shell to execute commands."
        },
    }
    
    @classmethod
    def get_technique(cls, technique_id: str) -> Optional[Dict]:
        """Get technique information by ID"""
        return cls.TECHNIQUE_MAP.get(technique_id)
    
    @classmethod
    def get_all_techniques(cls) -> Dict[str, Dict]:
        """Get all techniques"""
        return cls.TECHNIQUE_MAP


@dataclass
class SecurityEvent:
    """Represents a security event from XQL query results"""
    timestamp: str
    event_type: str
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    file_path: Optional[str] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    user_sid: Optional[str] = None
    mitre_technique: Optional[str] = None
    severity: str = "Medium"
    description: Optional[str] = None
    raw_data: Optional[Dict] = None


@dataclass
class AttackTimeline:
    """Represents a timeline of attack events"""
    start_time: str
    end_time: str
    events: List[SecurityEvent]
    techniques: List[str]
    tactics: List[str]
    affected_hosts: List[str]
    affected_users: List[str]


class MitreAttackReporter:
    """Generates HTML reports with MITRE ATT&CK framework alignment"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.events: List[SecurityEvent] = []
        self.timeline: Optional[AttackTimeline] = None
        
    def load_from_json(self, json_file: str) -> None:
        """Load events from JSON file"""
        logger.info(f"Loading events from {json_file}")
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            self._parse_events(data)
    
    def load_from_csv(self, csv_file: str) -> None:
        """Load events from CSV file"""
        logger.info(f"Loading events from {csv_file}")
        events = []
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                event = self._parse_csv_row(row)
                if event:
                    events.append(event)
        self.events = events
        logger.info(f"Loaded {len(self.events)} events from CSV")
    
    def _parse_events(self, data: Any) -> None:
        """Parse events from JSON data"""
        events = []
        
        # Handle different JSON structures
        if isinstance(data, list):
            event_list = data
        elif isinstance(data, dict) and 'data' in data:
            event_list = data['data']
        elif isinstance(data, dict) and 'results' in data:
            event_list = data['results']
        else:
            event_list = [data]
        
        for item in event_list:
            event = self._parse_event_item(item)
            if event:
                events.append(event)
        
        self.events = events
        logger.info(f"Parsed {len(self.events)} events from JSON")
    
    def _parse_event_item(self, item: Dict) -> Optional[SecurityEvent]:
        """Parse a single event item"""
        try:
            # Map common XQL field names
            timestamp = item.get('event_time_ts') or item.get('timestamp') or item.get('time')
            if isinstance(timestamp, (int, float)):
                timestamp = datetime.fromtimestamp(timestamp).isoformat()
            
            event_type = item.get('event_type') or item.get('type', 'UNKNOWN')
            process_name = item.get('action_process_image_name') or item.get('process_name')
            command_line = item.get('action_process_command_line') or item.get('command_line')
            file_path = item.get('action_file_path') or item.get('file_path')
            remote_ip = item.get('action_remote_ip') or item.get('remote_ip')
            remote_port = item.get('action_remote_port') or item.get('remote_port')
            user_sid = item.get('actor_primary_user_sid') or item.get('user_sid')
            
            # Auto-detect MITRE technique based on indicators
            mitre_technique = self._detect_mitre_technique(item)
            
            return SecurityEvent(
                timestamp=str(timestamp),
                event_type=str(event_type),
                process_name=process_name,
                command_line=command_line,
                file_path=file_path,
                remote_ip=remote_ip,
                remote_port=int(remote_port) if remote_port else None,
                user_sid=user_sid,
                mitre_technique=mitre_technique,
                raw_data=item
            )
        except Exception as e:
            logger.warning(f"Error parsing event item: {e}")
            return None
    
    def _parse_csv_row(self, row: Dict) -> Optional[SecurityEvent]:
        """Parse a CSV row into a SecurityEvent"""
        try:
            timestamp = row.get('event_time_ts') or row.get('timestamp') or row.get('time', '')
            if timestamp and timestamp.replace('.', '').isdigit():
                timestamp = datetime.fromtimestamp(float(timestamp)).isoformat()
            
            return SecurityEvent(
                timestamp=timestamp,
                event_type=row.get('event_type', 'UNKNOWN'),
                process_name=row.get('action_process_image_name') or row.get('process_name'),
                command_line=row.get('action_process_command_line') or row.get('command_line'),
                file_path=row.get('action_file_path') or row.get('file_path'),
                remote_ip=row.get('action_remote_ip') or row.get('remote_ip'),
                remote_port=int(row.get('action_remote_port', 0)) if row.get('action_remote_port') else None,
                user_sid=row.get('actor_primary_user_sid') or row.get('user_sid'),
                raw_data=row
            )
        except Exception as e:
            logger.warning(f"Error parsing CSV row: {e}")
            return None
    
    def _detect_mitre_technique(self, item: Dict) -> Optional[str]:
        """Auto-detect MITRE technique based on event indicators"""
        process_name = (item.get('action_process_image_name') or '').lower()
        command_line = (item.get('action_process_command_line') or '').lower()
        file_path = (item.get('action_file_path') or '').lower()
        remote_port = item.get('action_remote_port')
        event_type = (item.get('event_type') or '').upper()
        
        # Lateral Movement - RDP
        if remote_port == 3389 or 'rdp' in command_line:
            return "T1021.001"
        
        # Lateral Movement - SMB
        if '\\\\' in file_path or 'smb' in command_line:
            return "T1021.002"
        
        # Credential Access - LSASS
        if process_name == 'lsass.exe' and event_type == 'PROCESS':
            return "T1003.001"
        
        # Credential Access - Browser credentials
        if 'login data' in file_path or 'logins.json' in file_path:
            return "T1555.003"
        
        # Privilege Escalation - UAC Bypass
        if process_name in ['eventvwr.exe', 'fodhelper.exe', 'sdclt.exe']:
            return "T1548.002"
        
        # Privilege Escalation - Service Creation
        if process_name == 'sc.exe' and 'create' in command_line:
            return "T1543.003"
        
        # Privilege Escalation - Scheduled Task
        if process_name == 'schtasks.exe' and 'create' in command_line:
            return "T1053.005"
        
        # Process Injection
        if process_name in ['rundll32.exe', 'regsvr32.exe'] and '.dll' in command_line:
            return "T1055"
        
        # Defense Evasion - Event Log Clearing
        if process_name == 'wevtutil.exe' and ('clear' in command_line or 'delete' in command_line):
            return "T1070.001"
        
        # Persistence - Registry Run Keys
        if event_type == 'REGISTRY' and 'run' in file_path.lower():
            return "T1547.001"
        
        # Execution - PowerShell
        if process_name == 'powershell.exe' and ('-enc' in command_line or '-encodedcommand' in command_line):
            return "T1059.001"
        
        return None
    
    def build_timeline(self) -> AttackTimeline:
        """Build attack timeline from events"""
        if not self.events:
            raise ValueError("No events loaded. Load events first.")
        
        sorted_events = sorted(self.events, key=lambda x: x.timestamp)
        start_time = sorted_events[0].timestamp if sorted_events else datetime.now().isoformat()
        end_time = sorted_events[-1].timestamp if sorted_events else datetime.now().isoformat()
        
        techniques = list(set([e.mitre_technique for e in self.events if e.mitre_technique]))
        tactics = list(set([
            MitreTechnique.get_technique(t)['tactic'].value[1] 
            for t in techniques 
            if MitreTechnique.get_technique(t)
        ]))
        
        affected_hosts = list(set([
            e.remote_ip for e in self.events 
            if e.remote_ip and not e.remote_ip.startswith('10.') and 
            not e.remote_ip.startswith('192.168.') and not e.remote_ip.startswith('172.16.')
        ]))
        
        affected_users = list(set([e.user_sid for e in self.events if e.user_sid]))
        
        self.timeline = AttackTimeline(
            start_time=start_time,
            end_time=end_time,
            events=sorted_events,
            techniques=techniques,
            tactics=tactics,
            affected_hosts=affected_hosts,
            affected_users=affected_users
        )
        
        return self.timeline
    
    def generate_html_report(self, output_file: Optional[str] = None) -> str:
        """Generate HTML report"""
        if not self.events:
            raise ValueError("No events loaded. Load events first.")
        
        if not self.timeline:
            self.build_timeline()
        
        # Prepare data for template
        report_data = {
            'generation_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_events': len(self.events),
            'timeline': self.timeline,
            'techniques': self._get_technique_details(),
            'tactics_summary': self._get_tactics_summary(),
            'events_by_severity': self._get_events_by_severity(),
            'top_processes': self._get_top_processes(),
            'top_hosts': self._get_top_hosts(),
        }
        
        # Generate HTML
        html_content = self._render_html_template(report_data)
        
        # Write to file
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = self.output_dir / f"mitre_attack_report_{timestamp}.html"
        else:
            output_file = Path(output_file)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Report generated: {output_file}")
        return str(output_file)
    
    def _get_technique_details(self) -> List[Dict]:
        """Get detailed information about detected techniques"""
        technique_counts = {}
        for event in self.events:
            if event.mitre_technique:
                if event.mitre_technique not in technique_counts:
                    technique_counts[event.mitre_technique] = 0
                technique_counts[event.mitre_technique] += 1
        
        details = []
        for tech_id, count in technique_counts.items():
            tech_info = MitreTechnique.get_technique(tech_id)
            if tech_info:
                details.append({
                    'id': tech_id,
                    'name': tech_info['name'],
                    'tactic': tech_info['tactic'].value[1],
                    'description': tech_info['description'],
                    'count': count
                })
        
        return sorted(details, key=lambda x: x['count'], reverse=True)
    
    def _get_tactics_summary(self) -> Dict[str, int]:
        """Get summary of tactics"""
        tactic_counts = {}
        for event in self.events:
            if event.mitre_technique:
                tech_info = MitreTechnique.get_technique(event.mitre_technique)
                if tech_info:
                    tactic = tech_info['tactic'].value[1]
                    tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        return tactic_counts
    
    def _get_events_by_severity(self) -> Dict[str, int]:
        """Get event counts by severity"""
        severity_counts = {}
        for event in self.events:
            severity = event.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        return severity_counts
    
    def _get_top_processes(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top processes by occurrence"""
        process_counts = {}
        for event in self.events:
            if event.process_name:
                process_counts[event.process_name] = process_counts.get(event.process_name, 0) + 1
        return sorted(process_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def _get_top_hosts(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top hosts by connection count"""
        host_counts = {}
        for event in self.events:
            if event.remote_ip:
                host_counts[event.remote_ip] = host_counts.get(event.remote_ip, 0) + 1
        return sorted(host_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    
    def _render_html_template(self, data: Dict) -> str:
        """Render HTML template with data"""
        template_str = self._get_html_template()
        template = Template(template_str)
        return template.render(**data)
    
    def _get_html_template(self) -> str:
        """Get HTML template"""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MITRE ATT&CK Incident Response Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .section {
            background: white;
            padding: 25px;
            margin-bottom: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        
        .section h3 {
            color: #764ba2;
            margin-top: 20px;
            margin-bottom: 15px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        
        .stat-card h3 {
            font-size: 2.5em;
            margin-bottom: 10px;
            color: white;
            border: none;
        }
        
        .stat-card p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .tactic-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            margin: 5px;
            background-color: #667eea;
            color: white;
        }
        
        .technique-card {
            border-left: 4px solid #667eea;
            padding: 15px;
            margin-bottom: 15px;
            background-color: #f9f9f9;
        }
        
        .technique-card h4 {
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .technique-id {
            font-family: 'Courier New', monospace;
            background-color: #667eea;
            color: white;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: bold;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            background-color: #667eea;
            color: white;
            font-weight: bold;
        }
        
        tr:hover {
            background-color: #f5f5f5;
        }
        
        .timeline {
            position: relative;
            padding: 20px 0;
        }
        
        .timeline-item {
            padding: 15px;
            margin-bottom: 15px;
            border-left: 3px solid #667eea;
            background-color: #f9f9f9;
            position: relative;
        }
        
        .timeline-item::before {
            content: '';
            position: absolute;
            left: -8px;
            top: 20px;
            width: 14px;
            height: 14px;
            border-radius: 50%;
            background-color: #667eea;
        }
        
        .severity-critical {
            color: #dc3545;
            font-weight: bold;
        }
        
        .severity-high {
            color: #fd7e14;
            font-weight: bold;
        }
        
        .severity-medium {
            color: #ffc107;
            font-weight: bold;
        }
        
        .severity-low {
            color: #28a745;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            margin-top: 40px;
        }
        
        .code-block {
            background-color: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
        }
        
        .tag {
            display: inline-block;
            padding: 3px 8px;
            background-color: #e9ecef;
            border-radius: 4px;
            font-size: 0.85em;
            margin: 2px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ MITRE ATT&CK Incident Response Report</h1>
            <p>Generated: {{ generation_time }}</p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>{{ total_events }}</h3>
                    <p>Total Events</p>
                </div>
                <div class="stat-card">
                    <h3>{{ timeline.techniques|length }}</h3>
                    <p>MITRE Techniques</p>
                </div>
                <div class="stat-card">
                    <h3>{{ timeline.tactics|length }}</h3>
                    <p>Attack Tactics</p>
                </div>
                <div class="stat-card">
                    <h3>{{ timeline.affected_hosts|length }}</h3>
                    <p>Affected Hosts</p>
                </div>
            </div>
            
            <h3>Timeline</h3>
            <p><strong>Start:</strong> {{ timeline.start_time }}</p>
            <p><strong>End:</strong> {{ timeline.end_time }}</p>
        </div>
        
        <div class="section">
            <h2>MITRE ATT&CK Techniques Detected</h2>
            {% for technique in techniques %}
            <div class="technique-card">
                <h4>
                    <span class="technique-id">{{ technique.id }}</span> - {{ technique.name }}
                </h4>
                <p><strong>Tactic:</strong> <span class="tactic-badge">{{ technique.tactic }}</span></p>
                <p><strong>Description:</strong> {{ technique.description }}</p>
                <p><strong>Occurrences:</strong> {{ technique.count }} event(s)</p>
            </div>
            {% endfor %}
        </div>
        
        <div class="section">
            <h2>Tactics Summary</h2>
            {% for tactic, count in tactics_summary.items() %}
            <div style="margin-bottom: 10px;">
                <strong>{{ tactic }}</strong>: {{ count }} event(s)
                <div style="width: 100%; background-color: #e9ecef; border-radius: 4px; height: 20px; margin-top: 5px;">
                    <div style="background-color: #667eea; height: 100%; width: {{ (count / total_events * 100)|round }}%; border-radius: 4px;"></div>
                </div>
            </div>
            {% endfor %}
        </div>
        
        <div class="section">
            <h2>Top Processes</h2>
            <table>
                <thead>
                    <tr>
                        <th>Process Name</th>
                        <th>Occurrences</th>
                    </tr>
                </thead>
                <tbody>
                    {% for process, count in top_processes %}
                    <tr>
                        <td><code>{{ process }}</code></td>
                        <td>{{ count }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Top External Hosts</h2>
            <table>
                <thead>
                    <tr>
                        <th>Host IP</th>
                        <th>Connections</th>
                    </tr>
                </thead>
                <tbody>
                    {% for host, count in top_hosts %}
                    <tr>
                        <td><code>{{ host }}</code></td>
                        <td>{{ count }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Event Timeline</h2>
            <div class="timeline">
                {% for event in timeline.events[:100] %}
                <div class="timeline-item">
                    <strong>{{ event.timestamp }}</strong> - {{ event.event_type }}
                    {% if event.process_name %}
                    <br><span class="tag">Process: {{ event.process_name }}</span>
                    {% endif %}
                    {% if event.mitre_technique %}
                    <br><span class="technique-id">{{ event.mitre_technique }}</span>
                    {% endif %}
                    {% if event.command_line %}
                    <div class="code-block">{{ event.command_line[:200] }}{% if event.command_line|length > 200 %}...{% endif %}</div>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
            {% if timeline.events|length > 100 %}
            <p><em>Showing first 100 events. Total: {{ timeline.events|length }}</em></p>
            {% endif %}
        </div>
        
        <div class="section">
            <h2>Affected Systems</h2>
            <h3>Hosts</h3>
            <ul>
                {% for host in timeline.affected_hosts %}
                <li><code>{{ host }}</code></li>
                {% endfor %}
            </ul>
            
            <h3>Users</h3>
            <ul>
                {% for user in timeline.affected_users %}
                <li><code>{{ user }}</code></li>
                {% endfor %}
            </ul>
        </div>
        
        <div class="footer">
            <p>Report generated by Cortex XDR XQL MITRE ATT&CK Reporter v1.0</p>
            <p>For questions or issues, contact Security Operations</p>
        </div>
    </div>
</body>
</html>"""


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Generate MITRE ATT&CK HTML reports from XQL query results'
    )
    parser.add_argument(
        'input_file',
        help='Input file (JSON or CSV) containing XQL query results'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output HTML file path (default: auto-generated)'
    )
    parser.add_argument(
        '-d', '--output-dir',
        default='reports',
        help='Output directory for reports (default: reports)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize reporter
    reporter = MitreAttackReporter(output_dir=args.output_dir)
    
    # Load data
    input_path = Path(args.input_file)
    if not input_path.exists():
        logger.error(f"Input file not found: {args.input_file}")
        return 1
    
    if input_path.suffix.lower() == '.json':
        reporter.load_from_json(str(input_path))
    elif input_path.suffix.lower() == '.csv':
        reporter.load_from_csv(str(input_path))
    else:
        logger.error(f"Unsupported file format: {input_path.suffix}")
        logger.info("Supported formats: .json, .csv")
        return 1
    
    # Generate report
    try:
        output_file = reporter.generate_html_report(args.output)
        print(f"✓ Report generated successfully: {output_file}")
        return 0
    except Exception as e:
        logger.error(f"Error generating report: {e}", exc_info=True)
        return 1


if __name__ == '__main__':
    exit(main())
