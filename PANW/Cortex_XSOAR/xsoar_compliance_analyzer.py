import os
import json
import logging
import warnings
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import pickle

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from jinja2 import Template
import requests
from requests.auth import HTTPBasicAuth

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ComplianceFramework(Enum):
    OWASP_TOP_10 = "OWASP Top 10"
    CSA_CCM = "CSA CCM"
    HIPAA = "HIPAA"
    SOC2 = "SOC2"
    PCI_DSS = "PCI DSS"
    GDPR = "GDPR"
    CCPA = "CCPA"
    NIST_CSF = "NIST CSF"
    ISO_27001 = "ISO 27001"
    CIS = "CIS Controls"

class ThreatSeverity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

@dataclass
class ComplianceControl:
    framework: ComplianceFramework
    control_id: str
    description: str
    requirements: List[str]
    mapped_incidents: List[str]
    compliance_score: float

@dataclass
class VulnerabilityPrediction:
    vulnerability_id: str
    cve_id: Optional[str]
    exploit_likelihood: float
    data_breach_risk: float
    data_exfiltration_risk: float
    apt_target_probability: float
    recommended_actions: List[str]
    risk_level: ThreatSeverity

@dataclass
class IncidentData:
    incident_id: str
    name: str
    created: datetime
    severity: int
    type: str
    status: str
    details: Dict[str, Any]
    raw_data: Dict[str, Any]

class XSOARClient:
    """Client for interacting with Cortex XSOAR API"""
    
    def __init__(self, server_url: str, api_key: str, verify_ssl: bool = True):
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
    def get_incidents(self, 
                     query: str = "",
                     from_date: Optional[datetime] = None,
                     to_date: Optional[datetime] = None,
                     limit: int = 1000) -> List[Dict]:
        """Fetch incidents from XSOAR"""
        params = {
            "query": query,
            "size": limit,
            "sort": [{"field": "created", "asc": False}]
        }
        
        if from_date:
            params["from"] = from_date.isoformat()
        if to_date:
            params["to"] = to_date.isoformat()
            
        url = f"{self.server_url}/incidents/search"
        
        try:
            response = requests.post(
                url,
                headers=self.headers,
                params={"apikey": self.api_key},
                json=params,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            return response.json().get("data", [])
        except Exception as e:
            logger.error(f"Error fetching incidents: {e}")
            return []
    
    def get_incident_details(self, incident_id: str) -> Optional[Dict]:
        """Get detailed information about a specific incident"""
        url = f"{self.server_url}/incident"
        params = {"id": incident_id, "apikey": self.api_key}
        
        try:
            response = requests.get(url, params=params, verify=self.verify_ssl)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Error fetching incident {incident_id}: {e}")
            return None

class ComplianceMapper:
    """Maps incidents to compliance frameworks"""
    
    def __init__(self):
        self.framework_mappings = self._load_framework_mappings()
        
    def _load_framework_mappings(self) -> Dict:
        """Load compliance framework control mappings"""
        # This would typically be loaded from a database or configuration file
        mappings = {
            ComplianceFramework.OWASP_TOP_10: {
                "A01:2021-Broken Access Control": [
                    "Unauthorized access", "Privilege escalation", "IDOR"
                ],
                "A02:2021-Cryptographic Failures": [
                    "Weak encryption", "Missing TLS", "Sensitive data exposure"
                ],
                "A03:2021-Injection": [
                    "SQL injection", "XSS", "Command injection"
                ],
                # ... other OWASP categories
            },
            ComplianceFramework.HIPAA: {
                "164.308(a)(1) - Security Management Process": [
                    "Risk analysis", "Security incident", "Audit controls"
                ],
                "164.308(a)(3) - Workforce Security": [
                    "Unauthorized access", "Employee termination"
                ],
                # ... other HIPAA controls
            },
            # ... mappings for other frameworks
        }
        return mappings
    
    def map_incident_to_frameworks(self, incident: IncidentData) -> Dict[ComplianceFramework, List[str]]:
        """Map an incident to relevant compliance frameworks and controls"""
        mappings = {}
        
        for framework, controls in self.framework_mappings.items():
            matched_controls = []
            for control, keywords in controls.items():
                # Check incident details against keywords
                incident_text = f"{incident.name} {incident.type} {json.dumps(incident.details)}".lower()
                if any(keyword.lower() in incident_text for keyword in keywords):
                    matched_controls.append(control)
            
            if matched_controls:
                mappings[framework] = matched_controls
                
        return mappings

class MLPredictor:
    """Machine Learning for vulnerability prediction"""
    
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.is_trained = False
        
    def prepare_features(self, incidents: List[IncidentData]) -> pd.DataFrame:
        """Prepare features from incident data for ML"""
        features = []
        
        for incident in incidents:
            # Extract temporal features
            created = incident.created
            hour = created.hour
            day_of_week = created.weekday()
            month = created.month
            
            # Extract incident features
            severity = incident.severity
            has_cve = 1 if 'cve' in incident.details else 0
            has_exploit = 1 if 'exploit' in incident.details else 0
            data_sensitivity = incident.details.get('data_sensitivity', 0)
            
            # Calculate derived features
            incident_age = (datetime.now() - created).days
            
            features.append([
                severity,
                hour,
                day_of_week,
                month,
                has_cve,
                has_exploit,
                data_sensitivity,
                incident_age,
                len(incident.details)
            ])
            
        columns = [
            'severity', 'hour', 'day_of_week', 'month',
            'has_cve', 'has_exploit', 'data_sensitivity',
            'incident_age', 'detail_length'
        ]
        
        return pd.DataFrame(features, columns=columns)
    
    def train(self, incidents: List[IncidentData], labels: List[str]):
        """Train the ML model"""
        X = self.prepare_features(incidents)
        y = self.label_encoder.fit_transform(labels)
        
        # Handle class imbalance
        smote = SMOTE(random_state=42)
        X_resampled, y_resampled = smote.fit_resample(X, y)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_resampled, y_resampled, test_size=0.2, random_state=42
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        logger.info("Model training completed")
        logger.info(f"Classification Report:\n{classification_report(y_test, y_pred)}")
        
        self.is_trained = True
        
        # Train anomaly detector
        self.anomaly_detector.fit(X_train_scaled)
        
    def predict_vulnerability_risk(self, incident: IncidentData) -> VulnerabilityPrediction:
        """Predict risks for a vulnerability"""
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        # Prepare features for single incident
        X = self.prepare_features([incident])
        X_scaled = self.scaler.transform(X)
        
        # Get anomaly score
        anomaly_score = self.anomaly_detector.score_samples(X_scaled)[0]
        anomaly_prob = 1 / (1 + np.exp(-anomaly_score))
        
        # Get feature importances for explanation
        feature_names = X.columns
        importances = self.model.feature_importances_
        
        # Calculate risk scores (in a real scenario, these would come from the model)
        exploit_likelihood = min(0.9, max(0.1, incident.severity / 4 + anomaly_prob * 0.3))
        data_breach_risk = min(0.95, exploit_likelihood * 1.2)
        exfiltration_risk = data_breach_risk * 0.8
        
        # APT targeting probability
        apt_prob = 0.0
        if incident.severity >= 3 and 'cve' in incident.details:
            apt_prob = min(0.7, exploit_likelihood * 0.9)
        
        # Determine risk level
        overall_risk = max(exploit_likelihood, data_breach_risk, exfiltration_risk)
        if overall_risk >= 0.8:
            risk_level = ThreatSeverity.CRITICAL
        elif overall_risk >= 0.6:
            risk_level = ThreatSeverity.HIGH
        elif overall_risk >= 0.4:
            risk_level = ThreatSeverity.MEDIUM
        elif overall_risk >= 0.2:
            risk_level = ThreatSeverity.LOW
        else:
            risk_level = ThreatSeverity.INFO
        
        # Generate recommendations
        recommendations = []
        if exploit_likelihood > 0.7:
            recommendations.append("Apply security patches immediately")
        if data_breach_risk > 0.6:
            recommendations.append("Implement additional monitoring and alerting")
        if apt_prob > 0.5:
            recommendations.append("Conduct threat hunting exercise")
        
        return VulnerabilityPrediction(
            vulnerability_id=incident.incident_id,
            cve_id=incident.details.get('cve'),
            exploit_likelihood=exploit_likelihood,
            data_breach_risk=data_breach_risk,
            data_exfiltration_risk=exfiltration_risk,
            apt_target_probability=apt_prob,
            recommended_actions=recommendations,
            risk_level=risk_level
        )
    
    def save_model(self, path: str):
        """Save trained model to disk"""
        with open(path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler,
                'label_encoder': self.label_encoder,
                'anomaly_detector': self.anomaly_detector
            }, f)
    
    def load_model(self, path: str):
        """Load trained model from disk"""
        with open(path, 'rb') as f:
            data = pickle.load(f)
            self.model = data['model']
            self.scaler = data['scaler']
            self.label_encoder = data['label_encoder']
            self.anomaly_detector = data['anomaly_detector']
            self.is_trained = True

class ReportGenerator:
    """Generate HTML reports with visualizations"""
    
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
    def create_compliance_heatmap(self, compliance_data: Dict[ComplianceFramework, List[ComplianceControl]]) -> go.Figure:
        """Create heatmap of compliance framework coverage"""
        frameworks = []
        scores = []
        
        for framework, controls in compliance_data.items():
            frameworks.append(framework.value)
            if controls:
                avg_score = np.mean([c.compliance_score for c in controls])
                scores.append(avg_score)
            else:
                scores.append(0)
        
        # Create heatmap data
        fig = go.Figure(data=go.Heatmap(
            z=[scores],
            x=frameworks,
            y=['Compliance Score'],
            colorscale='RdYlGn',
            zmin=0,
            zmax=100,
            text=[[f"{s:.1f}%" for s in scores]],
            texttemplate="%{text}",
            textfont={"size": 14}
        ))
        
        fig.update_layout(
            title="Compliance Framework Coverage Heatmap",
            xaxis_title="Framework",
            yaxis_title="",
            height=400
        )
        
        return fig
    
    def create_risk_distribution_chart(self, predictions: List[VulnerabilityPrediction]) -> go.Figure:
        """Create pie chart of risk distribution"""
        risk_counts = {}
        for pred in predictions:
            risk = pred.risk_level.value
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        fig = go.Figure()
        if risk_counts:
            fig.add_trace(go.Pie(
                labels=list(risk_counts.keys()),
                values=list(risk_counts.values()),
                hole=.3,
                marker_colors=px.colors.sequential.RdBu
            ))
        else:
            fig.add_annotation(text="No prediction data", showarrow=False, x=0.5, y=0.5, xref="paper", yref="paper")
        fig.update_layout(title="Vulnerability Risk Level Distribution")
        
        return fig
    
    def create_timeline_chart(self, incidents: List[IncidentData]) -> go.Figure:
        """Create timeline of incidents"""
        dates = [incident.created for incident in incidents]
        severities = [incident.severity for incident in incidents]
        
        fig = go.Figure()
        
        if incidents:
            fig.add_trace(go.Scatter(
                x=dates,
                y=severities,
                mode='markers',
                marker=dict(
                    size=10,
                    color=severities,
                    colorscale='Reds',
                    showscale=True
                ),
                text=[incident.name for incident in incidents],
                hovertemplate='<b>%{text}</b><br>Date: %{x}<br>Severity: %{y}<extra></extra>'
            ))
        else:
            fig.add_annotation(text="No incident data", showarrow=False, x=0.5, y=0.5, xref="paper", yref="paper")
        
        fig.update_layout(
            title="Incident Timeline",
            xaxis_title="Date",
            yaxis_title="Severity",
            height=500
        )
        
        return fig
    
    def create_ml_feature_importance(self, ml_predictor: MLPredictor) -> go.Figure:
        """Create feature importance bar chart"""
        if not ml_predictor.is_trained:
            return None
            
        feature_names = ml_predictor.prepare_features([]).columns
        importances = ml_predictor.model.feature_importances_
        
        # Sort by importance
        indices = np.argsort(importances)[::-1]
        
        fig = go.Figure(data=[go.Bar(
            x=[feature_names[i] for i in indices],
            y=[importances[i] for i in indices],
            marker_color='lightblue'
        )])
        
        fig.update_layout(
            title="ML Model Feature Importance",
            xaxis_title="Features",
            yaxis_title="Importance",
            height=500
        )
        
        return fig
    
    def generate_html_report(self,
                           incidents: List[IncidentData],
                           compliance_data: Dict[ComplianceFramework, List[ComplianceControl]],
                           predictions: List[VulnerabilityPrediction],
                           ml_predictor: MLPredictor,
                           report_title: str = "Security Compliance Report") -> str:
        """Generate complete HTML report"""
        
        # Generate charts
        heatmap = self.create_compliance_heatmap(compliance_data)
        risk_chart = self.create_risk_distribution_chart(predictions)
        timeline = self.create_timeline_chart(incidents)
        feature_importance = self.create_ml_feature_importance(ml_predictor)
        
        # Calculate statistics
        total_incidents = len(incidents)
        avg_severity = np.mean([inc.severity for inc in incidents])
        critical_vulns = sum(1 for p in predictions if p.risk_level == ThreatSeverity.CRITICAL)
        
        # HTML Template
        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{{ title }}</title>
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background-color: #f5f5f5;
                }
                .header {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    border-radius: 10px;
                    margin-bottom: 30px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }
                .stat-card {
                    background: white;
                    border-radius: 10px;
                    padding: 20px;
                    margin: 10px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    flex: 1;
                    min-width: 200px;
                }
                .stat-container {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 20px;
                    margin-bottom: 30px;
                }
                .chart-container {
                    background: white;
                    border-radius: 10px;
                    padding: 20px;
                    margin-bottom: 30px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .stat-value {
                    font-size: 2.5em;
                    font-weight: bold;
                    color: #667eea;
                }
                .stat-label {
                    color: #666;
                    font-size: 0.9em;
                    text-transform: uppercase;
                }
                .compliance-table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }
                .compliance-table th, .compliance-table td {
                    border: 1px solid #ddd;
                    padding: 12px;
                    text-align: left;
                }
                .compliance-table th {
                    background-color: #667eea;
                    color: white;
                }
                .risk-critical { background-color: #ff4444; color: white; }
                .risk-high { background-color: #ff9933; }
                .risk-medium { background-color: #ffcc00; }
                .risk-low { background-color: #33cc33; }
                .risk-info { background-color: #6699ff; color: white; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{{ title }}</h1>
                <p>Generated on: {{ generation_date }}</p>
            </div>
            
            <div class="stat-container">
                <div class="stat-card">
                    <div class="stat-value">{{ total_incidents }}</div>
                    <div class="stat-label">Total Incidents</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ critical_vulns }}</div>
                    <div class="stat-label">Critical Vulnerabilities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ avg_severity|round(2) }}</div>
                    <div class="stat-label">Average Severity</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ frameworks_covered }}</div>
                    <div class="stat-label">Frameworks Covered</div>
                </div>
            </div>
            
            <div class="chart-container">
                <h2>Compliance Framework Coverage</h2>
                <div id="heatmap">{{ heatmap_html }}</div>
            </div>
            
            <div class="chart-container">
                <h2>Vulnerability Risk Distribution</h2>
                <div id="risk-chart">{{ risk_chart_html }}</div>
            </div>
            
            <div class="chart-container">
                <h2>Incident Timeline</h2>
                <div id="timeline">{{ timeline_html }}</div>
            </div>
            
            {% if feature_importance_html %}
            <div class="chart-container">
                <h2>ML Feature Importance</h2>
                <div id="feature-importance">{{ feature_importance_html }}</div>
            </div>
            {% endif %}
            
            <div class="chart-container">
                <h2>Top Risk Predictions</h2>
                <table class="compliance-table">
                    <thead>
                        <tr>
                            <th>Vulnerability ID</th>
                            <th>Exploit Likelihood</th>
                            <th>Data Breach Risk</th>
                            <th>APT Probability</th>
                            <th>Risk Level</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for pred in top_predictions %}
                        <tr>
                            <td>{{ pred.vulnerability_id }}</td>
                            <td>{{ (pred.exploit_likelihood * 100)|round(1) }}%</td>
                            <td>{{ (pred.data_breach_risk * 100)|round(1) }}%</td>
                            <td>{{ (pred.apt_target_probability * 100)|round(1) }}%</td>
                            <td class="risk-{{ pred.risk_level.value|lower }}">{{ pred.risk_level.value }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            
            <script>
                // Plotly charts rendering
                Plotly.newPlot('heatmap', {{ heatmap_json|safe }});
                Plotly.newPlot('risk-chart', {{ risk_chart_json|safe }});
                Plotly.newPlot('timeline', {{ timeline_json|safe }});
                {% if feature_importance_json %}
                Plotly.newPlot('feature-importance', {{ feature_importance_json|safe }});
                {% endif %}
            </script>
        </body>
        </html>
        """
        
        # Prepare data for template
        template_data = {
            'title': report_title,
            'generation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_incidents': total_incidents,
            'critical_vulns': critical_vulns,
            'avg_severity': avg_severity,
            'frameworks_covered': len(compliance_data),
            'top_predictions': sorted(predictions, 
                                    key=lambda x: x.exploit_likelihood, 
                                    reverse=True)[:10],
            'heatmap_html': '',
            'heatmap_json': heatmap.to_json(),
            'risk_chart_html': '',
            'risk_chart_json': risk_chart.to_json(),
            'timeline_html': '',
            'timeline_json': timeline.to_json(),
            'feature_importance_html': '',
            'feature_importance_json': feature_importance.to_json() if feature_importance else None
        }
        
        # Render template
        template = Template(html_template)
        html_content = template.render(**template_data)
        
        # Save to file
        filename = f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Report generated: {filepath}")
        return filepath

class ComplianceAnalyzer:
    """Main analyzer class"""
    
    def __init__(self, xsoar_client: XSOARClient, output_dir: str = "./reports"):
        self.xsoar_client = xsoar_client
        self.compliance_mapper = ComplianceMapper()
        self.ml_predictor = MLPredictor()
        self.report_generator = ReportGenerator(output_dir=output_dir)
    
    def generate_demo_incidents(self, count: int = 100, days_back: int = 30) -> List[IncidentData]:
        incidents: List[IncidentData] = []
        np.random.seed(42)
        now = datetime.now()
        types = ["Vulnerability", "Phishing", "Malware", "Policy Violation", "Anomaly"]
        for i in range(count):
            created_offset_days = np.random.randint(0, max(1, days_back))
            created = now - timedelta(days=int(created_offset_days), hours=int(np.random.randint(0, 24)))
            severity = int(np.random.randint(0, 5))
            itype = np.random.choice(types, p=[0.35, 0.2, 0.2, 0.15, 0.1])
            keywords_pool = [
                "Unauthorized access", "Privilege escalation", "IDOR",
                "Weak encryption", "Missing TLS", "Sensitive data exposure",
                "SQL injection", "XSS", "Command injection",
                "Risk analysis", "Security incident", "Audit controls",
                "Employee termination"
            ]
            details = {
                "data_sensitivity": float(np.random.choice([0, 1, 3, 5, 8, 10])),
            }
            if np.random.rand() < 0.5:
                details["description"] = np.random.choice(keywords_pool)
            if np.random.rand() < 0.3:
                details["cve"] = f"CVE-202{np.random.randint(0, 6)}-{np.random.randint(1000, 9999)}"
            if np.random.rand() < 0.25:
                details["exploit"] = True
            incident = IncidentData(
                incident_id=f"DEMO-{i+1}",
                name=f"Demo Incident {i+1}",
                created=created,
                severity=severity,
                type=itype,
                status="Closed" if np.random.rand() < 0.5 else "Open",
                details=details,
                raw_data={}
            )
            incidents.append(incident)
        return incidents
        
    def analyze_incidents(self, 
                         days_back: int = 30,
                         train_ml: bool = True,
                         demo: bool = False) -> Dict[str, Any]:
        """Main analysis method"""
        
        # Calculate date range
        to_date = datetime.now()
        from_date = to_date - timedelta(days=days_back)
        
        incidents: List[IncidentData] = []
        if demo:
            incidents = self.generate_demo_incidents(count=200, days_back=days_back)
            logger.info(f"Generated {len(incidents)} demo incidents")
        else:
            logger.info(f"Fetching incidents from {from_date} to {to_date}")
            raw_incidents = self.xsoar_client.get_incidents(
                from_date=from_date,
                to_date=to_date,
                limit=5000
            )
            for raw_inc in raw_incidents:
                incident = IncidentData(
                    incident_id=raw_inc.get('id'),
                    name=raw_inc.get('name', 'Unknown'),
                    created=datetime.fromisoformat(raw_inc.get('created', '2000-01-01')),
                    severity=raw_inc.get('severity', 0),
                    type=raw_inc.get('type', 'Unknown'),
                    status=raw_inc.get('status', 'Unknown'),
                    details=raw_inc.get('CustomFields', {}),
                    raw_data=raw_inc
                )
                incidents.append(incident)
            
        logger.info(f"Processed {len(incidents)} incidents")
        
        # Map to compliance frameworks
        compliance_data = {}
        for framework in ComplianceFramework:
            compliance_data[framework] = []
            
        for incident in incidents:
            mappings = self.compliance_mapper.map_incident_to_frameworks(incident)
            for framework, controls in mappings.items():
                for control in controls:
                    compliance_data[framework].append(control)
        
        # Train ML model if requested
        if train_ml and incidents:
            # Generate synthetic labels for training (in real scenario, these would come from historical data)
            labels = ['high_risk' if inc.severity >= 3 else 'low_risk' for inc in incidents]
            self.ml_predictor.train(incidents, labels)
            logger.info("ML model trained successfully")
        
        # Generate predictions
        predictions = []
        for incident in incidents:
            if 'vulnerability' in incident.type.lower():
                try:
                    pred = self.ml_predictor.predict_vulnerability_risk(incident)
                    predictions.append(pred)
                except Exception as e:
                    logger.warning(f"Could not predict for incident {incident.incident_id}: {e}")
        
        # Generate compliance controls with scores
        compliance_controls = {}
        for framework, controls in compliance_data.items():
            if controls:
                control_objs = []
                for control in set(controls):  # Deduplicate
                    # Calculate compliance score (simplified)
                    mapped_incidents = [inc for inc in incidents 
                                      if control in self.compliance_mapper.map_incident_to_frameworks(inc).get(framework, [])]
                    score = min(100, len(mapped_incidents) * 10)  # Simplified scoring
                    
                    control_obj = ComplianceControl(
                        framework=framework,
                        control_id=control,
                        description=f"Control for {control}",
                        requirements=[],
                        mapped_incidents=[inc.incident_id for inc in mapped_incidents],
                        compliance_score=score
                    )
                    control_objs.append(control_obj)
                
                compliance_controls[framework] = control_objs
        
        # Generate report
        report_path = self.report_generator.generate_html_report(
            incidents=incidents,
            compliance_data=compliance_controls,
            predictions=predictions,
            ml_predictor=self.ml_predictor,
            report_title=f"Security Compliance Analysis - Last {days_back} Days"
        )
        
        return {
            'incidents': incidents,
            'compliance_data': compliance_controls,
            'predictions': predictions,
            'report_path': report_path,
            'summary': {
                'total_incidents': len(incidents),
                'frameworks_covered': len([f for f, c in compliance_controls.items() if c]),
                'total_predictions': len(predictions),
                'critical_predictions': len([p for p in predictions if p.risk_level == ThreatSeverity.CRITICAL])
            }
        }

# Main execution script
if __name__ == "__main__":
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description='Cortex XSOAR Compliance Analyzer')
    parser.add_argument('--server', help='XSOAR server URL')
    parser.add_argument('--api-key', help='XSOAR API key')
    parser.add_argument('--days', type=int, default=30, help='Number of days to analyze')
    parser.add_argument('--output-dir', default='./reports', help='Output directory for reports')
    parser.add_argument('--no-ml', action='store_true', help='Disable ML predictions')
    parser.add_argument('--verify-ssl', action='store_true', default=True, help='Verify SSL certificates')
    parser.add_argument('--demo', action='store_true', help='Generate demo report with synthetic data')
    
    args = parser.parse_args()
    
    if not args.demo and (not args.server or not args.api_key):
        print("Error: --server and --api-key are required unless --demo is specified.")
        sys.exit(2)
    
    client = XSOARClient(
        server_url=args.server or "",
        api_key=args.api_key or "",
        verify_ssl=args.verify_ssl
    )
    
    analyzer = ComplianceAnalyzer(client, output_dir=args.output_dir)
    
    # Run analysis
    results = analyzer.analyze_incidents(
        days_back=args.days,
        train_ml=not args.no_ml,
        demo=args.demo
    )
    
    # Print summary
    print("\n" + "="*60)
    print("ANALYSIS COMPLETE")
    print("="*60)
    print(f"Report generated: {results['report_path']}")
    print(f"Total incidents analyzed: {results['summary']['total_incidents']}")
    print(f"Frameworks covered: {results['summary']['frameworks_covered']}")
    print(f"Vulnerability predictions: {results['summary']['total_predictions']}")
    print(f"Critical vulnerabilities: {results['summary']['critical_predictions']}")
    print("="*60)

