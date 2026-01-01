

 Key Features Implemented:

# 1. ML Risk Prediction (Python)
- ✅ TensorFlow/Keras Neural Network - Deep learning model for exploit likelihood
- ✅ Random Forest (scikit-learn) - Ensemble prediction
- ✅ PyTorch Support - Ready for custom architectures
- ✅ Ensemble Predictions - Combines RF and NN for accuracy

# 2. Advanced Visualizations (Matplotlib)
- ✅ Severity Distribution Chart - Bar chart with color coding
- ✅ Exploit Likelihood Distribution - Histogram with statistical overlays
- ✅ Risk Score Heatmap - Seaborn heatmap showing risk by category
- ✅ Base64 Encoded Images - Embedded in JSON report

# 3. Predictive Analytics
- ✅ Exploit Likelihood Score (0-1) - ML prediction of exploitation probability
- ✅ Risk Score (0-100) - Combined CVSS + exploit likelihood
- ✅ Feature Importance - Shows which factors contribute most to risk
- ✅ Confidence Metrics - Model agreement scores

# 4. Security Framework Coverage
- ✅ OWASP Top 10 2021 - All categories mapped
- ✅ CSA CCM Controls - 13 control domains
- ✅ CWE IDs - Common Weakness Enumeration
- ✅ CVSS Scores - Industry-standard severity

# 5. Compliance Mapping
- ✅ GDPR, HIPAA, PCI-DSS, SOC2, ISO27001
- ✅ Automatic Framework Detection
- ✅ Compliance Summary in reports

# 6. Detailed JSON Reports Include:
```json
{
  "scan_metadata": { "timestamp", "totals", "severity_counts" },
  "risk_analysis": {
    "average_exploit_likelihood": 0.67,
    "average_risk_score": 7.8,
    "high_risk_findings": 12
  },
  "compliance_summary": { "SOC2": 8, "PCI-DSS": 5 },
  "owasp_mapping": { "A01": 10, "A02": 5 },
  "findings": [ /* detailed findings */ ],
  "visualizations": {
    "severity_distribution": "base64_image",
    "exploit_likelihood": "base64_image",
    "risk_heatmap": "base64_image"
  },
  "recommendations": [ /* prioritized actions */ ]
}
```

 Usage:

# Python Version:
```bash
pip install tensorflow scikit-learn torch matplotlib seaborn pandas numpy

python terraform_scanner.py
```

# Go Version:
```bash
go build terraform_scanner.go
./terraform_scanner ./terraform_directory
```

 ML Model Architecture:

Neural Network (TensorFlow/Keras):
- Input: 9 features (CVSS, severity, public exposure, etc.)
- Hidden layers: 64 → 32 neurons with dropout
- Output: Sigmoid activation for probability
- Trained on synthetic data modeling real exploit patterns

Random Forest:
- 100 estimators for ensemble learning
- Provides feature importance rankings
- Robust to outliers

Ensemble Approach:
- Averages both predictions
- Confidence metric from model agreement
- Better generalization

 Risk Calculation Formula:
```
Risk Score = (0.4 × CVSS_Score) + (0.6 × Exploit_Likelihood × 10)
```

This gives you a 0-100 score where:
- 90-100: Immediate action required
- 70-89: High priority
- 50-69: Medium priority
- <50: Low priority

The ML models predict which vulnerabilities are most likely to be exploited based on characteristics like public exposure, authentication requirements, data sensitivity, and attack surface.