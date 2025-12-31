package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// SecurityRule represents a security policy rule
type SecurityRule struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Severity        string   `json:"severity"`
	Provider        string   `json:"provider"`
	ResourceType    string   `json:"resource_type"`
	Pattern         string   `json:"pattern"`
	OwaspMapping    []string `json:"owasp_mapping"`
	CsaCcmMapping   []string `json:"csa_ccm_mapping"`
	Description     string   `json:"description"`
	Recommendation  string   `json:"recommendation"`
	CompiledPattern *regexp.Regexp
}

// Finding represents a security finding
type Finding struct {
	RuleID          string   `json:"rule_id"`
	RuleName        string   `json:"rule_name"`
	Severity        string   `json:"severity"`
	File            string   `json:"file"`
	Line            int      `json:"line"`
	ResourceType    string   `json:"resource_type"`
	Description     string   `json:"description"`
	Recommendation  string   `json:"recommendation"`
	OwaspMapping    []string `json:"owasp_mapping"`
	CsaCcmMapping   []string `json:"csa_ccm_mapping"`
	MatchedText     string   `json:"matched_text"`
}

// ScanMetadata contains scan information
type ScanMetadata struct {
	ScanDate          string `json:"scan_date"`
	ScannerVersion    string `json:"scanner_version"`
	TotalFilesScanned int    `json:"total_files_scanned"`
	TotalFindings     int    `json:"total_findings"`
}

// SeverityStats tracks findings by severity
type SeverityStats struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// ExecutiveSummary provides high-level overview
type ExecutiveSummary struct {
	SeverityBreakdown SeverityStats `json:"severity_breakdown"`
	RiskScore         int           `json:"risk_score"`
	ComplianceStatus  string        `json:"compliance_status"`
}

// ComplianceMapping tracks OWASP and CSA CCM coverage
type ComplianceMapping struct {
	OwaspTop10 struct {
		Coverage         map[string]int `json:"coverage"`
		TotalCategories  int            `json:"total_categories"`
	} `json:"owasp_top_10"`
	CsaCcm struct {
		Coverage      map[string]int `json:"coverage"`
		TotalControls int            `json:"total_controls"`
	} `json:"csa_ccm"`
}

// Recommendation provides prioritized remediation guidance
type Recommendation struct {
	Priority    int    `json:"priority"`
	RuleID      string `json:"rule_id"`
	RuleName    string `json:"rule_name"`
	Occurrences int    `json:"occurrences"`
	Severity    string `json:"severity"`
	Action      string `json:"action"`
}

// RemediationPriority organizes findings by timeline
type RemediationPriority struct {
	ImmediateActionRequired []Finding `json:"immediate_action_required"`
	ShortTerm30Days         []Finding `json:"short_term_30_days"`
	MediumTerm90Days        []Finding `json:"medium_term_90_days"`
	LongTermPlanning        []Finding `json:"long_term_planning"`
}

// SecurityReport is the complete JSON output
type SecurityReport struct {
	ScanMetadata         ScanMetadata                `json:"scan_metadata"`
	ExecutiveSummary     ExecutiveSummary            `json:"executive_summary"`
	FindingsBySeverity   map[string][]Finding        `json:"findings_by_severity"`
	ComplianceMapping    ComplianceMapping           `json:"compliance_mapping"`
	Recommendations      []Recommendation            `json:"recommendations"`
	RemediationPriority  RemediationPriority         `json:"remediation_priority"`
}

// TerraformScanner performs security scanning
type TerraformScanner struct {
	Rules    []SecurityRule
	Findings []Finding
	Stats    SeverityStats
}

// NewTerraformScanner creates a new scanner instance
func NewTerraformScanner() *TerraformScanner {
	scanner := &TerraformScanner{
		Findings: make([]Finding, 0),
		Stats:    SeverityStats{},
	}
	scanner.initializeRules()
	return scanner
}

// initializeRules sets up all security rules
func (s *TerraformScanner) initializeRules() {
	rules := []SecurityRule{
		// AWS Security Rules
		{
			ID:             "AWS-S3-001",
			Name:           "S3 Bucket Public Access",
			Severity:       "critical",
			Provider:       "aws",
			ResourceType:   "aws_s3_bucket",
			Pattern:        `resource\s+"aws_s3_bucket"\s+"[^"]+"\s*{[^}]*acl\s*=\s*"public-read`,
			OwaspMapping:   []string{"A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"},
			CsaCcmMapping:  []string{"IAM-02", "DSI-02", "GRM-06"},
			Description:    "S3 bucket allows public read access",
			Recommendation: "Remove public ACL. Use bucket policies with principle of least privilege. Enable S3 Block Public Access.",
		},
		{
			ID:             "AWS-S3-002",
			Name:           "S3 Bucket Encryption Disabled",
			Severity:       "high",
			Provider:       "aws",
			ResourceType:   "aws_s3_bucket",
			Pattern:        `resource\s+"aws_s3_bucket"\s+"([^"]+)"\s*{(?:(?!server_side_encryption_configuration).)*}`,
			OwaspMapping:   []string{"A02:2021-Cryptographic Failures"},
			CsaCcmMapping:  []string{"EKM-01", "EKM-02", "DSI-01"},
			Description:    "S3 bucket does not have encryption enabled",
			Recommendation: "Enable server-side encryption using aws_s3_bucket_server_side_encryption_configuration with AES256 or aws:kms.",
		},
		{
			ID:             "AWS-EC2-001",
			Name:           "EC2 Instance Public IP",
			Severity:       "high",
			Provider:       "aws",
			ResourceType:   "aws_instance",
			Pattern:        `associate_public_ip_address\s*=\s*true`,
			OwaspMapping:   []string{"A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"},
			CsaCcmMapping:  []string{"IVS-01", "IAM-09"},
			Description:    "EC2 instance has public IP enabled",
			Recommendation: "Avoid public IPs. Use NAT Gateway or VPN for outbound access. Place instances in private subnets.",
		},
		{
			ID:             "AWS-SG-001",
			Name:           "Security Group Unrestricted Ingress",
			Severity:       "critical",
			Provider:       "aws",
			ResourceType:   "aws_security_group",
			Pattern:        `cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]`,
			OwaspMapping:   []string{"A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"},
			CsaCcmMapping:  []string{"IVS-01", "IVS-02", "IAM-09"},
			Description:    "Security group allows unrestricted ingress (0.0.0.0/0)",
			Recommendation: "Restrict ingress to specific IP ranges. Use least privilege principle for network access.",
		},
		{
			ID:             "AWS-RDS-001",
			Name:           "RDS Instance Not Encrypted",
			Severity:       "high",
			Provider:       "aws",
			ResourceType:   "aws_db_instance",
			Pattern:        `resource\s+"aws_db_instance"\s+"([^"]+)"\s*{(?:(?!storage_encrypted\s*=\s*true).)*}`,
			OwaspMapping:   []string{"A02:2021-Cryptographic Failures"},
			CsaCcmMapping:  []string{"EKM-01", "EKM-02", "DSI-01"},
			Description:    "RDS instance does not have encryption enabled",
			Recommendation: "Enable storage_encrypted = true and specify kms_key_id for encryption at rest.",
		},
		{
			ID:             "AWS-RDS-002",
			Name:           "RDS Publicly Accessible",
			Severity:       "critical",
			Provider:       "aws",
			ResourceType:   "aws_db_instance",
			Pattern:        `publicly_accessible\s*=\s*true`,
			OwaspMapping:   []string{"A01:2021-Broken Access Control"},
			CsaCcmMapping:  []string{"IAM-02", "DSI-02"},
			Description:    "RDS instance is publicly accessible",
			Recommendation: "Set publicly_accessible = false. Use private subnets and VPN/bastion for access.",
		},
		{
			ID:             "AWS-IAM-001",
			Name:           "IAM Policy Wildcard Actions",
			Severity:       "high",
			Provider:       "aws",
			ResourceType:   "aws_iam_policy",
			Pattern:        `"Action"\s*:\s*"[*]"`,
			OwaspMapping:   []string{"A01:2021-Broken Access Control"},
			CsaCcmMapping:  []string{"IAM-01", "IAM-02", "IAM-08"},
			Description:    "IAM policy allows wildcard (*) actions",
			Recommendation: "Use specific actions instead of wildcards. Follow least privilege principle.",
		},
		{
			ID:             "AWS-LOG-001",
			Name:           "CloudWatch Logs Not Configured",
			Severity:       "medium",
			Provider:       "aws",
			ResourceType:   "aws_instance",
			Pattern:        `resource\s+"aws_instance"\s+"([^"]+)"\s*{(?:(?!cloudwatch).)*}`,
			OwaspMapping:   []string{"A09:2021-Security Logging and Monitoring Failures"},
			CsaCcmMapping:  []string{"LOG-01", "LOG-02", "SEF-01"},
			Description:    "Instance does not have CloudWatch logging configured",
			Recommendation: "Configure CloudWatch Logs for monitoring and auditing. Enable detailed monitoring.",
		},
		// GCP Security Rules
		{
			ID:             "GCP-GCS-001",
			Name:           "GCS Bucket Public Access",
			Severity:       "critical",
			Provider:       "gcp",
			ResourceType:   "google_storage_bucket",
			Pattern:        `role\s*=\s*"roles/storage\.objectViewer"\s*\n\s*members\s*=\s*\[\s*"allUsers"`,
			OwaspMapping:   []string{"A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"},
			CsaCcmMapping:  []string{"IAM-02", "DSI-02", "GRM-06"},
			Description:    "GCS bucket allows public access",
			Recommendation: "Remove allUsers and allAuthenticatedUsers from IAM bindings. Use specific service accounts.",
		},
		{
			ID:             "GCP-GCS-002",
			Name:           "GCS Bucket Encryption Not Configured",
			Severity:       "high",
			Provider:       "gcp",
			ResourceType:   "google_storage_bucket",
			Pattern:        `resource\s+"google_storage_bucket"\s+"([^"]+)"\s*{(?:(?!encryption).)*}`,
			OwaspMapping:   []string{"A02:2021-Cryptographic Failures"},
			CsaCcmMapping:  []string{"EKM-01", "EKM-02", "DSI-01"},
			Description:    "GCS bucket does not have customer-managed encryption",
			Recommendation: "Configure encryption block with default_kms_key_name for CMEK encryption.",
		},
		{
			ID:             "GCP-GCE-001",
			Name:           "GCE Instance External IP",
			Severity:       "high",
			Provider:       "gcp",
			ResourceType:   "google_compute_instance",
			Pattern:        `access_config\s*{`,
			OwaspMapping:   []string{"A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"},
			CsaCcmMapping:  []string{"IVS-01", "IAM-09"},
			Description:    "GCE instance has external IP address",
			Recommendation: "Remove access_config block. Use Cloud NAT or Identity-Aware Proxy for access.",
		},
		{
			ID:             "GCP-FW-001",
			Name:           "Firewall Rule Allows All",
			Severity:       "critical",
			Provider:       "gcp",
			ResourceType:   "google_compute_firewall",
			Pattern:        `source_ranges\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]`,
			OwaspMapping:   []string{"A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"},
			CsaCcmMapping:  []string{"IVS-01", "IVS-02", "IAM-09"},
			Description:    "Firewall rule allows traffic from anywhere (0.0.0.0/0)",
			Recommendation: "Restrict source_ranges to specific IP ranges. Use Identity-Aware Proxy where possible.",
		},
		{
			ID:             "GCP-SQL-001",
			Name:           "Cloud SQL Not Encrypted",
			Severity:       "high",
			Provider:       "gcp",
			ResourceType:   "google_sql_database_instance",
			Pattern:        `resource\s+"google_sql_database_instance"\s+"([^"]+)"\s*{(?:(?!encryption_key_name).)*}`,
			OwaspMapping:   []string{"A02:2021-Cryptographic Failures"},
			CsaCcmMapping:  []string{"EKM-01", "EKM-02", "DSI-01"},
			Description:    "Cloud SQL instance not using customer-managed encryption key",
			Recommendation: "Configure encryption_key_name for CMEK. Enable automated backups with encryption.",
		},
		{
			ID:             "GCP-SQL-002",
			Name:           "Cloud SQL Public IP",
			Severity:       "critical",
			Provider:       "gcp",
			ResourceType:   "google_sql_database_instance",
			Pattern:        `ip_configuration\s*{[^}]*ipv4_enabled\s*=\s*true`,
			OwaspMapping:   []string{"A01:2021-Broken Access Control"},
			CsaCcmMapping:  []string{"IAM-02", "DSI-02"},
			Description:    "Cloud SQL instance has public IP enabled",
			Recommendation: "Set ipv4_enabled = false. Use Private IP and Cloud SQL Proxy for secure access.",
		},
		{
			ID:             "GCP-LOG-001",
			Name:           "GCE No Logging Configured",
			Severity:       "medium",
			Provider:       "gcp",
			ResourceType:   "google_compute_instance",
			Pattern:        `resource\s+"google_compute_instance"\s+"([^"]+)"\s*{(?:(?!logging).)*}`,
			OwaspMapping:   []string{"A09:2021-Security Logging and Monitoring Failures"},
			CsaCcmMapping:  []string{"LOG-01", "LOG-02", "SEF-01"},
			Description:    "GCE instance does not have logging configured",
			Recommendation: "Enable Cloud Logging and Cloud Monitoring. Configure log sinks for security events.",
		},
		// Cross-Provider Rules
		{
			ID:             "GEN-001",
			Name:           "Hardcoded Secrets",
			Severity:       "critical",
			Provider:       "all",
			ResourceType:   "all",
			Pattern:        `(password|secret|api_key|token)\s*=\s*"[^$]`,
			OwaspMapping:   []string{"A07:2021-Identification and Authentication Failures"},
			CsaCcmMapping:  []string{"IAM-01", "EKM-03", "GRM-01"},
			Description:    "Hardcoded secrets found in configuration",
			Recommendation: "Use secrets management services (AWS Secrets Manager, GCP Secret Manager). Reference secrets via variables.",
		},
		{
			ID:             "GEN-002",
			Name:           "Missing Resource Tags",
			Severity:       "low",
			Provider:       "all",
			ResourceType:   "all",
			Pattern:        `resource\s+"(?:aws_|google_)[^"]+"\s+"([^"]+)"\s*{(?:(?!tags).)*}`,
			OwaspMapping:   []string{"A05:2021-Security Misconfiguration"},
			CsaCcmMapping:  []string{"GRM-06", "GRM-08"},
			Description:    "Resource missing required tags/labels for governance",
			Recommendation: "Add tags/labels for Environment, Owner, CostCenter, and DataClassification for proper governance.",
		},
	}

	// Compile regex patterns
	for i := range rules {
		compiled, err := regexp.Compile(rules[i].Pattern)
		if err != nil {
			fmt.Printf("Warning: Failed to compile pattern for rule %s: %v\n", rules[i].ID, err)
			continue
		}
		rules[i].CompiledPattern = compiled
	}

	s.Rules = rules
}

// ScanFile scans a single Terraform file
func (s *TerraformScanner) ScanFile(filepath string) error {
	content, err := ioutil.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	contentStr := string(content)

	for _, rule := range s.Rules {
		if rule.CompiledPattern == nil {
			continue
		}

		// Check provider compatibility
		if rule.Provider != "all" {
			if rule.Provider == "aws" && !strings.Contains(contentStr, `provider "aws"`) {
				continue
			}
			if rule.Provider == "gcp" && !strings.Contains(contentStr, `provider "google"`) {
				continue
			}
		}

		// Find all matches
		matches := rule.CompiledPattern.FindAllStringIndex(contentStr, -1)

		for _, match := range matches {
			matchStart := match[0]
			matchEnd := match[1]

			// Calculate line number
			lineNum := strings.Count(contentStr[:matchStart], "\n") + 1

			// Extract matched text
			matchedText := contentStr[matchStart:matchEnd]
			if len(matchedText) > 100 {
				matchedText = matchedText[:100] + "..."
			}

			finding := Finding{
				RuleID:         rule.ID,
				RuleName:       rule.Name,
				Severity:       rule.Severity,
				File:           filepath,
				Line:           lineNum,
				ResourceType:   rule.ResourceType,
				Description:    rule.Description,
				Recommendation: rule.Recommendation,
				OwaspMapping:   rule.OwaspMapping,
				CsaCcmMapping:  rule.CsaCcmMapping,
				MatchedText:    matchedText,
			}

			s.Findings = append(s.Findings, finding)
			s.updateStats(rule.Severity)
		}
	}

	return nil
}

// updateStats updates severity statistics
func (s *TerraformScanner) updateStats(severity string) {
	switch severity {
	case "critical":
		s.Stats.Critical++
	case "high":
		s.Stats.High++
	case "medium":
		s.Stats.Medium++
	case "low":
		s.Stats.Low++
	case "info":
		s.Stats.Info++
	}
}

// ScanDirectory recursively scans a directory for Terraform files
func (s *TerraformScanner) ScanDirectory(dirPath string) error {
	var tfFiles []string

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".tf") {
			tfFiles = append(tfFiles, path)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("error walking directory: %w", err)
	}

	if len(tfFiles) == 0 {
		fmt.Printf("No Terraform files found in %s\n", dirPath)
		return nil
	}

	fmt.Printf("Found %d Terraform files. Scanning...\n", len(tfFiles))

	for _, tfFile := range tfFiles {
		fmt.Printf("Scanning: %s\n", tfFile)
		if err := s.ScanFile(tfFile); err != nil {
			fmt.Printf("Error scanning %s: %v\n", tfFile, err)
		}
	}

	return nil
}

// GenerateReport creates the JSON security report
func (s *TerraformScanner) GenerateReport(outputFile string) error {
	// Group findings by severity
	findingsBySeverity := make(map[string][]Finding)
	findingsBySeverity["critical"] = []Finding{}
	findingsBySeverity["high"] = []Finding{}
	findingsBySeverity["medium"] = []Finding{}
	findingsBySeverity["low"] = []Finding{}
	findingsBySeverity["info"] = []Finding{}

	for _, finding := range s.Findings {
		findingsBySeverity[finding.Severity] = append(findingsBySeverity[finding.Severity], finding)
	}

	// Calculate compliance mappings
	owaspCoverage := make(map[string]int)
	csaCcmCoverage := make(map[string]int)

	for _, finding := range s.Findings {
		for _, owasp := range finding.OwaspMapping {
			owaspCoverage[owasp]++
		}
		for _, ccm := range finding.CsaCcmMapping {
			csaCcmCoverage[ccm]++
		}
	}

	// Count unique files
	fileSet := make(map[string]bool)
	for _, finding := range s.Findings {
		fileSet[finding.File] = true
	}

	// Build compliance mapping
	complianceMapping := ComplianceMapping{}
	complianceMapping.OwaspTop10.Coverage = owaspCoverage
	complianceMapping.OwaspTop10.TotalCategories = len(owaspCoverage)
	complianceMapping.CsaCcm.Coverage = csaCcmCoverage
	complianceMapping.CsaCcm.TotalControls = len(csaCcmCoverage)

	// Generate report
	report := SecurityReport{
		ScanMetadata: ScanMetadata{
			ScanDate:          time.Now().Format(time.RFC3339),
			ScannerVersion:    "1.0.0",
			TotalFilesScanned: len(fileSet),
			TotalFindings:     len(s.Findings),
		},
		ExecutiveSummary: ExecutiveSummary{
			SeverityBreakdown: s.Stats,
			RiskScore:         s.calculateRiskScore(),
			ComplianceStatus:  s.assessCompliance(),
		},
		FindingsBySeverity:  findingsBySeverity,
		ComplianceMapping:   complianceMapping,
		Recommendations:     s.generateRecommendations(),
		RemediationPriority: s.prioritizeRemediation(findingsBySeverity),
	}

	// Write JSON report
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %w", err)
	}

	err = ioutil.WriteFile(outputFile, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("error writing report: %w", err)
	}

	// Print summary
	s.printSummary(report, outputFile)

	return nil
}

// calculateRiskScore calculates overall risk score (0-100)
func (s *TerraformScanner) calculateRiskScore() int {
	score := 0
	score += s.Stats.Critical * 25
	score += s.Stats.High * 10
	score += s.Stats.Medium * 5
	score += s.Stats.Low * 1

	if score > 100 {
		score = 100
	}

	return score
}

// assessCompliance assesses overall compliance status
func (s *TerraformScanner) assessCompliance() string {
	if s.Stats.Critical > 0 {
		return "NON-COMPLIANT - Critical issues must be resolved"
	} else if s.Stats.High > 5 {
		return "AT-RISK - Multiple high-severity issues detected"
	} else if s.Stats.High > 0 || s.Stats.Medium > 10 {
		return "NEEDS IMPROVEMENT - Address high and medium issues"
	} else if s.Stats.Medium > 0 || s.Stats.Low > 0 {
		return "ACCEPTABLE - Minor issues remain"
	}
	return "COMPLIANT - No security issues detected"
}

// generateRecommendations generates prioritized recommendations
func (s *TerraformScanner) generateRecommendations() []Recommendation {
	// Count issues by rule
	issueCounts := make(map[string]struct {
		count          int
		severity       string
		recommendation string
		ruleName       string
	})

	for _, finding := range s.Findings {
		key := finding.RuleID
		if data, exists := issueCounts[key]; exists {
			data.count++
			issueCounts[key] = data
		} else {
			issueCounts[key] = struct {
				count          int
				severity       string
				recommendation string
				ruleName       string
			}{
				count:          1,
				severity:       finding.Severity,
				recommendation: finding.Recommendation,
				ruleName:       finding.RuleName,
			}
		}
	}

	// Convert to slice for sorting
	type issueCount struct {
		ruleID         string
		count          int
		severity       string
		recommendation string
		ruleName       string
	}

	var issues []issueCount
	for ruleID, data := range issueCounts {
		issues = append(issues, issueCount{
			ruleID:         ruleID,
			count:          data.count,
			severity:       data.severity,
			recommendation: data.recommendation,
			ruleName:       data.ruleName,
		})
	}

	// Sort by severity then count
	severityOrder := map[string]int{
		"critical": 0,
		"high":     1,
		"medium":   2,
		"low":      3,
		"info":     4,
	}

	sort.Slice(issues, func(i, j int) bool {
		if severityOrder[issues[i].severity] != severityOrder[issues[j].severity] {
			return severityOrder[issues[i].severity] < severityOrder[issues[j].severity]
		}
		return issues[i].count > issues[j].count
	})

	// Build recommendations
	var recommendations []Recommendation
	for i, issue := range issues {
		if i >= 10 { // Top 10
			break
		}
		recommendations = append(recommendations, Recommendation{
			Priority:    i + 1,
			RuleID:      issue.ruleID,
			RuleName:    issue.ruleName,
			Occurrences: issue.count,
			Severity:    issue.severity,
			Action:      issue.recommendation,
		})
	}

	return recommendations
}

// prioritizeRemediation creates remediation roadmap
func (s *TerraformScanner) prioritizeRemediation(findingsBySeverity map[string][]Finding) RemediationPriority {
	priority := RemediationPriority{
		ImmediateActionRequired: []Finding{},
		ShortTerm30Days:         []Finding{},
		MediumTerm90Days:        []Finding{},
		LongTermPlanning:        []Finding{},
	}

	// Immediate: Critical (top 5)
	for i, f := range findingsBySeverity["critical"] {
		if i >= 5 {
			break
		}
		priority.ImmediateActionRequired = append(priority.ImmediateActionRequired, f)
	}

	// Short term: High (top 10)
	for i, f := range findingsBySeverity["high"] {
		if i >= 10 {
			break
		}
		priority.ShortTerm30Days = append(priority.ShortTerm30Days, f)
	}

	// Medium term: Medium (top 10)
	for i, f := range findingsBySeverity["medium"] {
		if i >= 10 {
			break
		}
		priority.MediumTerm90Days = append(priority.MediumTerm90Days, f)
	}

	// Long term: Low/Info (top 10)
	combined := append(findingsBySeverity["low"], findingsBySeverity["info"]...)
	for i, f := range combined {
		if i >= 10 {
			break
		}
		priority.LongTermPlanning = append(priority.LongTermPlanning, f)
	}

	return priority
}

// printSummary prints scan summary to console
func (s *TerraformScanner) printSummary(report SecurityReport, outputFile string) {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("Security Scan Complete!")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Total Findings: %d\n", len(s.Findings))
	fmt.Printf("  Critical: %d\n", s.Stats.Critical)
	fmt.Printf("  High: %d\n", s.Stats.High)
	fmt.Printf("  Medium: %d\n", s.Stats.Medium)
	fmt.Printf("  Low: %d\n", s.Stats.Low)
	fmt.Printf("  Info: %d\n", s.Stats.Info)
	fmt.Printf("\nRisk Score: %d/100\n", report.ExecutiveSummary.RiskScore)
	fmt.Printf("Compliance Status: %s\n", report.ExecutiveSummary.ComplianceStatus)
	fmt.Printf("Report saved to