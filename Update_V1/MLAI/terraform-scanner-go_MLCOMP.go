package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// SecurityFinding represents a security vulnerability
type SecurityFinding struct {
	ID                    string   `json:"id"`
	Severity              string   `json:"severity"`
	Category              string   `json:"category"`
	OwaspMapping          []string `json:"owasp_mapping"`
	CsaCcmMapping         []string `json:"csa_ccm_mapping"`
	ResourceType          string   `json:"resource_type"`
	ResourceName          string   `json:"resource_name"`
	FilePath              string   `json:"file_path"`
	LineNumber            int      `json:"line_number"`
	Description           string   `json:"description"`
	Recommendation        string   `json:"recommendation"`
	CweID                 string   `json:"cwe_id"`
	CvssScore             float64  `json:"cvss_score"`
	ExploitLikelihood     float64  `json:"exploit_likelihood"`
	RiskScore             float64  `json:"risk_score"`
	ComplianceFrameworks  []string `json:"compliance_frameworks"`
}

// SecurityRule defines a policy rule
type SecurityRule struct {
	ID              string
	Name            string
	Severity        string
	Owasp           []string
	CsaCcm          []string
	Cwe             string
	Cvss            float64
	Pattern         string
	Description     string
	Recommendation  string
}

// ScanReport contains scan results
type ScanReport struct {
	Metadata struct {
		Timestamp      string `json:"timestamp"`
		TotalFindings  int    `json:"total_findings"`
		Critical       int    `json:"critical"`
		High           int    `json:"high"`
		Medium         int    `json:"medium"`
		Low            int    `json:"low"`
	} `json:"scan_metadata"`
	RiskAnalysis struct {
		AvgExploitLikelihood  float64 `json:"average_exploit_likelihood"`
		AvgRiskScore          float64 `json:"average_risk_score"`
		HighRiskFindings      int     `json:"high_risk_findings"`
		CriticalExposures     int     `json:"critical_public_exposures"`
	} `json:"risk_analysis"`
	ComplianceSummary map[string]int `json:"compliance_summary"`
	OwaspMapping      map[string]int `json:"owasp_mapping"`
	Findings          []SecurityFinding `json:"findings"`
	Recommendations   []Recommendation  `json:"recommendations"`
}

// Recommendation for remediation
type Recommendation struct {
	Priority string `json:"priority"`
	Action   string `json:"action"`
	Impact   string `json:"impact"`
}

// TerraformScanner scans Terraform files
type TerraformScanner struct {
	findings []SecurityFinding
	rules    []SecurityRule
}

// NewTerraformScanner creates a new scanner
func NewTerraformScanner() *TerraformScanner {
	return &TerraformScanner{
		findings: make([]SecurityFinding, 0),
		rules:    initializeRules(),
	}
}

// initializeRules sets up security rules
func initializeRules() []SecurityRule {
	return []SecurityRule{
		{
			ID:       "AWS-S3-001",
			Name:     "S3 Bucket Public Access",
			Severity: "CRITICAL",
			Owasp:    []string{"A01", "A05"},
			CsaCcm:   []string{"IAM-01", "DSI-01"},
			Cwe:      "CWE-276",
			Cvss:     9.1,
			Pattern:  `block_public_acls\s*=\s*false`,
			Description: "S3 bucket allows public access",
			Recommendation: "Enable block_public_acls = true",
		},
		{
			ID:       "AWS-RDS-001",
			Name:     "RDS Instance Public Access",
			Severity: "CRITICAL",
			Owasp:    []string{"A01", "A05"},
			CsaCcm:   []string{"IAM-01", "IVS-02"},
			Cwe:      "CWE-284",
			Cvss:     9.8,
			Pattern:  `publicly_accessible\s*=\s*true`,
			Description: "RDS database is publicly accessible",
			Recommendation: "Set publicly_accessible = false",
		},
		{
			ID:       "AWS-SG-001",
			Name:     "Security Group Open to World",
			Severity: "CRITICAL",
			Owasp:    []string{"A01", "A05"},
			CsaCcm:   []string{"IVS-02"},
			Cwe:      "CWE-732",
			Cvss:     9.0,
			Pattern:  `cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]`,
			Description: "Security group allows traffic from 0.0.0.0/0",
			Recommendation: "Restrict source IP ranges",
		},
		{
			ID:       "GCP-SQL-001",
			Name:     "Cloud SQL Public IP",
			Severity: "CRITICAL",
			Owasp:    []string{"A01", "A05"},
			CsaCcm:   []string{"IAM-01", "IVS-02"},
			Cwe:      "CWE-284",
			Cvss:     9.8,
			Pattern:  `ipv4_enabled\s*=\s*true`,
			Description: "Cloud SQL has public IP enabled",
			Recommendation: "Use private IP only",
		},
		{
			ID:       "GCP-GCS-001",
			Name:     "GCS Bucket Public Access",
			Severity: "CRITICAL",
			Owasp:    []string{"A01", "A05"},
			CsaCcm:   []string{"IAM-01", "DSI-01"},
			Cwe:      "CWE-276",
			Cvss:     9.1,
			Pattern:  `"allUsers"`,
			Description: "GCS bucket grants public access",
			Recommendation: "Remove allUsers from IAM bindings",
		},
	}
}

// ScanFile scans a single Terraform file
func (s *TerraformScanner) ScanFile(filePath string) error {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	fileContent := string(content)

	for _, rule := range s.rules {
		re := regexp.MustCompile(rule.Pattern)
		matches := re.FindAllStringIndex(fileContent, -1)

		for _, match := range matches {
			lineNum := strings.Count(fileContent[:match[0]], "\n") + 1
			
			// Extract resource info
			resourceType, resourceName := extractResourceInfo(fileContent, match[0])

			finding := SecurityFinding{
				ID:                   generateID(rule.ID, filePath, lineNum),
				Severity:             rule.Severity,
				Category:             rule.Name,
				OwaspMapping:         rule.Owasp,
				CsaCcmMapping:        rule.CsaCcm,
				ResourceType:         resourceType,
				ResourceName:         resourceName,
				FilePath:             filePath,
				LineNumber:           lineNum,
				Description:          rule.Description,
				Recommendation:       rule.Recommendation,
				CweID:                rule.Cwe,
				CvssScore:            rule.Cvss,
				ComplianceFrameworks: mapCompliance(rule.CsaCcm),
			}

			// Calculate exploit likelihood
			finding.ExploitLikelihood = calculateExploitLikelihood(finding)
			finding.RiskScore = calculateRiskScore(finding)

			s.findings = append(s.findings, finding)
		}
	}

	return nil
}

// ScanDirectory scans all .tf files in a directory
func (s *TerraformScanner) ScanDirectory(dirPath string) error {
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".tf") {
			fmt.Printf("Scanning: %s\n", path)
			if err := s.ScanFile(path); err != nil {
				fmt.Printf("Error scanning %s: %v\n", path, err)
			}
		}

		return nil
	})
}

// GenerateReport creates a JSON report
func (s *TerraformScanner) GenerateReport(outputFile string) error {
	report := ScanReport{
		Findings: s.findings,
	}

	// Metadata
	report.Metadata.Timestamp = time.Now().Format(time.RFC3339)
	report.Metadata.TotalFindings = len(s.findings)

	// Count by severity
	for _, finding := range s.findings {
		switch finding.Severity {
		case "CRITICAL":
			report.Metadata.Critical++
		case "HIGH":
			report.Metadata.High++
		case "MEDIUM":
			report.Metadata.Medium++
		case "LOW":
			report.Metadata.Low++
		}
	}

	// Risk analysis
	var totalExploit, totalRisk float64
	for _, finding := range s.findings {
		totalExploit += finding.ExploitLikelihood
		totalRisk += finding.RiskScore
		
		if finding.RiskScore > 7.0 {
			report.RiskAnalysis.HighRiskFindings++
		}
		
		if finding.Severity == "CRITICAL" && strings.Contains(strings.ToLower(finding.Description), "public") {
			report.RiskAnalysis.CriticalExposures++
		}
	}

	if len(s.findings) > 0 {
		report.RiskAnalysis.AvgExploitLikelihood = totalExploit / float64(len(s.findings))
		report.RiskAnalysis.AvgRiskScore = totalRisk / float64(len(s.findings))
	}

	// Compliance summary
	report.ComplianceSummary = make(map[string]int)
	frameworks := []string{"SOC2", "PCI-DSS", "HIPAA", "GDPR", "ISO27001"}
	for _, framework := range frameworks {
		for _, finding := range s.findings {
			for _, fw := range finding.ComplianceFrameworks {
				if fw == framework {
					report.ComplianceSummary[framework]++
					break
				}
			}
		}
	}

	// OWASP mapping
	report.OwaspMapping = make(map[string]int)
	for _, finding := range s.findings {
		for _, owasp := range finding.OwaspMapping {
			report.OwaspMapping[owasp]++
		}
	}

	// Recommendations
	report.Recommendations = generateRecommendations(s.findings)

	// Write to file
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	if err := ioutil.WriteFile(outputFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	// Print summary
	fmt.Printf("\n✓ Report generated: %s\n", outputFile)
	fmt.Printf("✓ Total findings: %d\n", report.Metadata.TotalFindings)
	fmt.Printf("✓ Critical: %d\n", report.Metadata.Critical)
	fmt.Printf("✓ Average exploit likelihood: %.2f%%\n", report.RiskAnalysis.AvgExploitLikelihood*100)
	fmt.Printf("✓ High risk findings: %d\n", report.RiskAnalysis.HighRiskFindings)

	return nil
}

// Helper functions

func extractResourceInfo(content string, matchPos int) (string, string) {
	start := matchPos - 200
	if start < 0 {
		start = 0
	}

	snippet := content[start:matchPos]
	re := regexp.MustCompile(`resource\s+"([^"]+)"\s+"([^"]+)"`)
	matches := re.FindStringSubmatch(snippet)

	if len(matches) >= 3 {
		return matches[1], matches[2]
	}

	return "unknown", "unknown"
}

func generateID(ruleID, filePath string, lineNum int) string {
	data := fmt.Sprintf("%s%s%d", ruleID, filePath, lineNum)
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("%s-%x", ruleID, hash[:4])
}

func calculateExploitLikelihood(finding SecurityFinding) float64 {
	// Simple heuristic calculation
	likelihood := 0.0

	// CVSS contribution
	likelihood += (finding.CvssScore / 10) * 0.4

	// Severity contribution
	severityScore := map[string]float64{
		"CRITICAL": 1.0,
		"HIGH":     0.75,
		"MEDIUM":   0.5,
		"LOW":      0.25,
	}
	likelihood += severityScore[finding.Severity] * 0.3

	// Public exposure increases likelihood
	if strings.Contains(strings.ToLower(finding.Description), "public") {
		likelihood += 0.2
	}

	// Authentication factor
	if strings.Contains(strings.ToLower(finding.Description), "authentication") {
		likelihood += 0.1
	}

	if likelihood > 1.0 {
		likelihood = 1.0
	}

	return likelihood
}

func calculateRiskScore(finding SecurityFinding) float64 {
	cvssComponent := (finding.CvssScore / 10) * 40
	exploitComponent := finding.ExploitLikelihood * 60
	
	return cvssComponent + exploitComponent
}

func mapCompliance(csaCcm []string) []string {
	complianceMap := map[string][]string{
		"IAM-01": {"SOC2", "ISO27001", "HIPAA"},
		"DSI-01": {"GDPR", "ISO27001"},
		"DSI-02": {"HIPAA", "PCI-DSS", "GDPR"},
		"IVS-02": {"PCI-DSS", "SOC2"},
		"LOG-01": {"SOC2", "PCI-DSS", "ISO27001"},
	}

	frameworks := make(map[string]bool)
	for _, control := range csaCcm {
		if fws, ok := complianceMap[control]; ok {
			for _, fw := range fws {
				frameworks[fw] = true
			}
		}
	}

	result := make([]string, 0, len(frameworks))
	for fw := range frameworks {
		result = append(result, fw)
	}

	return result
}

func generateRecommendations(findings []SecurityFinding) []Recommendation {
	recommendations := make([]Recommendation, 0)

	criticalCount := 0
	highExploitCount := 0

	for _, finding := range findings {
		if finding.Severity == "CRITICAL" {
			criticalCount++
		}
		if finding.ExploitLikelihood > 0.7 {
			highExploitCount++
		}
	}

	if criticalCount > 0 {
		recommendations = append(recommendations, Recommendation{
			Priority: "IMMEDIATE",
			Action:   fmt.Sprintf("Address %d CRITICAL findings immediately", criticalCount),
			Impact:   "Prevents potential data breaches and compliance violations",
		})
	}

	if highExploitCount > 0 {
		recommendations = append(recommendations, Recommendation{
			Priority: "HIGH",
			Action:   fmt.Sprintf("Remediate %d findings with >70%% exploit likelihood", highExploitCount),
			Impact:   "Significantly reduces attack surface",
		})
	}

	return recommendations
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: terraform-scanner <directory_path>")
		fmt.Println("Example: terraform-scanner ./terraform")
		os.Exit(1)
	}

	scanPath := os.Args[1]
	
	scanner := NewTerraformScanner()
	
	fmt.Printf("Starting scan of: %s\n", scanPath)
	fmt.Println(strings.Repeat("=", 60))
	
	if err := scanner.ScanDirectory(scanPath); err != nil {
		fmt.Printf("Error during scan: %v\n", err)
		os.Exit(1)
	}

	if err := scanner.GenerateReport("terraform_security_report.json"); err != nil {
		fmt.Printf("Error generating report: %v\n", err)
		os.Exit(1)
	}
}
