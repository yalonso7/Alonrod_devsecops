package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
)

// SARIF Structures
type SarifLog struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name            string      `json:"name"`
	InformationUri  string      `json:"informationUri"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription Message             `json:"shortDescription"`
	FullDescription  Message             `json:"fullDescription"`
	Help             Message             `json:"help"`
	Properties       SarifRuleProperties `json:"properties"`
}

type SarifRuleProperties struct {
	Severity string   `json:"severity"`
	Owasp    []string `json:"owasp"`
	CsaCcm   []string `json:"csa_ccm"`
}

type Result struct {
	RuleID    string     `json:"ruleId"`
	RuleIndex int        `json:"ruleIndex"`
	Level     string     `json:"level"`
	Message   Message    `json:"message"`
	Locations []Location `json:"locations"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type ArtifactLocation struct {
	Uri string `json:"uri"`
}

type Region struct {
	StartLine int `json:"startLine"`
}

type Message struct {
	Text string `json:"text"`
}

// SecurityRule represents a security policy rule
type SecurityRule struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Severity        string   `json:"severity"`
	Provider        string   `json:"provider"`
	ResourceType    string   `json:"resource_type"`
	Pattern         string   `json:"pattern"`
	OwaspMapping    []string `json:"owasp"`
	CsaCcmMapping   []string `json:"csa_ccm"`
	Description     string   `json:"description"`
	Recommendation  string   `json:"recommendation"`
	CompiledPattern *regexp2.Regexp
}

// RulesConfig represents the structure of rules.json
type RulesConfig struct {
	Rules []SecurityRule `json:"rules"`
}

// Finding represents a security finding
type Finding struct {
	RuleID         string   `json:"rule_id"`
	RuleName       string   `json:"rule_name"`
	Severity       string   `json:"severity"`
	File           string   `json:"file"`
	Line           int      `json:"line"`
	ResourceType   string   `json:"resource_type"`
	Description    string   `json:"description"`
	Recommendation string   `json:"recommendation"`
	OwaspMapping   []string `json:"owasp_mapping"`
	CsaCcmMapping  []string `json:"csa_ccm_mapping"`
	MatchedText    string   `json:"matched_text"`
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
		Coverage        map[string]int `json:"coverage"`
		TotalCategories int            `json:"total_categories"`
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
	ScanMetadata        ScanMetadata         `json:"scan_metadata"`
	ExecutiveSummary    ExecutiveSummary     `json:"executive_summary"`
	FindingsBySeverity  map[string][]Finding `json:"findings_by_severity"`
	ComplianceMapping   ComplianceMapping    `json:"compliance_mapping"`
	Recommendations     []Recommendation     `json:"recommendations"`
	RemediationPriority RemediationPriority  `json:"remediation_priority"`
}

// TerraformScanner performs security scanning
type TerraformScanner struct {
	Rules     []SecurityRule
	Findings  []Finding
	Stats     SeverityStats
	RulesFile string
}

// NewTerraformScanner creates a new scanner instance
func NewTerraformScanner(rulesFile string) *TerraformScanner {
	scanner := &TerraformScanner{
		Findings:  make([]Finding, 0),
		Stats:     SeverityStats{},
		RulesFile: rulesFile,
	}
	scanner.initializeRules()
	return scanner
}

// initializeRules sets up all security rules from JSON
func (s *TerraformScanner) initializeRules() {
	jsonFile, err := os.Open(s.RulesFile)
	if err != nil {
		fmt.Printf("Error opening rules file %s: %v\n", s.RulesFile, err)
		os.Exit(1)
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	var config RulesConfig
	if err := json.Unmarshal(byteValue, &config); err != nil {
		// Fallback: try unmarshaling as a list directly
		var rulesList []SecurityRule
		if err2 := json.Unmarshal(byteValue, &rulesList); err2 != nil {
			fmt.Printf("Error parsing rules file: %v\n", err)
			os.Exit(1)
		}
		config.Rules = rulesList
	}

	// Compile regex patterns with regexp2
	for i := range config.Rules {
		// regexp2.RE2 option mimics Go's regexp package but we don't want that if we want lookaheads
		// Default options are usually fine for PCRE-like behavior
		compiled, err := regexp2.Compile(config.Rules[i].Pattern, 0)
		if err != nil {
			fmt.Printf("Warning: Failed to compile pattern for rule %s: %v\n", config.Rules[i].ID, err)
			continue
		}
		config.Rules[i].CompiledPattern = compiled
	}

	s.Rules = config.Rules
}

// checkIgnore checks if a rule is ignored via comment
func (s *TerraformScanner) checkIgnore(content string, lineNum int, ruleID string) bool {
	lines := strings.Split(content, "\n")

	// Adjust for 0-based indexing
	currentLineIdx := lineNum - 1

	ignoreTag := fmt.Sprintf("tf-scanner:ignore:%s", ruleID)

	// Check current line (inline comment)
	if currentLineIdx < len(lines) {
		if strings.Contains(lines[currentLineIdx], ignoreTag) {
			return true
		}
	}

	// Check previous line
	if currentLineIdx > 0 {
		if strings.Contains(lines[currentLineIdx-1], ignoreTag) {
			return true
		}
	}

	return false
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
				// Simple check
			}
			if rule.Provider == "gcp" && !strings.Contains(contentStr, `provider "google"`) {
				// Simple check
			}
		}

		// Find all matches using regexp2
		// regexp2 doesn't have FindAllStringIndex, so we iterate
		m, _ := rule.CompiledPattern.FindStringMatch(contentStr)
		for m != nil {
			// Get match range
			// Group 0 is the full match
			g := m.GroupByNumber(0)
			matchStart := g.Index
			matchEnd := g.Index + g.Length

			// Calculate line number
			// Be careful with large files, this re-counting is inefficient but fine for PoC
			lineNum := strings.Count(contentStr[:matchStart], "\n") + 1

			// Check for ignore comments
			if s.checkIgnore(contentStr, lineNum, rule.ID) {
				m, _ = rule.CompiledPattern.FindNextMatch(m)
				continue
			}

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

			// Find next match
			m, _ = rule.CompiledPattern.FindNextMatch(m)
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
			ScannerVersion:    "1.1.0",
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

// GenerateSarifReport generates a SARIF report
func (s *TerraformScanner) GenerateSarifReport(outputFile string) error {
	// Create rules map for index lookup
	rulesMap := make(map[string]int)
	var sarifRules []SarifRule

	for i, rule := range s.Rules {
		rulesMap[rule.ID] = i
		sarifRules = append(sarifRules, SarifRule{
			ID:   rule.ID,
			Name: rule.Name,
			ShortDescription: Message{
				Text: rule.Name,
			},
			FullDescription: Message{
				Text: rule.Description,
			},
			Help: Message{
				Text: rule.Recommendation,
			},
			Properties: SarifRuleProperties{
				Severity: rule.Severity,
				Owasp:    rule.OwaspMapping,
				CsaCcm:   rule.CsaCcmMapping,
			},
		})
	}

	// Create results
	var results []Result
	for _, finding := range s.Findings {
		level := "warning"
		if finding.Severity == "critical" || finding.Severity == "high" {
			level = "error"
		}

		results = append(results, Result{
			RuleID:    finding.RuleID,
			RuleIndex: rulesMap[finding.RuleID],
			Level:     level,
			Message: Message{
				Text: finding.Description,
			},
			Locations: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							Uri: finding.File,
						},
						Region: Region{
							StartLine: finding.Line,
						},
					},
				},
			},
		})
	}

	sarifLog := SarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:            "Terraform Security Scanner",
						InformationUri:  "https://github.com/example/terraform-scanner",
						SemanticVersion: "1.1.0",
						Rules:           sarifRules,
					},
				},
				Results: results,
			},
		},
	}

	// Write SARIF report
	jsonData, err := json.MarshalIndent(sarifLog, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling SARIF: %w", err)
	}

	err = ioutil.WriteFile(outputFile, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("error writing SARIF report: %w", err)
	}

	fmt.Printf("SARIF report saved to: %s\n", outputFile)
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
	type kv struct {
		Key   string
		Value struct {
			count          int
			severity       string
			recommendation string
			ruleName       string
		}
	}

	var sortedIssues []kv
	for k, v := range issueCounts {
		sortedIssues = append(sortedIssues, kv{k, v})
	}

	// Sort by severity and count
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.Slice(sortedIssues, func(i, j int) bool {
		sevI := severityOrder[sortedIssues[i].Value.severity]
		sevJ := severityOrder[sortedIssues[j].Value.severity]
		if sevI != sevJ {
			return sevI < sevJ
		}
		return sortedIssues[i].Value.count > sortedIssues[j].Value.count
	})

	var recommendations []Recommendation
	for i, item := range sortedIssues {
		if i >= 10 {
			break
		}
		recommendations = append(recommendations, Recommendation{
			Priority:    i + 1,
			RuleID:      item.Key,
			RuleName:    item.Value.ruleName,
			Occurrences: item.Value.count,
			Severity:    item.Value.severity,
			Action:      item.Value.recommendation,
		})
	}

	return recommendations
}

// prioritizeRemediation creates remediation roadmap
func (s *TerraformScanner) prioritizeRemediation(findings map[string][]Finding) RemediationPriority {
	rp := RemediationPriority{}

	// Immediate (Critical, top 5)
	if len(findings["critical"]) > 5 {
		rp.ImmediateActionRequired = findings["critical"][:5]
	} else {
		rp.ImmediateActionRequired = findings["critical"]
	}

	// Short term (High, top 10)
	if len(findings["high"]) > 10 {
		rp.ShortTerm30Days = findings["high"][:10]
	} else {
		rp.ShortTerm30Days = findings["high"]
	}

	// Medium term (Medium, top 10)
	if len(findings["medium"]) > 10 {
		rp.MediumTerm90Days = findings["medium"][:10]
	} else {
		rp.MediumTerm90Days = findings["medium"]
	}

	// Long term (Low/Info, top 10)
	lowAndInfo := append(findings["low"], findings["info"]...)
	if len(lowAndInfo) > 10 {
		rp.LongTermPlanning = lowAndInfo[:10]
	} else {
		rp.LongTermPlanning = lowAndInfo
	}

	return rp
}

// printSummary prints the execution summary
func (s *TerraformScanner) printSummary(report SecurityReport, outputFile string) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("Security Scan Complete!")
	fmt.Printf("%s\n", strings.Repeat("=", 70))
	fmt.Printf("Total Findings: %d\n", len(s.Findings))
	fmt.Printf("  Critical: %d\n", s.Stats.Critical)
	fmt.Printf("  High: %d\n", s.Stats.High)
	fmt.Printf("  Medium: %d\n", s.Stats.Medium)
	fmt.Printf("  Low: %d\n", s.Stats.Low)
	fmt.Printf("  Info: %d\n", s.Stats.Info)
	fmt.Printf("\nRisk Score: %d/100\n", report.ExecutiveSummary.RiskScore)
	fmt.Printf("Report saved to: %s\n", outputFile)
	fmt.Printf("%s\n\n", strings.Repeat("=", 70))

	if len(s.Findings) > 0 {
		fmt.Println("Sample Critical/High Findings:")
		fmt.Println(strings.Repeat("-", 70))
		count := 0
		for _, finding := range s.Findings {
			if count >= 5 {
				break
			}
			if finding.Severity == "critical" || finding.Severity == "high" {
				fmt.Printf("\n[%s] %s\n", strings.ToUpper(finding.Severity), finding.RuleName)
				fmt.Printf("  File: %s:%d\n", finding.File, finding.Line)
				fmt.Printf("  OWASP: %s\n", strings.Join(finding.OwaspMapping, ", "))
				fmt.Printf("  CSA CCM: %s\n", strings.Join(finding.CsaCcmMapping, ", "))
				fmt.Printf("  Issue: %s\n", finding.Description)
				count++
			}
		}
	}
}

func main() {
	outputFile := flag.String("o", "terraform_security_report.json", "Output JSON report file")
	rulesFile := flag.String("rules", "rules.json", "Path to rules JSON file")
	sarifFile := flag.String("sarif", "", "Output SARIF report file (optional)")
	flag.Parse()

	args := flag.Args()
	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}

	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("Terraform Infrastructure as Code Security Scanner")
	fmt.Println("OWASP Top 10 & CSA CCM Compliance Checker")
	fmt.Printf("%s\n\n", strings.Repeat("=", 70))

	scanner := NewTerraformScanner(*rulesFile)

	// Scan the directory
	if err := scanner.ScanDirectory(scanPath); err != nil {
		fmt.Printf("Error scanning directory: %v\n", err)
		os.Exit(1)
	}

	// Generate report
	if err := scanner.GenerateReport(*outputFile); err != nil {
		fmt.Printf("Error generating report: %v\n", err)
		os.Exit(1)
	}

	// Generate SARIF report if requested
	if *sarifFile != "" {
		if err := scanner.GenerateSarifReport(*sarifFile); err != nil {
			fmt.Printf("Error generating SARIF report: %v\n", err)
			os.Exit(1)
		}
	}
}
