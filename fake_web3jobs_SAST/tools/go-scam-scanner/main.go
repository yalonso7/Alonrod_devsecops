package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Rule struct {
	ID          string
	Severity    string
	Title       string
	Category    string
	Pattern     *regexp.Regexp
	Why         string
	Impact      string
	Remediation string
}

type Finding struct {
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	FilePath    string `json:"file_path"`
	Line        int    `json:"line"`
	Category    string `json:"category"`
	Why         string `json:"why"`
	Impact      string `json:"impact"`
	Remediation string `json:"remediation"`
	Evidence    string `json:"evidence"`
}

type FileStats struct {
	FilePath             string
	Entropy              float64
	LongLineRatio        float64
	HexEscapeCount       float64
	SuspiciousTokenCount float64
	NonAlnumRatio        float64
}

type ScanSummary struct {
	ExploitabilityScore float64            `json:"exploitability_score"`
	ExploitabilityBand  string             `json:"exploitability_band"`
	SeverityCounts      map[string]int     `json:"severity_counts"`
	FeatureVector       map[string]float64 `json:"feature_vector"`
	URLs                []string           `json:"urls"`
	Findings            []Finding          `json:"findings"`
}

var (
	excludeDirs = map[string]bool{
		".git": true, "node_modules": true, "dist": true, "build": true, ".next": true, ".cache": true, "coverage": true,
	}
	textExt = map[string]bool{
		".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".json": true, ".sol": true,
		".md": true, ".yml": true, ".yaml": true, ".py": true, ".go": true, ".sh": true, ".cmd": true, ".ps1": true,
	}
	sevOrder = map[string]int{"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
	urlRe    = regexp.MustCompile(`https?://[^\s"'` + "`" + `)>]+`)
)

func buildRules() []Rule {
	return []Rule{
		{
			ID:          "dynamic_function",
			Severity:    "Critical",
			Title:       "Dynamic Code Execution Primitive Detected",
			Category:    "RCE",
			Pattern:     regexp.MustCompile(`(?i)new\s+Function(?:\.constructor)?\s*\(`),
			Why:         "Dynamic runtime code construction enables arbitrary payload execution.",
			Impact:      "Remote code execution and full process compromise.",
			Remediation: "Remove dynamic execution and use explicit, typed control flow.",
		},
		{
			ID:          "eval",
			Severity:    "High",
			Title:       "Potentially Unsafe eval Usage",
			Category:    "RCE",
			Pattern:     regexp.MustCompile(`(?i)\beval\s*\(`),
			Why:         "eval executes string input as code.",
			Impact:      "Code injection under attacker-controlled input.",
			Remediation: "Replace eval with safe parser logic.",
		},
		{
			ID:          "process_exec",
			Severity:    "Critical",
			Title:       "Process Execution Primitive with Potential Abuse",
			Category:    "Execution",
			Pattern:     regexp.MustCompile(`(?i)child_process|exec\s*\(|spawn\s*\(|execFile\s*\(`),
			Why:         "Shell/process APIs are commonly abused by droppers and loaders.",
			Impact:      "Arbitrary command execution on host.",
			Remediation: "Disallow process execution in untrusted code paths.",
		},
		{
			ID:          "folder_open",
			Severity:    "Critical",
			Title:       "VS Code Auto-Run Task on Folder Open",
			Category:    "Persistence",
			Pattern:     regexp.MustCompile(`(?i)"runOn"\s*:\s*"folderOpen"`),
			Why:         "Auto-run tasks can execute payloads when repository is opened.",
			Impact:      "Workstation compromise without explicit command invocation.",
			Remediation: "Delete auto-run tasks and enforce explicit command execution.",
		},
		{
			ID:          "hardcoded_secret",
			Severity:    "High",
			Title:       "Hardcoded Secret/Key Material",
			Category:    "Secrets",
			Pattern:     regexp.MustCompile(`(?i)(secret|api[_-]?key|private[_-]?key|token)\s*[:=]\s*['"][^'"]{8,}['"]`),
			Why:         "Secrets in source are recoverable from repo and artifacts.",
			Impact:      "Credential theft, unauthorized access, token abuse.",
			Remediation: "Move secrets to environment/secret manager and rotate exposed values.",
		},
		{
			ID:          "obfuscation",
			Severity:    "High",
			Title:       "Obfuscation / Encoded Payload Indicator",
			Category:    "Obfuscation",
			Pattern:     regexp.MustCompile(`(?i)atob\s*\(|Buffer\.from\([^)]*base64|\\x[0-9a-fA-F]{2}`),
			Why:         "Encoded strings and hex escapes often hide second-stage payloads.",
			Impact:      "Concealed C2 and delayed detection.",
			Remediation: "Decode and review encoded data; remove untrusted payload paths.",
		},
	}
}

func isTextCandidate(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base == "package.json" || base == "tasks.json" || base == "readme.md" {
		return true
	}
	return textExt[strings.ToLower(filepath.Ext(path))]
}

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func entropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := map[rune]float64{}
	for _, ch := range s {
		counts[ch]++
	}
	total := float64(len(s))
	var e float64
	for _, c := range counts {
		p := c / total
		e -= p * math.Log2(p)
	}
	return e
}

func extractSnippet(content string, line, context int) string {
	lines := strings.Split(content, "\n")
	if len(lines) == 0 {
		return ""
	}
	start := line - context
	if start < 1 {
		start = 1
	}
	end := line + context
	if end > len(lines) {
		end = len(lines)
	}
	var out []string
	for i := start; i <= end; i++ {
		out = append(out, fmt.Sprintf("%d: %s", i, lines[i-1]))
	}
	return strings.Join(out, "\n")
}

func lineNumber(content string, index int) int {
	return strings.Count(content[:index], "\n") + 1
}

func markdownLang(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".js":
		return "js"
	case ".jsx":
		return "jsx"
	case ".ts":
		return "ts"
	case ".tsx":
		return "tsx"
	case ".json":
		return "json"
	case ".sol":
		return "solidity"
	case ".py":
		return "python"
	case ".go":
		return "go"
	default:
		return "text"
	}
}

func calcFileStats(rel, content string) FileStats {
	lines := strings.Split(content, "\n")
	if len(lines) == 0 {
		lines = []string{""}
	}
	longCount := 0
	for _, ln := range lines {
		if len(ln) > 220 {
			longCount++
		}
	}
	hexCount := float64(len(regexp.MustCompile(`\\x[0-9a-fA-F]{2}`).FindAllString(content, -1)))
	susp := float64(len(regexp.MustCompile(`(?i)atob\(|fromCharCode\(|new Function|eval\(|child_process|exec\(|spawn\(`).FindAllString(content, -1)))
	sample := content
	if len(sample) > 20000 {
		sample = sample[:20000]
	}
	alnum := 0
	for _, ch := range sample {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			alnum++
		}
	}
	nonAlnum := 1.0 - (float64(alnum) / math.Max(float64(len(sample)), 1))
	return FileStats{
		FilePath:             rel,
		Entropy:              entropy(sample),
		LongLineRatio:        float64(longCount) / math.Max(float64(len(lines)), 1),
		HexEscapeCount:       hexCount,
		SuspiciousTokenCount: susp,
		NonAlnumRatio:        nonAlnum,
	}
}

func meanStd(vals []float64) (float64, float64) {
	if len(vals) == 0 {
		return 0, 1
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	mean := sum / float64(len(vals))
	var sq float64
	for _, v := range vals {
		d := v - mean
		sq += d * d
	}
	std := math.Sqrt(sq / float64(len(vals)))
	if std == 0 {
		std = 1e-6
	}
	return mean, std
}

func detectAnomalies(stats []FileStats) []Finding {
	if len(stats) < 3 {
		return nil
	}
	getMetric := func(name string, s FileStats) float64 {
		switch name {
		case "entropy":
			return s.Entropy
		case "long":
			return s.LongLineRatio
		case "hex":
			return s.HexEscapeCount
		case "sus":
			return s.SuspiciousTokenCount
		default:
			return s.NonAlnumRatio
		}
	}
	metrics := []string{"entropy", "long", "hex", "sus", "non"}
	means := map[string]float64{}
	stds := map[string]float64{}
	for _, m := range metrics {
		var vals []float64
		for _, s := range stats {
			vals = append(vals, getMetric(m, s))
		}
		means[m], stds[m] = meanStd(vals)
	}
	type scored struct {
		S     FileStats
		Score float64
	}
	var scoredList []scored
	for _, s := range stats {
		var sum float64
		for _, m := range metrics {
			z := (getMetric(m, s) - means[m]) / stds[m]
			if z > 0 {
				sum += z
			}
		}
		score := sum / float64(len(metrics))
		if score >= 1.2 {
			scoredList = append(scoredList, scored{S: s, Score: score})
		}
	}
	sort.Slice(scoredList, func(i, j int) bool { return scoredList[i].Score > scoredList[j].Score })
	if len(scoredList) > 10 {
		scoredList = scoredList[:10]
	}
	var out []Finding
	for _, s := range scoredList {
		if s.S.HexEscapeCount == 0 && s.S.SuspiciousTokenCount == 0 {
			continue
		}
		sev := "Medium"
		if s.Score >= 2.0 {
			sev = "High"
		}
		out = append(out, Finding{
			Severity: sev,
			Title:    fmt.Sprintf("Anomalous File Signature (score=%.2f)", s.Score),
			FilePath: s.S.FilePath,
			Line:     1,
			Category: "Obfuscation",
			Why:      "Statistical outlier across entropy/obfuscation/exec-token metrics.",
			Impact:   "Likely hidden payload or packed script behavior.",
			Remediation: "Manually deobfuscate and isolate before execution.",
			Evidence: fmt.Sprintf(
				"entropy=%.2f, long_line_ratio=%.2f, hex_escapes=%.0f, suspicious_tokens=%.0f, non_alnum_ratio=%.2f",
				s.S.Entropy, s.S.LongLineRatio, s.S.HexEscapeCount, s.S.SuspiciousTokenCount, s.S.NonAlnumRatio,
			),
		})
	}
	return out
}

func sigmoid(x float64) float64 {
	if x >= 0 {
		z := math.Exp(-x)
		return 1 / (1 + z)
	}
	z := math.Exp(x)
	return z / (1 + z)
}

func exploitability(findings []Finding, stats []FileStats, urls []string) (float64, map[string]float64) {
	sev := map[string]float64{"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
	cat := map[string]float64{}
	for _, f := range findings {
		sev[f.Severity] += 1
		cat[f.Category] += 1
	}
	suspDomains := 0.0
	for _, u := range urls {
		host := strings.ToLower(strings.TrimSpace(u))
		if strings.Contains(host, "npoint.io") || strings.Contains(host, "vercel.app") || strings.Contains(host, "pastebin") {
			suspDomains++
		}
	}
	maxEntropy := 0.0
	hexTotal := 0.0
	for _, s := range stats {
		if s.Entropy > maxEntropy {
			maxEntropy = s.Entropy
		}
		hexTotal += s.HexEscapeCount
	}
	features := map[string]float64{
		"critical_count":       sev["Critical"],
		"high_count":           sev["High"],
		"rce_signals":          cat["RCE"] + cat["Execution"],
		"persistence_signals":  cat["Persistence"],
		"obfuscation_signals":  cat["Obfuscation"],
		"suspicious_domains":   suspDomains,
		"max_file_entropy":     maxEntropy,
		"hex_escape_total":     hexTotal,
		"finding_density":      float64(len(findings)) / math.Max(float64(len(stats)), 1),
	}
	weights := map[string]float64{
		"critical_count":      0.95,
		"high_count":          0.45,
		"rce_signals":         0.70,
		"persistence_signals": 0.80,
		"obfuscation_signals": 0.60,
		"suspicious_domains":  0.35,
		"max_file_entropy":    0.55,
		"hex_escape_total":    0.006,
		"finding_density":     1.20,
	}
	bias := -4.2
	linear := bias
	for k, w := range weights {
		linear += features[k] * w
	}
	return sigmoid(linear), features
}

func scoreBand(score float64) string {
	if score >= 0.90 {
		return "Very High"
	}
	if score >= 0.70 {
		return "High"
	}
	if score >= 0.45 {
		return "Medium"
	}
	return "Low"
}

func scanRepo(root string) ([]Finding, []FileStats, []string, error) {
	rules := buildRules()
	var findings []Finding
	var stats []FileStats
	urlSet := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if excludeDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !isTextCandidate(path) {
			return nil
		}
		content, readErr := readFile(path)
		if readErr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		stats = append(stats, calcFileStats(rel, content))
		for _, u := range urlRe.FindAllString(content, -1) {
			urlSet[u] = true
		}
		for _, r := range rules {
			matches := r.Pattern.FindAllStringIndex(content, -1)
			if len(matches) == 0 {
				continue
			}
			maxMatches := len(matches)
			if maxMatches > 5 {
				maxMatches = 5
			}
			for i := 0; i < maxMatches; i++ {
				ln := lineNumber(content, matches[i][0])
				findings = append(findings, Finding{
					Severity:    r.Severity,
					Title:       r.Title,
					FilePath:    rel,
					Line:        ln,
					Category:    r.Category,
					Why:         r.Why,
					Impact:      r.Impact,
					Remediation: r.Remediation,
					Evidence:    extractSnippet(content, ln, 2),
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}
	var urls []string
	for u := range urlSet {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	return findings, stats, urls, nil
}

func severityCounts(findings []Finding) map[string]int {
	out := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
	for _, f := range findings {
		out[f.Severity]++
	}
	return out
}

func renderReport(target string, findings []Finding, stats []FileStats, urls []string, score float64, band string, features map[string]float64) string {
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if sevOrder[a.Severity] != sevOrder[b.Severity] {
			return sevOrder[a.Severity] < sevOrder[b.Severity]
		}
		if a.FilePath != b.FilePath {
			return a.FilePath < b.FilePath
		}
		return a.Line < b.Line
	})
	counts := severityCounts(findings)
	verdict := "Likely benign"
	if score >= 0.70 {
		verdict = "Likely malicious"
	} else if score >= 0.45 {
		verdict = "Suspicious"
	}
	var b strings.Builder
	fmt.Fprintln(&b, "# Security Assessment Report - Job Scam Scanner (Go)")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "**Target:** `%s`  \n", filepath.Base(target))
	fmt.Fprintln(&b, "**Scanner:** `tools/go-scam-scanner/main.go`  ")
	fmt.Fprintf(&b, "**Generated:** %s\n\n", time.Now().UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Fprintln(&b, "---\n")
	fmt.Fprintln(&b, "## Executive Summary\n")
	fmt.Fprintf(&b, "- Total findings: **%d** across **%d** scanned files.\n", len(findings), len(stats))
	fmt.Fprintf(&b, "- ML exploitability likelihood: **%.1f%%** (**%s**).\n", score*100, band)
	fmt.Fprintf(&b, "- Verdict: **%s**.\n\n", verdict)

	fmt.Fprintln(&b, "## Risk Dashboard\n")
	fmt.Fprintln(&b, "### Severity Distribution\n")
	fmt.Fprintln(&b, "```mermaid")
	fmt.Fprintln(&b, "pie title Findings by Severity")
	fmt.Fprintf(&b, "  \"Critical\" : %d\n", counts["Critical"])
	fmt.Fprintf(&b, "  \"High\" : %d\n", counts["High"])
	fmt.Fprintf(&b, "  \"Medium\" : %d\n", counts["Medium"])
	fmt.Fprintf(&b, "  \"Low\" : %d\n", counts["Low"])
	fmt.Fprintln(&b, "```\n")

	fmt.Fprintln(&b, "### Exploitability & Anomaly Dashboard\n")
	fmt.Fprintln(&b, "| Metric | Value |")
	fmt.Fprintln(&b, "|---|---:|")
	fmt.Fprintf(&b, "| Exploitability likelihood | %.1f%% |\n", score*100)
	fmt.Fprintf(&b, "| Exploitability band | %s |\n", band)
	fmt.Fprintf(&b, "| Suspicious URLs observed | %d |\n", len(urls))
	fmt.Fprintf(&b, "| Findings density | %.2f |\n\n", features["finding_density"])

	fmt.Fprintln(&b, "### Attack Chain Graph\n")
	fmt.Fprintln(&b, "```mermaid")
	fmt.Fprintln(&b, "flowchart TD")
	fmt.Fprintln(&b, "  A[Workspace Open / Runtime Start] --> B[Suspicious Trigger]")
	fmt.Fprintln(&b, "  B --> C[Remote Fetch or Encoded Payload]")
	fmt.Fprintln(&b, "  C --> D[Dynamic Execution Primitive]")
	fmt.Fprintln(&b, "  D --> E[Potential Host or Server Compromise]")
	fmt.Fprintln(&b, "```\n")

	fmt.Fprintln(&b, "## Findings (Prioritized)\n")
	for i, f := range findings {
		fmt.Fprintf(&b, "## %d) %s - %s\n\n", i+1, f.Severity, f.Title)
		fmt.Fprintf(&b, "**Affected file**: `%s`\n\n", f.FilePath)
		fmt.Fprintln(&b, "**Why this is suspicious**")
		fmt.Fprintf(&b, "- %s\n\n", f.Why)
		fmt.Fprintln(&b, "**Potential impact**")
		fmt.Fprintf(&b, "- %s\n\n", f.Impact)
		fmt.Fprintln(&b, "**Evidence**\n")
		fmt.Fprintf(&b, "```%s\n", markdownLang(f.FilePath))
		fmt.Fprintln(&b, strings.TrimSpace(f.Evidence))
		fmt.Fprintln(&b, "```\n")
		fmt.Fprintln(&b, "**Remediation**")
		fmt.Fprintf(&b, "- %s\n\n", f.Remediation)
		fmt.Fprintln(&b, "---\n")
	}

	fmt.Fprintln(&b, "## Indicators of Compromise (IOCs)\n")
	fmt.Fprintln(&b, "### Network IOCs")
	if len(urls) == 0 {
		fmt.Fprintln(&b, "- No external URLs observed.")
	} else {
		max := len(urls)
		if max > 100 {
			max = 100
		}
		for i := 0; i < max; i++ {
			fmt.Fprintf(&b, "- `%s`\n", urls[i])
		}
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "### Behavioral IOCs")
	fmt.Fprintln(&b, "- Dynamic execution primitives (`new Function`, `eval`, shell execution APIs).")
	fmt.Fprintln(&b, "- Auto-run workflow hooks (`runOn: folderOpen`) and unattended execution paths.")
	fmt.Fprintln(&b, "- Encoded payload indicators (base64 blobs, hex-escaped sequences, high-entropy scripts).\n")

	fmt.Fprintln(&b, "## ML Feature Snapshot\n")
	fmt.Fprintln(&b, "| Feature | Value |")
	fmt.Fprintln(&b, "|---|---:|")
	keys := make([]string, 0, len(features))
	for k := range features {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "| %s | %.4f |\n", k, features[k])
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Remediation Plan\n")
	fmt.Fprintln(&b, "### Immediate Containment (0-2 hours)")
	fmt.Fprintln(&b, "1. Quarantine suspicious files and disable IDE auto-task execution.")
	fmt.Fprintln(&b, "2. Remove dynamic code execution and remote bootstrap logic.")
	fmt.Fprintln(&b, "3. Block/monitor IOC domains and rotate exposed credentials.\n")
	fmt.Fprintln(&b, "### Eradication (same day)")
	fmt.Fprintln(&b, "1. Replace hardcoded secrets with managed environment secrets.")
	fmt.Fprintln(&b, "2. Add CI checks for dangerous primitives and auto-exec behaviors.")
	fmt.Fprintln(&b, "3. Validate all dependencies and remove unnecessary packages.\n")
	fmt.Fprintln(&b, "### Recovery & Hardening (1-3 days)")
	fmt.Fprintln(&b, "1. Re-image impacted hosts when code execution is confirmed.")
	fmt.Fprintln(&b, "2. Add SAST + secret scanning + dependency scanning in CI/CD.")
	fmt.Fprintln(&b, "3. Enforce secure coding policy for external assessment repositories.\n")
	fmt.Fprintln(&b, "```mermaid")
	fmt.Fprintln(&b, "flowchart LR")
	fmt.Fprintln(&b, "  A[Containment] --> B[Eradication]")
	fmt.Fprintln(&b, "  B --> C[Credential Rotation]")
	fmt.Fprintln(&b, "  C --> D[Host Recovery]")
	fmt.Fprintln(&b, "  D --> E[Hardening]")
	fmt.Fprintln(&b, "```\n")
	fmt.Fprintln(&b, "## Confidence & Limitations\n")
	fmt.Fprintln(&b, "- Confidence is highest for static anti-patterns and known malware staging behaviors.")
	fmt.Fprintln(&b, "- Report does not execute payloads; dynamic sandboxing may reveal additional behavior.")
	fmt.Fprintln(&b, "- ML outputs are heuristic and intended for triage prioritization.\n")
	fmt.Fprintln(&b, "## Final Assessment\n")
	fmt.Fprintf(&b, "**%s** based on combined static findings and ML/anomaly scoring.\n", verdict)
	return b.String()
}

func main() {
	target := flag.String("target", ".", "Target repository path")
	outMD := flag.String("output-md", "SCAM_SCAN_REPORT_GO.md", "Output markdown report")
	outJSON := flag.String("output-json", "SCAM_SCAN_SUMMARY_GO.json", "Output json summary")
	flag.Parse()

	root, err := filepath.Abs(*target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve target: %v\n", err)
		os.Exit(1)
	}

	findings, stats, urls, err := scanRepo(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
		os.Exit(1)
	}

	anomalyFindings := detectAnomalies(stats)
	findings = append(findings, anomalyFindings...)

	score, features := exploitability(findings, stats, urls)
	band := scoreBand(score)
	report := renderReport(root, findings, stats, urls, score, band, features)

	if err := os.WriteFile(*outMD, []byte(report), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write markdown report: %v\n", err)
		os.Exit(1)
	}

	summary := ScanSummary{
		ExploitabilityScore: score,
		ExploitabilityBand:  band,
		SeverityCounts:      severityCounts(findings),
		FeatureVector:       features,
		URLs:                urls,
		Findings:            findings,
	}
	jsonBytes, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal summary: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outJSON, jsonBytes, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write json summary: %v\n", err)
		os.Exit(1)
	}

	w := bufio.NewWriter(os.Stdout)
	fmt.Fprintf(w, "[+] Scan completed for: %s\n", root)
	fmt.Fprintf(w, "[+] Markdown report: %s\n", *outMD)
	fmt.Fprintf(w, "[+] JSON summary: %s\n", *outJSON)
	fmt.Fprintf(w, "[+] Exploitability likelihood: %.1f%% (%s)\n", score*100, band)
	_ = w.Flush()
}

