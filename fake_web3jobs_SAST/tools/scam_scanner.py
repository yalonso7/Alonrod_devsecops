#!/usr/bin/env python3
"""
Web3 Fake-Job Scam Scanner (Python)

Static scanner with:
- Rule-based detection (RCE, auto-exec tasks, obfuscation, secret leaks, suspicious URLs)
- ML-style exploitability likelihood scoring (logistic model over extracted features)
- Unsupervised anomaly detection (per-file statistical outlier scoring)
- Markdown report generation with dashboards and mermaid graphs
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import statistics
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
DEFAULT_EXCLUDE_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    ".next",
    ".cache",
    "coverage",
    "__pycache__",
}
TEXT_EXTENSIONS = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".json",
    ".sol",
    ".md",
    ".yml",
    ".yaml",
    ".py",
    ".go",
    ".sh",
    ".cmd",
    ".ps1",
}
SPECIAL_FILENAMES = {"package.json", "tasks.json", "README.md"}


@dataclass
class Finding:
    severity: str
    title: str
    file_path: str
    line: int
    why: str
    impact: str
    evidence: str
    category: str
    remediation: str


@dataclass
class FileStats:
    file_path: str
    entropy: float
    long_line_ratio: float
    hex_escape_count: int
    suspicious_token_count: int
    non_alnum_ratio: float
    line_count: int


@dataclass
class ScanResult:
    findings: List[Finding]
    anomaly_findings: List[Finding]
    exploitability_score: float
    exploitability_band: str
    feature_vector: Dict[str, float]
    urls: List[str]
    scanned_files: int
    file_stats: List[FileStats]


@dataclass
class Rule:
    id: str
    severity: str
    title: str
    category: str
    pattern: re.Pattern
    why: str
    impact: str
    remediation: str


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def is_text_candidate(filename: str) -> bool:
    base = os.path.basename(filename)
    _, ext = os.path.splitext(filename.lower())
    return ext in TEXT_EXTENSIONS or base in SPECIAL_FILENAMES


def safe_read(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return None


def extract_line_snippet(content: str, line_number: int, context: int = 2) -> str:
    lines = content.splitlines()
    if not lines:
        return ""
    start = max(1, line_number - context)
    end = min(len(lines), line_number + context)
    out: List[str] = []
    for idx in range(start, end + 1):
        out.append(f"{idx}: {lines[idx - 1]}")
    return "\n".join(out)


def build_rules() -> List[Rule]:
    return [
        Rule(
            id="remote_exec_function_constructor",
            severity="Critical",
            title="Dynamic Code Execution Primitive Detected",
            category="RCE",
            pattern=re.compile(r"new\s+Function(?:\.constructor)?\s*\(", re.IGNORECASE),
            why="Dynamic runtime code construction enables arbitrary payload execution.",
            impact="Remote code execution and full process compromise.",
            remediation="Remove dynamic execution and replace with strict, typed control flow.",
        ),
        Rule(
            id="eval_usage",
            severity="High",
            title="Potentially Unsafe eval Usage",
            category="RCE",
            pattern=re.compile(r"\beval\s*\(", re.IGNORECASE),
            why="eval executes arbitrary strings as code.",
            impact="Code injection and arbitrary behavior under attacker-controlled input.",
            remediation="Replace eval with safe parsers or explicit dispatch maps.",
        ),
        Rule(
            id="child_process_exec",
            severity="Critical",
            title="Process Execution Primitive with Potential Abuse",
            category="Execution",
            pattern=re.compile(r"child_process|exec\s*\(|spawn\s*\(|execFile\s*\(", re.IGNORECASE),
            why="Shell/process execution APIs are commonly abused by droppers and backdoors.",
            impact="Host compromise through arbitrary command execution.",
            remediation="Restrict command execution, remove from untrusted paths, and harden input validation.",
        ),
        Rule(
            id="vscode_folder_open_autoexec",
            severity="Critical",
            title="VS Code Auto-Run Task on Folder Open",
            category="Persistence",
            pattern=re.compile(r'"runOn"\s*:\s*"folderOpen"', re.IGNORECASE),
            why="Auto-running tasks on folder open can execute payloads without explicit consent.",
            impact="Developer workstation compromise upon opening project.",
            remediation="Remove folder-open tasks and require explicit user invocation.",
        ),
        Rule(
            id="remote_payload_fetch",
            severity="High",
            title="Remote Payload Fetch Pattern",
            category="C2",
            pattern=re.compile(r"(axios|get|fetch|https\.get)\s*\([^)]*https?://", re.IGNORECASE),
            why="Direct remote fetch in sensitive paths may stage executable payloads.",
            impact="Remote code delivery and command-and-control enablement.",
            remediation="Disallow remote code/data bootstrap in runtime paths and pin trusted APIs.",
        ),
        Rule(
            id="base64_c2_url",
            severity="High",
            title="Encoded URL / Obfuscated Endpoint Indicator",
            category="Obfuscation",
            pattern=re.compile(r"(atob\s*\(|Buffer\.from\([^)]*base64|[A-Za-z0-9+/]{40,}={0,2})", re.IGNORECASE),
            why="Encoded URLs and long base64 blobs are common for C2 concealment.",
            impact="Hidden malicious infrastructure and delayed detection.",
            remediation="Decode and validate all encoded literals; remove untrusted endpoints.",
        ),
        Rule(
            id="hardcoded_secret",
            severity="High",
            title="Hardcoded Secret/Key Material",
            category="Secrets",
            pattern=re.compile(
                r"(secret|api[_-]?key|private[_-]?key|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
                re.IGNORECASE,
            ),
            why="Embedded secrets are recoverable from source and artifacts.",
            impact="Credential theft, token forgery, and unauthorized access.",
            remediation="Move secrets to environment/secret manager and rotate exposed values.",
        ),
        Rule(
            id="wallet_dangerous_signing",
            severity="High",
            title="Wallet Signature/Approval Risk Pattern",
            category="Web3",
            pattern=re.compile(
                r"(eth_sign|personal_sign|signTypedData|setApprovalForAll|approve\s*\(|permit\s*\()",
                re.IGNORECASE,
            ),
            why="High-risk wallet methods can be abused for drainer workflows.",
            impact="Asset approvals/signatures can be abused to transfer user funds.",
            remediation="Require explicit UX confirmation, scope checks, and transaction simulation.",
        ),
    ]


def normalize_path(path: str, root: str) -> str:
    rel = os.path.relpath(path, root)
    return rel.replace("\\", "/")


def collect_files(root: str) -> List[str]:
    out: List[str] = []
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDE_DIRS]
        for name in files:
            path = os.path.join(base, name)
            if is_text_candidate(path):
                out.append(path)
    return out


def match_rule(rule: Rule, content: str, file_path: str) -> List[Tuple[int, str]]:
    matches: List[Tuple[int, str]] = []
    for m in rule.pattern.finditer(content):
        line = content.count("\n", 0, m.start()) + 1
        snippet = extract_line_snippet(content, line)
        matches.append((line, snippet))
        if len(matches) >= 5:
            break
    return matches


def extract_urls(content: str) -> List[str]:
    return re.findall(r"https?://[^\s\"'`)>]+", content)


def calc_file_stats(content: str, rel_path: str) -> FileStats:
    lines = content.splitlines() or [""]
    avg_long = sum(1 for ln in lines if len(ln) > 220) / max(len(lines), 1)
    hex_escape_count = len(re.findall(r"\\x[0-9a-fA-F]{2}", content))
    suspicious_tokens = len(
        re.findall(
            r"(atob\(|fromCharCode\(|new Function|eval\(|child_process|exec\(|spawn\(|process\.env|os\.)",
            content,
            flags=re.IGNORECASE,
        )
    )
    text_sample = content[:20000]
    alnum = sum(1 for ch in text_sample if ch.isalnum())
    non_alnum_ratio = 1.0 - (alnum / max(len(text_sample), 1))
    return FileStats(
        file_path=rel_path,
        entropy=shannon_entropy(text_sample),
        long_line_ratio=avg_long,
        hex_escape_count=hex_escape_count,
        suspicious_token_count=suspicious_tokens,
        non_alnum_ratio=non_alnum_ratio,
        line_count=len(lines),
    )


def detect_anomalies(stats: List[FileStats]) -> List[Tuple[FileStats, float]]:
    if len(stats) < 3:
        return []

    metric_names = [
        "entropy",
        "long_line_ratio",
        "hex_escape_count",
        "suspicious_token_count",
        "non_alnum_ratio",
    ]
    means: Dict[str, float] = {}
    stdevs: Dict[str, float] = {}
    for name in metric_names:
        vals = [float(getattr(s, name)) for s in stats]
        means[name] = statistics.mean(vals)
        stdevs[name] = statistics.pstdev(vals) or 1e-6

    scored: List[Tuple[FileStats, float]] = []
    for s in stats:
        zsum = 0.0
        for name in metric_names:
            value = float(getattr(s, name))
            z = (value - means[name]) / stdevs[name]
            if z > 0:
                zsum += z
        anomaly_score = zsum / len(metric_names)
        if anomaly_score >= 1.2:
            scored.append((s, anomaly_score))
    scored.sort(key=lambda item: item[1], reverse=True)
    return scored[:10]


def sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1 / (1 + z)
    z = math.exp(x)
    return z / (1 + z)


def ml_exploitability_score(findings: List[Finding], stats: List[FileStats], urls: List[str]) -> Tuple[float, Dict[str, float]]:
    sev_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    categories = {"RCE": 0, "Execution": 0, "Persistence": 0, "C2": 0, "Obfuscation": 0, "Secrets": 0, "Web3": 0}
    for f in findings:
        sev_count[f.severity] += 1
        categories[f.category] = categories.get(f.category, 0) + 1

    suspicious_domains = 0
    for u in urls:
        host = urlparse(u).netloc.lower()
        if any(x in host for x in ("npoint.io", "vercel.app", "raw.githubusercontent.com", "pastebin")):
            suspicious_domains += 1

    max_entropy = max((s.entropy for s in stats), default=0.0)
    total_hex = sum(s.hex_escape_count for s in stats)

    features: Dict[str, float] = {
        "critical_count": float(sev_count["Critical"]),
        "high_count": float(sev_count["High"]),
        "rce_signals": float(categories.get("RCE", 0) + categories.get("Execution", 0)),
        "persistence_signals": float(categories.get("Persistence", 0)),
        "obfuscation_signals": float(categories.get("Obfuscation", 0)),
        "suspicious_domain_hits": float(suspicious_domains),
        "max_file_entropy": max_entropy,
        "hex_escape_total": float(total_hex),
        "finding_density": float(len(findings)) / max(len(stats), 1),
    }

    # Lightweight logistic model (heuristic coefficients calibrated for malware-like repo patterns).
    weights = {
        "critical_count": 0.95,
        "high_count": 0.45,
        "rce_signals": 0.70,
        "persistence_signals": 0.80,
        "obfuscation_signals": 0.60,
        "suspicious_domain_hits": 0.35,
        "max_file_entropy": 0.55,
        "hex_escape_total": 0.006,
        "finding_density": 1.20,
    }
    bias = -4.2
    linear = bias + sum(features[k] * w for k, w in weights.items())
    return sigmoid(linear), features


def severity_counts(findings: Iterable[Finding]) -> Dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def exploitability_band(score: float) -> str:
    if score >= 0.90:
        return "Very High"
    if score >= 0.70:
        return "High"
    if score >= 0.45:
        return "Medium"
    return "Low"


def scan_repository(root: str) -> ScanResult:
    rules = build_rules()
    files = collect_files(root)
    findings: List[Finding] = []
    stats: List[FileStats] = []
    urls_set = set()

    for abs_path in files:
        content = safe_read(abs_path)
        if content is None:
            continue
        rel_path = normalize_path(abs_path, root)
        stats.append(calc_file_stats(content, rel_path))
        for u in extract_urls(content):
            urls_set.add(u)
        for rule in rules:
            for line, snippet in match_rule(rule, content, rel_path):
                findings.append(
                    Finding(
                        severity=rule.severity,
                        title=rule.title,
                        file_path=rel_path,
                        line=line,
                        why=rule.why,
                        impact=rule.impact,
                        evidence=snippet,
                        category=rule.category,
                        remediation=rule.remediation,
                    )
                )

    # Add chain-strengthening critical if folderOpen + child_process + remote URL occur in same file.
    for abs_path in files:
        if os.path.basename(abs_path).lower() != "tasks.json":
            continue
        content = safe_read(abs_path) or ""
        if (
            re.search(r'"runOn"\s*:\s*"folderOpen"', content, flags=re.IGNORECASE)
            and re.search(r"child_process|exec\s*\(", content, flags=re.IGNORECASE)
            and re.search(r"https?://", content, flags=re.IGNORECASE)
        ):
            rel_path = normalize_path(abs_path, root)
            findings.append(
                Finding(
                    severity="Critical",
                    title="Download-Execute-Delete Dropper Chain",
                    file_path=rel_path,
                    line=1,
                    why="Combines auto-run trigger with remote download and shell execution.",
                    impact="Immediate endpoint compromise when workspace is opened.",
                    evidence=extract_line_snippet(content, 1, context=10),
                    category="Execution",
                    remediation="Delete task, block endpoint, and verify endpoint telemetry.",
                )
            )

    anomalies = detect_anomalies(stats)
    anomaly_findings: List[Finding] = []
    for s, score in anomalies:
        if s.hex_escape_count == 0 and s.suspicious_token_count == 0:
            continue
        anomaly_findings.append(
            Finding(
                severity="Medium" if score < 2.0 else "High",
                title=f"Anomalous File Signature (score={score:.2f})",
                file_path=s.file_path,
                line=1,
                why="Statistical outlier across entropy/obfuscation/exec-token metrics.",
                impact="Likely hidden payload or non-benign packed script behavior.",
                evidence=(
                    f"entropy={s.entropy:.2f}, long_line_ratio={s.long_line_ratio:.2f}, "
                    f"hex_escapes={s.hex_escape_count}, suspicious_tokens={s.suspicious_token_count}, "
                    f"non_alnum_ratio={s.non_alnum_ratio:.2f}"
                ),
                category="Obfuscation",
                remediation="Manually reverse/deobfuscate and isolate before execution.",
            )
        )

    all_findings = findings + anomaly_findings
    all_findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file_path, f.line))
    score, features = ml_exploitability_score(all_findings, stats, sorted(urls_set))
    return ScanResult(
        findings=all_findings,
        anomaly_findings=anomaly_findings,
        exploitability_score=score,
        exploitability_band=exploitability_band(score),
        feature_vector=features,
        urls=sorted(urls_set),
        scanned_files=len(stats),
        file_stats=stats,
    )


def markdown_code_lang(path: str) -> str:
    ext = os.path.splitext(path.lower())[1]
    return {
        ".js": "js",
        ".jsx": "jsx",
        ".ts": "ts",
        ".tsx": "tsx",
        ".json": "json",
        ".sol": "solidity",
        ".md": "md",
        ".py": "python",
        ".go": "go",
    }.get(ext, "text")


def format_report(result: ScanResult, target_root: str) -> str:
    counts = severity_counts(result.findings)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_findings = len(result.findings)
    verdict = "Likely malicious" if result.exploitability_score >= 0.70 else "Suspicious" if result.exploitability_score >= 0.45 else "Likely benign"

    lines: List[str] = []
    lines.append("# Security Assessment Report - Job Scam Scanner")
    lines.append("")
    lines.append(f"**Target:** `{os.path.basename(target_root)}`  ")
    lines.append("**Scanner:** `tools/scam_scanner.py`  ")
    lines.append(f"**Generated:** {date_str}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Total findings: **{total_findings}** across **{result.scanned_files}** scanned files.")
    lines.append(f"- ML exploitability likelihood: **{result.exploitability_score:.1%}** (**{result.exploitability_band}**).")
    lines.append(f"- Verdict: **{verdict}**.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Risk Dashboard")
    lines.append("")
    lines.append("### Severity Distribution")
    lines.append("")
    lines.append("```mermaid")
    lines.append("pie title Findings by Severity")
    lines.append(f'  "Critical" : {counts.get("Critical", 0)}')
    lines.append(f'  "High" : {counts.get("High", 0)}')
    lines.append(f'  "Medium" : {counts.get("Medium", 0)}')
    lines.append(f'  "Low" : {counts.get("Low", 0)}')
    lines.append("```")
    lines.append("")
    lines.append("### Exploitability & Anomaly Dashboard")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Exploitability likelihood | {result.exploitability_score:.1%} |")
    lines.append(f"| Exploitability band | {result.exploitability_band} |")
    lines.append(f"| Anomaly findings | {len(result.anomaly_findings)} |")
    lines.append(f"| Suspicious URLs observed | {len(result.urls)} |")
    lines.append(f"| Findings density | {result.feature_vector['finding_density']:.2f} |")
    lines.append("")
    lines.append("### Attack Chain Graph")
    lines.append("")
    lines.append("```mermaid")
    lines.append("flowchart TD")
    lines.append("  A[Workspace Open / Runtime Start] --> B[Suspicious Trigger]")
    lines.append("  B --> C[Remote Fetch or Encoded Payload]")
    lines.append("  C --> D[Dynamic Execution Primitive]")
    lines.append("  D --> E[Potential Host or Server Compromise]")
    lines.append("```")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Findings (Prioritized)")
    lines.append("")

    for idx, finding in enumerate(result.findings, start=1):
        lines.append(f"## {idx}) {finding.severity} - {finding.title}")
        lines.append("")
        lines.append(f"**Affected file**: `{finding.file_path}`")
        lines.append("")
        lines.append("**Why this is suspicious**")
        lines.append(f"- {finding.why}")
        lines.append("")
        lines.append("**Potential impact**")
        lines.append(f"- {finding.impact}")
        lines.append("")
        lines.append("**Evidence**")
        lines.append("")
        lines.append(f"```{markdown_code_lang(finding.file_path)}")
        lines.append(finding.evidence.strip() or "(evidence unavailable)")
        lines.append("```")
        lines.append("")
        lines.append("**Remediation**")
        lines.append(f"- {finding.remediation}")
        lines.append("")
        lines.append("---")
        lines.append("")

    lines.append("## Indicators of Compromise (IOCs)")
    lines.append("")
    lines.append("### Network IOCs")
    if result.urls:
        for url in result.urls[:100]:
            lines.append(f"- `{url}`")
    else:
        lines.append("- No external URLs observed.")
    lines.append("")
    lines.append("### Behavioral IOCs")
    lines.append("- Dynamic execution primitives (`new Function`, `eval`, shell execution APIs).")
    lines.append("- Auto-run workflow hooks (`runOn: folderOpen`) and unattended execution paths.")
    lines.append("- Encoded payload indicators (base64 blobs, hex-escaped sequences, high-entropy scripts).")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## ML Feature Snapshot")
    lines.append("")
    lines.append("| Feature | Value |")
    lines.append("|---|---:|")
    for key in sorted(result.feature_vector.keys()):
        lines.append(f"| {key} | {result.feature_vector[key]:.4f} |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Remediation Plan")
    lines.append("")
    lines.append("### Immediate Containment (0-2 hours)")
    lines.append("1. Quarantine suspicious files and disable IDE auto-task execution.")
    lines.append("2. Remove dynamic code execution and remote bootstrap logic.")
    lines.append("3. Block/monitor IOC domains and rotate exposed credentials.")
    lines.append("")
    lines.append("### Eradication (same day)")
    lines.append("1. Replace hardcoded secrets with managed environment secrets.")
    lines.append("2. Add CI checks for dangerous primitives and auto-exec behaviors.")
    lines.append("3. Validate all dependencies and remove unnecessary packages.")
    lines.append("")
    lines.append("### Recovery & Hardening (1-3 days)")
    lines.append("1. Re-image impacted hosts when code execution is confirmed.")
    lines.append("2. Add SAST + secret scanning + dependency scanning in CI/CD.")
    lines.append("3. Enforce secure coding policy for external assessment repositories.")
    lines.append("")
    lines.append("```mermaid")
    lines.append("flowchart LR")
    lines.append("  A[Containment] --> B[Eradication]")
    lines.append("  B --> C[Credential Rotation]")
    lines.append("  C --> D[Host Recovery]")
    lines.append("  D --> E[Hardening]")
    lines.append("```")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Confidence & Limitations")
    lines.append("")
    lines.append("- Confidence is highest for static anti-patterns and known malware staging behaviors.")
    lines.append("- Report does not execute payloads; dynamic sandboxing may reveal additional behavior.")
    lines.append("- ML outputs are heuristic and intended for triage prioritization.")
    lines.append("")
    lines.append("## Final Assessment")
    lines.append("")
    lines.append(f"**{verdict}** based on combined static findings and ML/anomaly scoring.")
    lines.append("")
    return "\n".join(lines)


def write_json_summary(path: str, result: ScanResult) -> None:
    payload = {
        "exploitability_score": result.exploitability_score,
        "exploitability_band": result.exploitability_band,
        "severity_counts": severity_counts(result.findings),
        "feature_vector": result.feature_vector,
        "findings": [
            {
                "severity": f.severity,
                "title": f.title,
                "file_path": f.file_path,
                "line": f.line,
                "category": f.category,
            }
            for f in result.findings
        ],
        "urls": result.urls,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan repositories for fake-job scam indicators.")
    parser.add_argument("target", nargs="?", default=".", help="Target repository path")
    parser.add_argument(
        "--output-md",
        default="SCAM_SCAN_REPORT_PY.md",
        help="Output Markdown report path",
    )
    parser.add_argument(
        "--output-json",
        default="SCAM_SCAN_SUMMARY_PY.json",
        help="Output JSON summary path",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = os.path.abspath(args.target)
    result = scan_repository(root)
    report = format_report(result, root)

    md_path = os.path.abspath(args.output_md)
    json_path = os.path.abspath(args.output_json)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(report)
    write_json_summary(json_path, result)

    print(f"[+] Scan completed for: {root}")
    print(f"[+] Markdown report: {md_path}")
    print(f"[+] JSON summary: {json_path}")
    print(f"[+] Exploitability likelihood: {result.exploitability_score:.1%} ({result.exploitability_band})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

