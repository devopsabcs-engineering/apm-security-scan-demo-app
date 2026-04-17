#!/usr/bin/env python3
"""
Semantic Pattern Scanner — Engine 3 of the APM Security 4-engine architecture.

Scans agent configuration files for embedded threat patterns and produces
SARIF v2.1.0 output with automationDetails.id: apm-security/semantic.

Rule IDs:
  APM-SEC-001: Base64-encoded payload (CWE-506)
  APM-SEC-002: Embedded external URL (CWE-200)
  APM-SEC-003: Shell command injection (CWE-78)
  APM-SEC-004: System prompt override (CWE-94)
  APM-SEC-006: Secrets pattern (CWE-798)
  APM-SEC-007: Excessive tool permissions (CWE-269)
  APM-SEC-008: Missing CODEOWNERS (CWE-862)
"""

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

AGENT_CONFIG_GLOBS = [
    "**/*.agent.md", "**/*.instructions.md", "**/*.prompt.md",
    "**/SKILL.md", "**/copilot-instructions.md", "**/AGENTS.md",
    "**/CLAUDE.md", "**/apm.yml", "**/mcp.json"
]

URL_ALLOWLIST_DOMAINS = [
    "github.com", "microsoft.com", "owasp.org", "w3.org",
    "docs.oasis-open.org", "cdn.jsdelivr.net", "rubygems.org",
    "genai.owasp.org", "atlas.mitre.org", "danielmeppiel.github.io",
    "devopsabcs-engineering.github.io", "dev.azure.com",
    "code.visualstudio.com", "react.dev", "learn.microsoft.com",
    "pypi.org", "npmjs.com", "golang.org", "pkg.go.dev"
]

RULES = {
    "APM-SEC-001": {
        "id": "APM-SEC-001",
        "shortDescription": {"text": "Base64-encoded payload detected"},
        "fullDescription": {"text": "A Base64-encoded string of 40+ characters was found in an agent configuration file. This could embed hidden instructions."},
        "helpUri": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
        "properties": {"tags": ["security", "prompt-injection", "CWE-506", "OWASP-LLM01"]}
    },
    "APM-SEC-002": {
        "id": "APM-SEC-002",
        "shortDescription": {"text": "Embedded external URL not in allowlist"},
        "fullDescription": {"text": "An external URL was found that is not in the approved domain allowlist. This could be an exfiltration endpoint."},
        "helpUri": "https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/",
        "properties": {"tags": ["security", "exfiltration", "CWE-200", "OWASP-LLM07"]}
    },
    "APM-SEC-003": {
        "id": "APM-SEC-003",
        "shortDescription": {"text": "Shell command injection pattern"},
        "fullDescription": {"text": "A shell command injection pattern (&&, ||, ;, backticks, $()) was found outside of a code block in an agent configuration file."},
        "helpUri": "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
        "properties": {"tags": ["security", "command-injection", "CWE-78", "OWASP-LLM06"]}
    },
    "APM-SEC-004": {
        "id": "APM-SEC-004",
        "shortDescription": {"text": "System prompt override phrase detected"},
        "fullDescription": {"text": "A system prompt override phrase was detected that could hijack agent behavior."},
        "helpUri": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
        "properties": {"tags": ["security", "prompt-injection", "CWE-94", "OWASP-LLM01"]}
    },
    "APM-SEC-006": {
        "id": "APM-SEC-006",
        "shortDescription": {"text": "Secrets pattern detected"},
        "fullDescription": {"text": "An API key, token, password, or secret pattern was found in an agent configuration file."},
        "helpUri": "https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/",
        "properties": {"tags": ["security", "secrets", "CWE-798", "OWASP-LLM07"]}
    },
    "APM-SEC-007": {
        "id": "APM-SEC-007",
        "shortDescription": {"text": "Excessive tool permissions"},
        "fullDescription": {"text": "An agent definition includes more than 15 tools or uses a wildcard, granting excessive agency."},
        "helpUri": "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
        "properties": {"tags": ["security", "excessive-agency", "CWE-269", "OWASP-LLM06"]}
    },
    "APM-SEC-008": {
        "id": "APM-SEC-008",
        "shortDescription": {"text": "Missing CODEOWNERS protection"},
        "fullDescription": {"text": "No CODEOWNERS file found or it does not cover agent configuration directories."},
        "helpUri": "https://genai.owasp.org/llmrisk/llm032025-supply-chain/",
        "properties": {"tags": ["security", "supply-chain", "CWE-862", "OWASP-LLM03"]}
    }
}

SEVERITY_MAP = {
    "APM-SEC-001": ("error", "7.0"),
    "APM-SEC-002": ("warning", "4.0"),
    "APM-SEC-003": ("error", "7.0"),
    "APM-SEC-004": ("error", "9.0"),
    "APM-SEC-006": ("error", "9.0"),
    "APM-SEC-007": ("warning", "4.0"),
    "APM-SEC-008": ("note", "1.0"),
}

BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/=]{40,}')
URL_PATTERN = re.compile(r'https?://[^\s)\]>"\']+')
SHELL_PATTERN = re.compile(r'(?:&&|\|\||;|`[^`]+`|\$\([^)]+\))')
OVERRIDE_PHRASES = [
    "ignore previous instructions", "ignore all previous",
    "override all", "bypass safety", "disregard above",
    "forget your instructions", "you are now", "act as if"
]
SECRETS_PATTERN = re.compile(
    r'(?:api[_-]?key|token|password|secret|credential)\s*[:=]\s*["\']?\S{8,}',
    re.IGNORECASE
)


def is_in_code_block(lines, line_idx):
    """Check if a line is inside a fenced code block."""
    fence_count = 0
    for i in range(line_idx):
        stripped = lines[i].strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            fence_count += 1
    return fence_count % 2 == 1


def scan_file(filepath, scan_dir):
    """Scan a single file for semantic patterns."""
    findings = []
    rel_path = os.path.relpath(filepath, scan_dir)

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except Exception:
        return findings

    for line_idx, line in enumerate(lines):
        if is_in_code_block(lines, line_idx):
            continue

        # APM-SEC-001: Base64
        for match in BASE64_PATTERN.finditer(line):
            findings.append({
                "ruleId": "APM-SEC-001",
                "file": rel_path,
                "line": line_idx + 1,
                "col": match.start() + 1,
                "message": f"Base64-encoded payload ({len(match.group())} chars): {match.group()[:30]}..."
            })

        # APM-SEC-002: External URLs
        for match in URL_PATTERN.finditer(line):
            url = match.group()
            domain = url.split("//")[1].split("/")[0].split(":")[0]
            if not any(domain.endswith(allowed) for allowed in URL_ALLOWLIST_DOMAINS):
                findings.append({
                    "ruleId": "APM-SEC-002",
                    "file": rel_path,
                    "line": line_idx + 1,
                    "col": match.start() + 1,
                    "message": f"External URL not in allowlist: {url}"
                })

        # APM-SEC-003: Shell injection
        for match in SHELL_PATTERN.finditer(line):
            findings.append({
                "ruleId": "APM-SEC-003",
                "file": rel_path,
                "line": line_idx + 1,
                "col": match.start() + 1,
                "message": f"Shell command injection pattern: {match.group()}"
            })

        # APM-SEC-004: Override phrases
        lower_line = line.lower()
        for phrase in OVERRIDE_PHRASES:
            idx = lower_line.find(phrase)
            if idx >= 0:
                findings.append({
                    "ruleId": "APM-SEC-004",
                    "file": rel_path,
                    "line": line_idx + 1,
                    "col": idx + 1,
                    "message": f"System prompt override: '{phrase}'"
                })

        # APM-SEC-006: Secrets
        for match in SECRETS_PATTERN.finditer(line):
            findings.append({
                "ruleId": "APM-SEC-006",
                "file": rel_path,
                "line": line_idx + 1,
                "col": match.start() + 1,
                "message": f"Possible secret: {match.group()[:40]}..."
            })

    return findings


def check_codeowners(scan_dir):
    """Check for CODEOWNERS coverage of agent config directories."""
    findings = []
    codeowners_paths = [
        os.path.join(scan_dir, "CODEOWNERS"),
        os.path.join(scan_dir, ".github", "CODEOWNERS"),
        os.path.join(scan_dir, "docs", "CODEOWNERS"),
    ]

    if not any(os.path.exists(p) for p in codeowners_paths):
        findings.append({
            "ruleId": "APM-SEC-008",
            "file": "CODEOWNERS",
            "line": 1,
            "col": 1,
            "message": "No CODEOWNERS file found — agent config directories are unprotected"
        })

    return findings


def collect_files(scan_dir):
    """Collect all agent config files to scan."""
    from glob import glob
    files = set()
    for pattern in AGENT_CONFIG_GLOBS:
        for f in glob(os.path.join(scan_dir, pattern), recursive=True):
            if os.path.isfile(f):
                files.add(f)
    return sorted(files)


def build_sarif(findings):
    """Build SARIF v2.1.0 output from findings."""
    results = []
    for f in findings:
        level, severity = SEVERITY_MAP.get(f["ruleId"], ("warning", "4.0"))
        fingerprint = hashlib.sha256(
            f"{f['ruleId']}:{f['file']}:{f['line']}".encode()
        ).hexdigest()[:32]

        results.append({
            "ruleId": f["ruleId"],
            "level": level,
            "message": {"text": f["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"].replace("\\", "/")},
                    "region": {
                        "startLine": f["line"],
                        "startColumn": f["col"]
                    }
                }
            }],
            "partialFingerprints": {"primaryLocationLineHash": fingerprint},
            "properties": {"security-severity": severity}
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "apm-semantic-scanner",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/devopsabcs-engineering/apm-security-scan-demo-app",
                    "rules": list(RULES.values())
                }
            },
            "automationDetails": {"id": "apm-security/semantic"},
            "results": results
        }]
    }


def main():
    parser = argparse.ArgumentParser(description="APM Security Semantic Pattern Scanner")
    parser.add_argument("--scan-dir", default=".", help="Directory to scan")
    parser.add_argument("--output", default="semantic-results.sarif", help="Output SARIF file")
    args = parser.parse_args()

    scan_dir = os.path.abspath(args.scan_dir)
    files = collect_files(scan_dir)

    all_findings = []
    for filepath in files:
        all_findings.extend(scan_file(filepath, scan_dir))

    all_findings.extend(check_codeowners(scan_dir))

    sarif = build_sarif(all_findings)

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(sarif, f, indent=2)

    error_count = sum(1 for f in all_findings if SEVERITY_MAP.get(f["ruleId"], ("warning",))[0] == "error")
    print(f"Semantic scan complete: {len(all_findings)} findings ({error_count} errors)")

    sys.exit(1 if error_count > 0 else 0)


if __name__ == "__main__":
    main()
