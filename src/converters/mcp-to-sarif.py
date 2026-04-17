#!/usr/bin/env python3
"""
MCP Configuration Validator — Engine 4 of the APM Security 4-engine architecture.

Validates mcp.json against organizational security requirements and an
approved server allowlist. Produces SARIF v2.1.0 output with
automationDetails.id: apm-security/mcp.

Rule IDs:
  APM-SEC-005: Unauthorized MCP server (CWE-829)
  APM-SEC-007: Excessive tool permissions (CWE-269)
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

RULES = {
    "APM-SEC-005": {
        "id": "APM-SEC-005",
        "shortDescription": {"text": "Unauthorized MCP server"},
        "fullDescription": {"text": "An MCP server was found that is not in the approved server allowlist."},
        "helpUri": "https://genai.owasp.org/llmrisk/llm032025-supply-chain/",
        "properties": {"tags": ["security", "supply-chain", "CWE-829", "OWASP-LLM03"]}
    },
    "MCP-TRANSPORT": {
        "id": "MCP-TRANSPORT",
        "shortDescription": {"text": "Insecure MCP transport"},
        "fullDescription": {"text": "A remote MCP server does not use HTTPS/TLS transport."},
        "helpUri": "https://genai.owasp.org/llmrisk/llm032025-supply-chain/",
        "properties": {"tags": ["security", "transport", "CWE-319"]}
    },
    "MCP-AUTH": {
        "id": "MCP-AUTH",
        "shortDescription": {"text": "Missing MCP authentication"},
        "fullDescription": {"text": "A remote MCP server does not specify an authentication method."},
        "helpUri": "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
        "properties": {"tags": ["security", "authentication", "CWE-306"]}
    },
    "APM-SEC-007": {
        "id": "APM-SEC-007",
        "shortDescription": {"text": "Excessive tool permissions"},
        "fullDescription": {"text": "An MCP server exposes more than 15 tools or uses a wildcard, granting excessive agency."},
        "helpUri": "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
        "properties": {"tags": ["security", "excessive-agency", "CWE-269", "OWASP-LLM06"]}
    }
}

SEVERITY_MAP = {
    "APM-SEC-005": ("error", "7.0"),
    "MCP-TRANSPORT": ("error", "7.0"),
    "MCP-AUTH": ("error", "7.0"),
    "APM-SEC-007": ("warning", "4.0"),
}

DEFAULT_ALLOWLIST = {
    "approvedServers": [
        {"name": "github-mcp-server", "publisher": "github", "transport": ["stdio"], "maxTools": 30, "approved": True},
        {"name": "playwright-mcp-server", "publisher": "microsoft", "transport": ["stdio"], "maxTools": 20, "approved": True},
    ]
}


def load_allowlist(scan_dir):
    """Load MCP server allowlist from config."""
    allowlist_path = os.path.join(scan_dir, "src", "config", "mcp-allowlist.json")
    if not os.path.exists(allowlist_path):
        # Check parent scanner repo
        parent_allowlist = os.path.join(os.path.dirname(scan_dir), "apm-security-scan-demo-app", "src", "config", "mcp-allowlist.json")
        if os.path.exists(parent_allowlist):
            allowlist_path = parent_allowlist
        else:
            return DEFAULT_ALLOWLIST

    try:
        with open(allowlist_path, 'r') as f:
            return json.load(f)
    except Exception:
        return DEFAULT_ALLOWLIST


def find_mcp_files(scan_dir):
    """Find all mcp.json files in the scan directory."""
    files = []
    for root, _, filenames in os.walk(scan_dir):
        for fn in filenames:
            if fn == "mcp.json":
                files.append(os.path.join(root, fn))
    return files


def validate_mcp(filepath, scan_dir, allowlist):
    """Validate a single mcp.json file."""
    findings = []
    rel_path = os.path.relpath(filepath, scan_dir)

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            config = json.load(f)
    except Exception as e:
        findings.append({
            "ruleId": "APM-SEC-005",
            "file": rel_path,
            "line": 1,
            "col": 1,
            "message": f"Failed to parse mcp.json: {str(e)}"
        })
        return findings

    servers = config.get("mcpServers", config.get("servers", {}))
    approved_names = {s["name"] for s in allowlist.get("approvedServers", []) if s.get("approved")}

    line_num = 1
    for server_name, server_config in servers.items():
        line_num += 1

        # Check allowlist
        if server_name not in approved_names:
            findings.append({
                "ruleId": "APM-SEC-005",
                "file": rel_path,
                "line": line_num,
                "col": 1,
                "message": f"Unauthorized MCP server: '{server_name}' not in approved allowlist"
            })

        # Check transport security for remote servers
        transport = server_config.get("transport", "stdio")
        if isinstance(transport, dict):
            transport_type = transport.get("type", "stdio")
        else:
            transport_type = transport

        if transport_type in ("sse", "http", "streamable-http"):
            url = server_config.get("url", server_config.get("endpoint", ""))
            if isinstance(transport, dict):
                url = transport.get("url", url)
            if url and not url.startswith("https://"):
                findings.append({
                    "ruleId": "MCP-TRANSPORT",
                    "file": rel_path,
                    "line": line_num,
                    "col": 1,
                    "message": f"MCP server '{server_name}' uses insecure transport: {url}"
                })

            # Check authentication for remote servers
            auth = server_config.get("auth", server_config.get("authentication"))
            if not auth:
                findings.append({
                    "ruleId": "MCP-AUTH",
                    "file": rel_path,
                    "line": line_num,
                    "col": 1,
                    "message": f"MCP server '{server_name}' has no authentication configured"
                })

        # Check tool count
        tools = server_config.get("tools", [])
        if isinstance(tools, list) and len(tools) > 15:
            findings.append({
                "ruleId": "APM-SEC-007",
                "file": rel_path,
                "line": line_num,
                "col": 1,
                "message": f"MCP server '{server_name}' exposes {len(tools)} tools (max recommended: 15)"
            })
        elif isinstance(tools, str) and tools == "*":
            findings.append({
                "ruleId": "APM-SEC-007",
                "file": rel_path,
                "line": line_num,
                "col": 1,
                "message": f"MCP server '{server_name}' uses wildcard tool permissions"
            })

    return findings


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
                    "name": "apm-mcp-validator",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/devopsabcs-engineering/apm-security-scan-demo-app",
                    "rules": list(RULES.values())
                }
            },
            "automationDetails": {"id": "apm-security/mcp"},
            "results": results
        }]
    }


def main():
    parser = argparse.ArgumentParser(description="APM Security MCP Configuration Validator")
    parser.add_argument("--scan-dir", default=".", help="Directory to scan")
    parser.add_argument("--output", default="mcp-results.sarif", help="Output SARIF file")
    args = parser.parse_args()

    scan_dir = os.path.abspath(args.scan_dir)
    allowlist = load_allowlist(scan_dir)
    mcp_files = find_mcp_files(scan_dir)

    all_findings = []
    for filepath in mcp_files:
        all_findings.extend(validate_mcp(filepath, scan_dir, allowlist))

    if not mcp_files:
        print("No mcp.json files found to validate")

    sarif = build_sarif(all_findings)

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(sarif, f, indent=2)

    error_count = sum(1 for f in all_findings if SEVERITY_MAP.get(f["ruleId"], ("warning",))[0] == "error")
    print(f"MCP validation complete: {len(all_findings)} findings ({error_count} errors)")

    sys.exit(1 if error_count > 0 else 0)


if __name__ == "__main__":
    main()
