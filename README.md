Palo Alto Firewall Rules Merger
A production-grade Python tool that intelligently merges millions of Palo Alto firewall security rules into a optimized set of rules — while preserving zone integrity, excluding public source IPs, and maintaining a full audit trail.
Built and deployed in a live enterprise environment protecting 10,000+ endpoints.

The Problem
When a Palo Alto firewall has been running for months or years, it accumulates millions of traffic log entries and thousands of redundant security rules. Managing, reviewing, or migrating these rules manually is:

Time-consuming and error-prone
Nearly impossible at scale
A serious risk during firewall migrations or audits

The Solution
This tool automates the entire rule optimization process — from raw Palo Alto rule files to clean, validated, deployment-ready configuration — in minutes.

Features

Parses millions of Palo Alto CLI security rules using memory-efficient streaming
Groups rules intelligently by shared zones, actions, applications, and services
Merges thousands of redundant rules into a target number of optimized rules (default: 30)
Automatically detects and excludes real (public) source IP addresses for security
Skips disabled rules automatically
Produces 3 output files: merged config, excluded IPs log, and full audit mapping
Handles files of any size without loading everything into memory


How It Works
Input: Palo Alto rules file (.txt)
        │
        ▼
[1] Parse all rules line by line (streaming)
        │
        ▼
[2] Group rules by signature
    (same zones + action + applications + services)
        │
        ▼
[3] Merge each group into one optimized rule
    - Combine all source/destination IPs
    - Remove public source IPs
    - Preserve zone information
        │
        ▼
[4] Generate 3 output files
    - Merged config (ready to deploy)
    - Excluded real IPs (audit log)
    - Rule mapping (full audit trail)

Requirements

Python 3.7+
No external libraries required — uses standard library only


Installation
bashgit clone https://github.com/Youssef-Fathelbab/paloalto-firewall-automation.git
cd paloalto-firewall-automation

Usage
bashpython merging.py
You will be prompted for:
Enter path to your Palo Alto rules file: your_rules.txt
Enter target number of merged rules (default 30): 30

Input Format
The tool expects a Palo Alto CLI configuration file with rules in this format:
set rulebase security rules "RuleName" from Trust to Untrust source 10.0.0.1 destination any application ssl service application-default action allow log-end yes

Output Files
After running, the tool generates 3 files automatically:
FileDescription*_merged_config.txtFinal optimized rules ready to deploy on Palo Alto*_excluded_real_ips.txtAll public source IPs that were removed for security*_merge_mapping.txtFull audit trail — which original rules went into each merged rule
Example Output
[1/6] Parsing rules from rules.txt...
      Found 125,430 unique rules

[2/6] Grouping rules by similarity...
      Created 847 signature groups

[3/6] Merging rules into 30 groups...
      Merged-Rule-1: Merged 42,300 rules
      Merged-Rule-2: Merged 28,150 rules
      ...

[4/6] Total merged rules: 30
[5/6] Real source IPs excluded: 1,247
[6/6] Generating output files...

Original rules processed:  125,430
Merged rules created:      30
Real source IPs excluded:  1,247

Public IP Filtering
The tool automatically identifies and removes real (public) source IP addresses from merged rules. This prevents accidentally allowing external internet traffic through your internal security policies.
Private IP ranges that are kept:

10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
Loopback, reserved, and multicast ranges

Public IPs are logged to *_excluded_real_ips.txt for review.

Rule Merging Logic
Rules are grouped by their signature — a combination of:

Source zones
Destination zones
Action (allow/deny)
Applications
Services

Rules sharing the same signature are safe to merge — their source and destination IPs are combined into a single optimized rule without changing the security behavior.

Production Use
This tool was built and used in a live production environment at an enterprise MSSP, processing firewall logs from a network protecting 10,000+ endpoints for a confidential large-scale client.

Related Tools
This script is part of a larger Palo Alto automation toolkit:
ScriptPurposecsvconfig.pyParse traffic logs and auto-generate firewall rulesmerging.pyMerge millions of rules into optimized set (this tool)check.pyValidate no rules were lost during merging

Author
Youssef Walid Fathelbab
OSCP-Certified Cybersecurity & Network Engineer
LinkedIn

License
MIT License — free to use, modify, and distribute with attribution.
