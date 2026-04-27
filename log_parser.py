"""
log_parser.py — Parses uploaded log files and stores flagged entries in the database.
Supports: .txt, .log, .csv, .json log formats.
"""

import re
import json
from datetime import datetime
from database import insert_log_entries

# Keywords that flag a log line as suspicious
THREAT_KEYWORDS = {
    "CRITICAL": ["attack", "intrusion", "exploit", "malware", "ransomware",
                 "backdoor", "rootkit", "payload", "shellcode"],
    "HIGH":     ["failed login", "authentication failure", "brute force",
                 "unauthorized", "permission denied", "access denied",
                 "sql injection", "xss", "traversal", "suspicious"],
    "MEDIUM":   ["error", "warning", "failed", "timeout", "refused",
                 "blocked", "denied", "invalid"],
    "LOW":      ["disconnect", "retry", "slow", "unusual"],
}


def classify_line(line: str):
    """Return (level, flag_reason) for a log line."""
    line_lower = line.lower()
    for level, keywords in THREAT_KEYWORDS.items():
        for kw in keywords:
            if kw in line_lower:
                return level, kw
    return "INFO", ""


def extract_timestamp(line: str) -> str:
    """Try to extract a timestamp from the log line, else use now."""
    patterns = [
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}",
        r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}",
        r"\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}",
    ]
    for p in patterns:
        m = re.search(p, line)
        if m:
            return m.group(0)
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_log_text(text: str, source_file: str = "uploaded") -> list:
    """
    Parse raw log text into structured entries.
    Returns list of dicts ready for insert_log_entries().
    """
    lines   = text.strip().splitlines()
    entries = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        level, flag_reason = classify_line(line)
        flagged = 1 if level in ("CRITICAL", "HIGH", "MEDIUM") else 0

        entries.append({
            "timestamp":   extract_timestamp(line),
            "source_file": source_file,
            "level":       level,
            "message":     line[:500],  # cap at 500 chars
            "flagged":     flagged,
            "flag_reason": flag_reason,
        })

    return entries


def parse_and_store(text: str, source_file: str = "uploaded") -> dict:
    """Parse log text, save to DB, return summary."""
    entries  = parse_log_text(text, source_file)
    if entries:
        insert_log_entries(entries)

    flagged  = [e for e in entries if e["flagged"]]
    critical = [e for e in flagged if e["level"] == "CRITICAL"]
    high     = [e for e in flagged if e["level"] == "HIGH"]

    return {
        "total_lines": len(entries),
        "flagged":     len(flagged),
        "critical":    len(critical),
        "high":        len(high),
        "entries":     entries[:100],  # return first 100 for display
    }
