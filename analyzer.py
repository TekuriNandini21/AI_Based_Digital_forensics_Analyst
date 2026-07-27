"""
analyzer.py
------------------------------------------------------------
Core Forensic Analysis Engine.

Parses uploaded evidence files (CSV / JSON / TXT log formats)
and applies a library of rule-based detectors to flag
suspicious activity commonly seen in:

    * Windows Event Logs
    * Linux auth.log
    * SSH logs
    * Apache / Nginx access logs
    * Firewall logs
    * Browser history exports
    * File metadata listings
    * Generic network logs

Everything here is pattern/heuristic based (regex + simple
statistics) -- there is no exploitation, offensive tooling,
or attack code. The goal is purely detective: read evidence,
flag anomalies, and produce a structured incident list that
can be scored, timelined and reported on.
------------------------------------------------------------
"""

import re
import io
import json
import csv
from collections import defaultdict, Counter
from datetime import datetime


# ----------------------------------------------------------------
# Regex patterns used across detectors
# ----------------------------------------------------------------

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

FAILED_LOGIN_PATTERNS = [
    r"failed password",
    r"authentication failure",
    r"login failed",
    r"invalid user",
    r"failed login",
    r"logon failure",
]

SUCCESS_LOGIN_PATTERNS = [
    r"accepted password",
    r"accepted publickey",
    r"logon success",
    r"successful login",
    r"session opened",
]

PRIV_ESC_PATTERNS = [
    r"\bsudo\b", r"\bsu \b", r"COMMAND=.*", r"privilege escalation",
    r"runas", r"administrator group", r"added to group.*admin",
]

USER_CREATION_PATTERNS = [
    r"useradd", r"new user account", r"user account created",
    r"net user .* /add", r"adduser",
]

SUSPICIOUS_COMMAND_PATTERNS = [
    r"powershell -enc", r"-encodedcommand", r"invoke-expression", r"iex\(",
    r"downloadstring", r"certutil -urlcache", r"mimikatz", r"wget http",
    r"curl http.*\|.*sh", r"base64 -d", r"nc -e", r"/bin/bash -i",
]

DELETED_FILE_PATTERNS = [r"file deleted", r"deleted file", r"rm -rf", r"del /f"]
HIDDEN_FILE_PATTERNS = [r"\.hidden", r"attrib \+h", r"hidden file"]

MALWARE_EXT_PATTERNS = [
    r"\.exe$", r"\.scr$", r"\.bat$", r"\.vbs$", r"\.ps1$", r"\.dll$",
    r"\.jar$", r"\.js$", r"\.hta$", r"\.msi$",
]

REGISTRY_PATTERNS = [r"HKEY_", r"registry key", r"reg add", r"reg delete"]

USB_PATTERNS = [r"usbstor", r"usb device", r"removable storage", r"volume mounted"]

RDP_PATTERNS = [r"remote desktop", r"rdp", r"logon type 10", r"terminal services"]

SSH_PATTERNS = [r"sshd", r"ssh2", r"ssh login"]

PORT_SCAN_PATTERNS = [r"port scan", r"nmap", r"syn scan", r"multiple ports"]

DNS_TUNNEL_PATTERNS = [r"dns tunnel", r"txt record.*base64", r"unusual dns query length"]

LARGE_TRANSFER_PATTERNS = [r"large file transfer", r"bytes_sent=\d{8,}", r"exfiltration"]

NETWORK_SCAN_PATTERNS = [r"network scan", r"host discovery", r"ping sweep"]

UNKNOWN_PROCESS_PATTERNS = [r"unknown process", r"unsigned binary", r"unrecognized executable"]


SEVERITY_MAP = {
    "Brute Force Attack": "Critical",
    "Successful Login After Multiple Failures": "Critical",
    "Privilege Escalation": "Critical",
    "Malware Indicator": "Critical",
    "Suspicious Command Execution": "Critical",
    "DNS Tunneling Indicator": "High",
    "Unauthorized User Creation": "High",
    "PowerShell Abuse": "High",
    "Port Scanning": "High",
    "Network Scanning": "High",
    "Large File Transfer": "High",
    "Registry Modification": "Medium",
    "Deleted Files": "Medium",
    "Hidden Files": "Medium",
    "Unknown Process": "Medium",
    "Remote Desktop Login": "Medium",
    "USB Device Activity": "Low",
    "SSH Login Activity": "Low",
    "Failed Login Attempt": "Low",
    "Suspicious File Extension": "Medium",
    "Suspicious IP Address": "Medium",
}


def _matches_any(patterns, text):
    text_l = text.lower()
    return any(re.search(p, text_l) for p in patterns)


def _extract_ips(text):
    return IP_REGEX.findall(text)


def _extract_username(text):
    m = re.search(r"user[= ]+([a-zA-Z0-9_\-\.]+)", text, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"for ([a-zA-Z0-9_\-\.]+) from", text, re.IGNORECASE)
    if m:
        return m.group(1)
    return None


def _extract_timestamp(text):
    """
    Attempts to extract a timestamp using several common log formats.
    Falls back to current time if nothing matches, so every incident
    remains sortable on a timeline.
    """
    patterns = [
        r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}",
        r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}",
        r"[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}",
    ]
    for p in patterns:
        m = re.search(p, text)
        if m:
            return m.group(0)
    return datetime.utcnow().isoformat()


def _load_lines_from_txt(content):
    return [line.strip() for line in content.splitlines() if line.strip()]


def _load_rows_from_csv(content):
    reader = csv.DictReader(io.StringIO(content))
    return [row for row in reader]


def _load_rows_from_json(content):
    data = json.loads(content)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # Try common wrapper keys, otherwise treat dict as a single row
        for key in ("events", "logs", "records", "data"):
            if key in data and isinstance(data[key], list):
                return data[key]
        return [data]
    return []


def parse_evidence_file(filename, content):
    """
    Loads an evidence file (already read as text) into a list of
    "log lines" (strings) that detectors can scan. CSV/JSON rows
    are flattened into a single descriptive string per row so the
    same regex-based detectors work uniformly across formats.
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "txt"

    if ext == "txt" or ext == "log":
        return _load_lines_from_txt(content)

    if ext == "csv":
        rows = _load_rows_from_csv(content)
        return [" ".join(f"{k}={v}" for k, v in row.items()) for row in rows]

    if ext == "json":
        rows = _load_rows_from_json(content)
        flat_lines = []
        for row in rows:
            if isinstance(row, dict):
                flat_lines.append(" ".join(f"{k}={v}" for k, v in row.items()))
            else:
                flat_lines.append(str(row))
        return flat_lines

    # Unknown extension - fall back to treating it as plain text
    return _load_lines_from_txt(content)


def _make_incident(category, line, extra_source_ip=None):
    ips = _extract_ips(line)
    source_ip = extra_source_ip or (ips[0] if ips else None)
    destination_ip = ips[1] if len(ips) > 1 else None
    return {
        "timestamp": _extract_timestamp(line),
        "category": category,
        "severity": SEVERITY_MAP.get(category, "Low"),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "username": _extract_username(line),
        "description": f"{category} detected in evidence log line.",
        "raw_line": line[:500],
    }


def analyze_lines(lines):
    """
    Runs the full detector library over a list of log lines and
    returns a structured list of incident dicts, plus summary
    statistics (suspicious users/hosts, top attackers, etc.).
    """
    incidents = []

    # Track failed logins per (user, ip) to detect brute force /
    # "success after failures" patterns.
    failed_attempts = defaultdict(list)  # key -> list of line indices
    ip_failed_counter = Counter()

    for idx, line in enumerate(lines):
        line_l = line.lower()

        if _matches_any(FAILED_LOGIN_PATTERNS, line_l):
            incidents.append(_make_incident("Failed Login Attempt", line))
            ips = _extract_ips(line)
            user = _extract_username(line) or "unknown"
            key = (user, ips[0] if ips else "unknown")
            failed_attempts[key].append(idx)
            if ips:
                ip_failed_counter[ips[0]] += 1

        if _matches_any(SUCCESS_LOGIN_PATTERNS, line_l):
            ips = _extract_ips(line)
            user = _extract_username(line) or "unknown"
            key = (user, ips[0] if ips else "unknown")
            if len(failed_attempts.get(key, [])) >= 3:
                incidents.append(_make_incident(
                    "Successful Login After Multiple Failures", line))

        if _matches_any(PRIV_ESC_PATTERNS, line_l):
            incidents.append(_make_incident("Privilege Escalation", line))

        if _matches_any(USER_CREATION_PATTERNS, line_l):
            incidents.append(_make_incident("Unauthorized User Creation", line))

        if _matches_any(SUSPICIOUS_COMMAND_PATTERNS, line_l):
            if "powershell" in line_l:
                incidents.append(_make_incident("PowerShell Abuse", line))
            else:
                incidents.append(_make_incident("Suspicious Command Execution", line))

        if _matches_any(DELETED_FILE_PATTERNS, line_l):
            incidents.append(_make_incident("Deleted Files", line))

        if _matches_any(HIDDEN_FILE_PATTERNS, line_l):
            incidents.append(_make_incident("Hidden Files", line))

        if _matches_any(MALWARE_EXT_PATTERNS, line_l):
            incidents.append(_make_incident("Suspicious File Extension", line))

        if _matches_any(REGISTRY_PATTERNS, line_l):
            incidents.append(_make_incident("Registry Modification", line))

        if _matches_any(USB_PATTERNS, line_l):
            incidents.append(_make_incident("USB Device Activity", line))

        if _matches_any(RDP_PATTERNS, line_l):
            incidents.append(_make_incident("Remote Desktop Login", line))

        if _matches_any(SSH_PATTERNS, line_l):
            incidents.append(_make_incident("SSH Login Activity", line))

        if _matches_any(PORT_SCAN_PATTERNS, line_l):
            incidents.append(_make_incident("Port Scanning", line))

        if _matches_any(NETWORK_SCAN_PATTERNS, line_l):
            incidents.append(_make_incident("Network Scanning", line))

        if _matches_any(DNS_TUNNEL_PATTERNS, line_l):
            incidents.append(_make_incident("DNS Tunneling Indicator", line))

        if _matches_any(LARGE_TRANSFER_PATTERNS, line_l):
            incidents.append(_make_incident("Large File Transfer", line))

        if _matches_any(UNKNOWN_PROCESS_PATTERNS, line_l):
            incidents.append(_make_incident("Unknown Process", line))

    # Brute force detection: 5+ failed attempts from same key
    for key, occurrences in failed_attempts.items():
        if len(occurrences) >= 5:
            user, ip = key
            incidents.append({
                "timestamp": _extract_timestamp(lines[occurrences[-1]]),
                "category": "Brute Force Attack",
                "severity": SEVERITY_MAP["Brute Force Attack"],
                "source_ip": ip if ip != "unknown" else None,
                "destination_ip": None,
                "username": user if user != "unknown" else None,
                "description": (
                    f"{len(occurrences)} failed login attempts detected for "
                    f"user '{user}' from IP '{ip}' -- indicates a brute force attack."
                ),
                "raw_line": lines[occurrences[-1]][:500],
            })

    # Suspicious IP addresses: any IP responsible for many failed logins
    for ip, count in ip_failed_counter.items():
        if count >= 8:
            incidents.append({
                "timestamp": datetime.utcnow().isoformat(),
                "category": "Suspicious IP Address",
                "severity": SEVERITY_MAP["Suspicious IP Address"],
                "source_ip": ip,
                "destination_ip": None,
                "username": None,
                "description": f"IP address {ip} generated {count} failed login events.",
                "raw_line": "",
            })

    return incidents


def build_summary(incidents):
    """
    Builds the evidence-level summary statistics used by the
    dashboard, report generator, and AI prompt builder.
    """
    severity_counts = Counter(i["severity"] for i in incidents)
    category_counts = Counter(i["category"] for i in incidents)
    suspicious_users = Counter(i["username"] for i in incidents if i.get("username"))
    suspicious_hosts = Counter(i["source_ip"] for i in incidents if i.get("source_ip"))

    timeline = sorted(
        [i for i in incidents if i.get("timestamp")],
        key=lambda x: x["timestamp"]
    )

    return {
        "total_incidents": len(incidents),
        "severity_counts": dict(severity_counts),
        "category_counts": dict(category_counts),
        "suspicious_users": suspicious_users.most_common(10),
        "suspicious_hosts": suspicious_hosts.most_common(10),
        "top_attack_sources": suspicious_hosts.most_common(5),
        "timeline": timeline,
    }


def calculate_risk_score(summary):
    """
    Produces a 0-100 AI-style risk score from the severity mix.
    Weighted so that Critical incidents dominate the score while
    still accounting for volume of lower-severity findings.
    """
    weights = {"Critical": 10, "High": 6, "Medium": 3, "Low": 1}
    sev_counts = summary["severity_counts"]

    raw_score = sum(weights.get(sev, 1) * count for sev, count in sev_counts.items())
    # Normalize with a soft cap so scores don't blow past 100 on huge logs
    score = min(100, int(raw_score))

    if score <= 20:
        level = "Safe"
    elif score <= 40:
        level = "Low"
    elif score <= 60:
        level = "Medium"
    elif score <= 80:
        level = "High"
    else:
        level = "Critical"

    return score, level


def analyze_evidence_file(filename, content):
    """
    High-level convenience function: parse a raw file's content,
    run all detectors, and return (incidents, summary, risk_score,
    risk_level) in one call. This is the main entry point used by
    app.py.
    """
    lines = parse_evidence_file(filename, content)
    incidents = analyze_lines(lines)
    summary = build_summary(incidents)
    risk_score, risk_level = calculate_risk_score(summary)
    return {
        "lines_parsed": len(lines),
        "incidents": incidents,
        "summary": summary,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }
