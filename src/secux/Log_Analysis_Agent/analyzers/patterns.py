import re
from typing import List, Dict, Pattern


KNOWN_ATTACK_PATTERNS: List[Dict] = [
    {
        "name": "SQL Injection Attempt",
        "pattern": r"(union\s+select|select\s+\*\s+from|'?\s+or\s+'1'='1|exec\s*\(|xp_cmdshell)",
        "type": "sql_injection",
        "severity": "HIGH",
        "confidence": 0.85
    },
    {
        "name": "XSS Attempt",
        "pattern": r"(<script|javascript:|onerror\s*=|<iframe|<svg|alert\s*\()",
        "type": "xss",
        "severity": "MEDIUM",
        "confidence": 0.70
    },
    {
        "name": "Path Traversal Attempt",
        "pattern": r"(\.\./|\.\.\\|%2e%2e|%5c|../../etc/passwd)",
        "type": "path_traversal",
        "severity": "HIGH",
        "confidence": 0.80
    },
    {
        "name": "Command Injection Attempt",
        "pattern": r"(;\s*cat\s+|;\s*ls\s+|;\s*wget\s+|;\s*curl\s+|\|\s*ncat\s+|&\s*nc\s+)",
        "type": "command_injection",
        "severity": "CRITICAL",
        "confidence": 0.90
    },
    {
        "name": "SSH Brute Force",
        "pattern": r"(sshd.*Failed|sshd.*Invalid)",
        "type": "brute_force",
        "severity": "HIGH",
        "confidence": 0.85
    },
    {
        "name": "HTTP Flood",
        "pattern": r"(GET\s+/\s+HTTP|POST\s+/\s+HTTP)",
        "type": "dos",
        "severity": "MEDIUM",
        "confidence": 0.60
    },
    {
        "name": "Directory Enumeration",
        "pattern": r"(/\.git/|/\.env|/\.htaccess|/admin|/wp-login|phpmyadmin)",
        "type": "reconnaissance",
        "severity": "LOW",
        "confidence": 0.65
    },
    {
        "name": "Authentication Bypass Attempt",
        "pattern": r"(Basic\s+Auth|NTLM|Bearer|Authorization:\s*\w+)",
        "type": "auth_bypass",
        "severity": "MEDIUM",
        "confidence": 0.55
    },
    {
        "name": "PowerShell Execution",
        "pattern": r"(powershell|powershell\.exe|pwsh|Invoke-Expression|iex\s)",
        "type": "malicious_execution",
        "severity": "HIGH",
        "confidence": 0.80
    },
    {
        "name": "Suspicious User Agent",
        "pattern": r"(sqlmap|nmap|masscan|nikto|burp|sqlninja|sqli)",
        "type": "scanning",
        "severity": "MEDIUM",
        "confidence": 0.75
    }
]


class PatternMatcher:
    
    def __init__(self):
        self.patterns: List[Dict] = []
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        for attack in KNOWN_ATTACK_PATTERNS:
            self.patterns.append({
                **attack,
                "compiled": re.compile(attack["pattern"], re.IGNORECASE)
            })
    
    def match(self, text: str) -> List[Dict]:
        matches = []
        
        for pattern in self.patterns:
            if pattern["compiled"].search(text):
                matches.append({
                    "name": pattern["name"],
                    "type": pattern["type"],
                    "severity": pattern["severity"],
                    "confidence": pattern["confidence"],
                    "matched_text": pattern["compiled"].search(text).group(0)
                })
        
        return matches
