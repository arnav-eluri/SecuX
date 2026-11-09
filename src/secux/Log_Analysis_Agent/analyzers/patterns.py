import re
from typing import List, Dict, Pattern


KNOWN_ATTACK_PATTERNS: List[Dict] = [
    # ── Web attacks ───────────────────────────────────────────────────────────
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
        "pattern": r"(Basic\s+Auth\s+bypass|ntlm\s+relay|pass.the.hash|auth.*bypass)",
        "type": "auth_bypass",
        "severity": "MEDIUM",
        "confidence": 0.55
    },
    {
        "name": "Suspicious User Agent",
        "pattern": r"(sqlmap|nmap|masscan|nikto|burp|sqlninja|sqli)",
        "type": "scanning",
        "severity": "MEDIUM",
        "confidence": 0.75
    },
    # ── SSH brute force ───────────────────────────────────────────────────────
    # Specific to 'Failed password' and 'Invalid user' — avoids matching
    # POSSIBLE BREAK-IN lines (which carry 'failed' in a different context)
    {
        "name": "SSH Brute Force",
        "pattern": r"sshd.*Failed\s+password|sshd.*Invalid\s+user",
        "type": "brute_force_attempt",
        "severity": "HIGH",
        "confidence": 0.85
    },
    {
        "name": "SSH PAM Authentication Failure",
        "pattern": r"pam_unix\(sshd:auth\).*authentication failure|sshd.*pam.*authentication failure",
        "type": "brute_force_attempt",
        "severity": "HIGH",
        "confidence": 0.80
    },
    # ── Reconnaissance ────────────────────────────────────────────────────────
    {
        "name": "SSH Reverse DNS Probe",
        "pattern": r"POSSIBLE BREAK-IN ATTEMPT|Did not receive identification string",
        "type": "reconnaissance",
        "severity": "MEDIUM",
        "confidence": 0.75
    },
    # ── Privilege escalation ──────────────────────────────────────────────────
    # lsass.exe access — any process reading LSASS memory is suspicious
    {
        "name": "LSASS Memory Access",
        "pattern": r"\blsass\.exe\b",
        "type": "privilege_escalation",
        "severity": "CRITICAL",
        "confidence": 0.95
    },
    # SeDebugPrivilege is required for LSASS credential dumping
    {
        "name": "Debug Privilege Granted",
        "pattern": r"SeDebugPrivilege",
        "type": "privilege_escalation",
        "severity": "CRITICAL",
        "confidence": 0.90
    },
    # EventID 4648 = explicit credential use (pass-the-hash, lateral movement)
    {
        "name": "Explicit Credential Use",
        "pattern": r'"EventID".*"4648"|EventID.*4648.*explicit|4648.*TargetUserName',
        "type": "privilege_escalation",
        "severity": "HIGH",
        "confidence": 0.85
    },
    # ── Malicious execution ───────────────────────────────────────────────────
    {
        "name": "PowerShell Execution",
        "pattern": r"powershell|powershell\.exe|pwsh|Invoke-Expression|iex\s",
        "type": "malicious_execution",
        "severity": "HIGH",
        "confidence": 0.80
    },
    # Encoded powershell (-enc / -encodedcommand) — classic stager/obfuscation
    {
        "name": "Encoded PowerShell Command",
        "pattern": r"-[Ee]nc[oO]dedCommand|-[Ee]nc\s+[A-Za-z0-9+/=]{10}|nop.*bypass.*encod|exec\s+bypass",
        "type": "malicious_execution",
        "severity": "CRITICAL",
        "confidence": 0.92
    },
    # ROT13-encoded "WindowsPowerShell" / "powershell.exe" in UserAssist registry key
    # JvaqbjfCbjreFuryy = WindowsPowerShell, cbjrefuryy.rkr = powershell.exe
    {
        "name": "ROT13 PowerShell UserAssist Entry",
        "pattern": r"JvaqbjfCbjreFuryy|cbjrefuryy\.rkr",
        "type": "malicious_execution",
        "severity": "HIGH",
        "confidence": 0.90
    },
    # ── Service modification ──────────────────────────────────────────────────
    # Windows service registry key access — HKLM\...\Services\<ServiceName>
    {
        "name": "Windows Service Registry Access",
        "pattern": r"\\\\Services\\\\[A-Za-z]|REGISTRY.*\\Services\\[A-Za-z]|ControlSet.*\\Services\\[A-Za-z]",
        "type": "service_modification",
        "severity": "HIGH",
        "confidence": 0.80
    },
    # sc.exe creating or reconfiguring a service
    {
        "name": "Service Creation via sc.exe",
        "pattern": r'\bsc\b.*(create|config|failure)\s+\w|sc\.exe.*(create|config)',
        "type": "service_modification",
        "severity": "CRITICAL",
        "confidence": 0.90
    },
    # Service binary path pointing to cmd.exe or powershell — classic persistence
    {
        "name": "Malicious Service Binary Path",
        "pattern": r"binpath\s*=\s*(cmd|powershell)|ImagePath.*cmd\.exe|ImagePath.*powershell",
        "type": "service_modification",
        "severity": "CRITICAL",
        "confidence": 0.95
    },
    # cmd.exe / powershell configured as a service binary = active malicious execution
    {
        "name": "Service Binary Malicious Execution",
        "pattern": r"binpath\s*=\s*(cmd\.exe|cmd\s|powershell)|ImagePath.*(cmd\.exe|powershell\.exe)",
        "type": "malicious_execution",
        "severity": "CRITICAL",
        "confidence": 0.90
    },
    # ── UNSW-NB15 network flow records ───────────────────────────────────────
    # These entries carry attack_cat in the JSON payload; match on that field.
    {
        "name": "Network Flow Reconnaissance",
        "pattern": r'"attack_cat"\s*:\s*"Reconnaissance"|"attack_cat"\s*:\s*"Analysis"',
        "type": "reconnaissance",
        "severity": "MEDIUM",
        "confidence": 0.90
    },
    {
        "name": "Network Flow DoS",
        "pattern": r'"attack_cat"\s*:\s*"(DoS|Generic|Fuzzers)"',
        "type": "dos",
        "severity": "HIGH",
        "confidence": 0.90
    },
    {
        "name": "Network Flow Exploit/Shellcode",
        "pattern": r'"attack_cat"\s*:\s*"(Exploits|Shellcode)"',
        "type": "malicious_execution",
        "severity": "CRITICAL",
        "confidence": 0.92
    },
    {
        "name": "Network Flow Backdoor/Worm",
        "pattern": r'"attack_cat"\s*:\s*"(Backdoors?|Worms?)"',
        "type": "malicious_process",
        "severity": "CRITICAL",
        "confidence": 0.92
    },
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
