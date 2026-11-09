import subprocess
import platform
import socket
from typing import List

class DataCollector:
    """
    Collects real-time system data for AI security analysis.
    """
    
    def __init__(self):
        self.os = platform.system().lower()
        self.is_windows = self.os == "windows"

    def get_network_context(self) -> str:
        """Collects active network connections and listening ports."""
        try:
            if self.is_windows:
                # Get listening ports and active connections
                cmd = "netstat -ano"
                result = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
                # Filter for LISTENING or ESTABLISHED to keep it concise
                lines = [line.strip() for line in result.split("\n") if "LISTENING" in line or "ESTABLISHED" in line]
                return "\n".join(lines[:50]) # Limit to top 50 for context window
            else:
                return None
        except Exception as e:
            return f"Error collecting network data: {str(e)}"

    def get_vulnerability_context(self) -> str:
        """Collects system configuration and running processes."""
        try:
            context = []
            context.append(f"OS: {platform.platform()}")
            context.append(f"Architecture: {platform.machine()}")
            
            if self.is_windows:
                # Add running processes (top 30 by name)
                cmd = "tasklist /NH /FO CSV"
                result = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
                processes = [line.split(",")[0].strip('"') for line in result.split("\n") if line.strip()]
                unique_procs = sorted(list(set(processes)))
                context.append(f"Running Processes: {', '.join(unique_procs[:40])}")
                
                # Add some system info about patches
                cmd = "systeminfo"
                # This can be slow, maybe just get OS version info
                context.append(f"Node: {socket.gethostname()}")
            
            return "\n".join(context)
        except Exception as e:
            return f"Error collecting vulnerability data: {str(e)}"

    def get_auth_context(self, log_findings: list) -> str:
        """Consolidates log findings into an authentication-focused context string."""
        # Match on known auth-related finding types (precise, not stringify-and-search)
        AUTH_TYPES = {
            'brute_force_attempt', 'login_failure', 'login_success',
            'off_hours_login', 'off_hours_activity', 'high_failure_ratio',
            'privilege_escalation', 'privilege_assign'
        }
        auth_related = [
            f for f in log_findings
            if isinstance(f, dict) and f.get('type', '') in AUTH_TYPES
        ]

        if not auth_related:
            # Fallback: look for auth keywords in description or message fields only
            auth_related = [
                f for f in log_findings
                if isinstance(f, dict) and any(
                    kw in (f.get('description', '') + f.get('type', '')).lower()
                    for kw in ('login', 'auth', 'password', 'credential', 'privilege')
                )
            ]

        if not auth_related:
            return f"No authentication anomalies detected. Total findings analyzed: {len(log_findings)}"

        lines = []
        for f in auth_related[:20]:
            desc = f.get('description') or f.get('type', str(f))
            ev = f.get('evidence', {})
            sev = f.get('severity', '?')
            lines.append(
                f"[{sev}] {desc} "
                f"(IP={ev.get('source_ip', 'N/A')}, user={ev.get('target_user', 'N/A')})"
            )
        return "\n".join(lines)
