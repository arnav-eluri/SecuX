import re
import os
from datetime import datetime
from typing import Iterator, Optional
from .base import BaseParser, LogEntry


class SimpleTextParser(BaseParser):
    """
    Parser for simple technical logs in the format:
    YYYY-MM-DD HH:MM:SS LEVEL Message [user=...] [ip=...]
    """

    # Regex to extract timestamp, level, and the rest of the message
    LOG_REGEX = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<level>INFO|WARN|ERROR|DEBUG|CRITICAL)\s+(?P<message>.*)$'
    )

    def can_parse(self, filepath: str) -> bool:
        # Fallback parser for any .log or .txt file if others fail
        return filepath.lower().endswith(('.log', '.txt'))

    def parse(self, filepath: str) -> Iterator[LogEntry]:
        if not os.path.exists(filepath):
            return

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    match = self.LOG_REGEX.match(line)
                    if match:
                        groups = match.groupdict()
                        try:
                            timestamp = datetime.strptime(groups['timestamp'], '%Y-%m-%d %H:%M:%S')
                        except Exception:
                            timestamp = datetime.utcnow()

                        msg = groups['message']
                        level = groups['level']

                        # Extract metadata — use precise patterns to avoid false matches
                        source_ip = self._extract_ip(msg)
                        target_user = self._extract_value(msg, 'user')

                        # ─── Event Classification ────────────────────────────
                        msg_lower = msg.lower()
                        event_type = "generic"

                        if "failed login" in msg_lower or "login failure" in msg_lower or (
                            "failed" in msg_lower and "login" in msg_lower
                        ):
                            event_type = "login_failure"
                            level = "Warning"

                        elif "login successful" in msg_lower or "accepted password" in msg_lower or (
                            "login" in msg_lower and "successful" in msg_lower
                        ):
                            event_type = "login_success"

                        elif "user role changed" in msg_lower or (
                            "role" in msg_lower and ("changed" in msg_lower or "->" in msg)
                        ):
                            # e.g. "User role changed user=arnav role=user -> admin"
                            event_type = "privilege_escalation"
                            level = "Warning"

                        elif "sudo" in msg_lower:
                            event_type = "privilege_escalation"
                            level = "Warning"

                        elif "privilege" in msg_lower:
                            event_type = "privilege_escalation"
                            level = "Warning"

                        elif "suspicious process" in msg_lower or (
                            "process started" in msg_lower
                        ):
                            event_type = "suspicious_process"
                            level = "Warning"

                        elif "outbound connection" in msg_lower:
                            event_type = "suspicious_connection"
                            level = "Warning"

                        elif "file transfer" in msg_lower or "exfil" in msg_lower or (
                            "transfer initiated" in msg_lower
                        ):
                            event_type = "data_exfiltration"
                            level = "Warning"

                        elif "api request" in msg_lower or "endpoint=" in msg_lower:
                            event_type = "api_request"

                        elif "connection attempt" in msg_lower:
                            event_type = "network_connection"

                        # ── Normalise level casing for downstream analyzers ──
                        if level.upper() == 'WARN':
                            level = 'Warning'
                        elif level.upper() == 'ERROR':
                            level = 'Error'
                        elif level.upper() == 'INFO':
                            level = 'Information'
                        elif level.upper() == 'DEBUG':
                            level = 'Debug'
                        elif level.upper() == 'CRITICAL':
                            level = 'Critical'
                        else:
                            level = level.capitalize()

                        yield LogEntry(
                            timestamp=timestamp,
                            source=os.path.basename(filepath),
                            event_type=event_type,
                            level=level,
                            message=msg,
                            raw=line,
                            source_ip=source_ip,
                            target_user=target_user
                        )
                    else:
                        # Fallback for non-matching lines (treat as info)
                        yield LogEntry(
                            timestamp=datetime.utcnow(),
                            source=os.path.basename(filepath),
                            event_type="unknown",
                            level="Information",
                            message=line[:200],
                            raw=line
                        )
        except Exception:
            return

    def _extract_ip(self, message: str) -> Optional[str]:
        """
        Extract a plain IP address from key=value pairs.
        Handles: ip=1.2.3.4 but NOT external_ip=... (which is not the source IP).
        """
        # Only match 'ip=' that is preceded by a word boundary or space, not 'external_ip='
        match = re.search(r'(?<![_a-zA-Z])ip=([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})', message, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def _extract_value(self, message: str, key: str) -> Optional[str]:
        match = re.search(fr'(?<![_a-zA-Z]){key}=([^\s=,]+)', message, re.IGNORECASE)
        return match.group(1) if match else None
