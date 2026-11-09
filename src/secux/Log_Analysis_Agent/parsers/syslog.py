import re
import os
from datetime import datetime, timezone
from typing import Iterator, Optional
from .base import BaseParser, LogEntry


SYSLOG_REGEX = re.compile(
    r'^<(?P<priority>\d+)>?(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+(?P<tag>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$'
)

APACHE_COMMON_REGEX = re.compile(
    r'^(?P<host>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d+)\s+(?P<size>\S+)'
)

APACHE_COMBINED_REGEX = re.compile(
    r'^(?P<host>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d+)\s+(?P<size>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)"'
)


class SyslogParser(BaseParser):
    
    MONTH_MAP = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
        'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }
    
    def can_parse(self, filepath: str) -> bool:
        name = filepath.lower()
        return any(x in name for x in ['syslog', 'auth.log', 'secure', 'messages', 'kern.log'])
    
    def parse(self, filepath: str) -> Iterator[LogEntry]:
        if not os.path.exists(filepath):
            return
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    yield from self._parse_line(line.strip())
        except Exception:
            return
    
    def _parse_line(self, line: str) -> Iterator[LogEntry]:
        if not line or line.startswith('#'):
            return
        
        match = SYSLOG_REGEX.match(line)
        if match:
            yield from self._parse_syslog_entry(match, line)
        
        elif APACHE_COMBINED_REGEX.match(line) or APACHE_COMMON_REGEX.match(line):
            yield from self._parse_apache_entry(line)
    
    def _parse_syslog_entry(self, match, raw: str) -> Iterator[LogEntry]:
        groups = match.groupdict()
        
        try:
            month = self.MONTH_MAP.get(groups['timestamp'].split()[0], 1)
            day = int(groups['timestamp'].split()[1])
            time_parts = groups['timestamp'].split()[2]
            hour, minute, second = map(int, time_parts.split(':'))
            
            timestamp = datetime(datetime.now().year, month, day, hour, minute, second)
        except Exception:
            timestamp = datetime.now(timezone.utc)

        message = groups['message']
        tag = groups['tag']
        
        event_type, level = self._classify_message(tag, message)
        source_ip = self._extract_ip(message)
        target_user = self._extract_user(message)
        
        yield LogEntry(
            timestamp=timestamp,
            source=groups['hostname'],
            event_type=event_type,
            level=level,
            message=message,
            raw=raw,
            source_ip=source_ip,
            target_user=target_user,
            action=tag,
            status=self._extract_status(message),
            process_id=int(groups['pid']) if groups['pid'] else None
        )
    
    def _parse_apache_entry(self, line: str) -> Iterator[LogEntry]:
        match = APACHE_COMBINED_REGEX.match(line)
        if not match:
            match = APACHE_COMMON_REGEX.match(line)
        if not match:
            return
        
        groups = match.groupdict()
        
        try:
            timestamp = datetime.strptime(groups['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
        except Exception:
            timestamp = datetime.now(timezone.utc)
        
        status = int(groups['status'])
        level = "Information"
        if status >= 500:
            level = "Error"
        elif status >= 400:
            level = "Warning"
        
        yield LogEntry(
            timestamp=timestamp,
            source=groups['host'],
            event_type="http_request",
            level=level,
            message=f"{groups['method']} {groups['path']} -> {status}",
            raw=line,
            source_ip=groups['host'],
            target_user=groups['user'] if groups['user'] != '-' else None,
            action=f"{groups['method']} {groups['path']}",
            status="success" if status < 400 else "failed",
            metadata={
                "status": status,
                "size": groups['size'],
                "referer": groups.get('referer', ''),
                "user_agent": groups.get('agent', '')
            }
        )
    
    def _classify_message(self, tag: str, message: str) -> tuple:
        msg_lower = message.lower()
        tag_lower = tag.lower()
        
        if any(x in msg_lower for x in ['failed password', 'authentication failure', 'invalid user', 'failed login']):
            return ("login_failure", "Warning")
        if any(x in msg_lower for x in ['accepted password', 'session opened', 'login successful']):
            return ("login_success", "Information")
        if any(x in msg_lower for x in ['disconnected', 'session closed', 'logged out']):
            return ("logout", "Information")
        if any(x in msg_lower for x in ['error', 'failed', 'critical']):
            return ("error", "Error")
        if 'sudo' in tag_lower or 'sudo' in msg_lower:
            return ("privilege_escalation", "Warning")
        if 'sshd' in tag_lower:
            if 'opened' in msg_lower:
                return ("ssh_session", "Information")
            if 'closed' in msg_lower:
                return ("ssh_session_close", "Information")
        
        return ("generic", "Information")
    
    def _extract_ip(self, message: str) -> Optional[str]:
        patterns = [
            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
            r'from\s+(\S+@\S+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                ip = match.group(1) if '.' in match.group(1) else None
                if ip and ip != '0.0.0.0':
                    return ip
        return None
    
    def _extract_user(self, message: str) -> Optional[str]:
        match = re.search(r'(?:user|for)\s+(\S+)', message, re.IGNORECASE)
        if match:
            user = match.group(1)
            if user not in ['unknown', 'invalid']:
                return user
        return None
    
    def _extract_status(self, message: str) -> Optional[str]:
        if any(x in message.lower() for x in ['success', 'accepted', 'opened']):
            return 'success'
        if any(x in message.lower() for x in ['failed', 'error', 'denied', 'refused']):
            return 'failed'
        return None
