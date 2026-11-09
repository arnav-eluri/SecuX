import os
import re
from datetime import datetime, timezone
from typing import Iterator, Optional
from .base import BaseParser, LogEntry


class IISParser(BaseParser):
    
    IIS_FIELDS = [
        'date', 'time', 's-ip', 'cs-method', 'cs-uri-stem', 'cs-uri-query',
        's-port', 'cs-username', 'c-ip', 'cs(User-Agent)', 'cs(Referer)', 'sc-status', 'sc-substatus', 'sc-win32-status', 'time-taken'
    ]
    
    def can_parse(self, filepath: str) -> bool:
        name = filepath.lower()
        return 'iis' in name or 'w3svc' in name or 'u_ex' in os.path.basename(name)
    
    def parse(self, filepath: str) -> Iterator[LogEntry]:
        if not os.path.exists(filepath):
            return
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                header_found = False
                for line in f:
                    line = line.strip()
                    
                    if line.startswith('#Software:'):
                        header_found = True
                        continue
                    
                    if line.startswith('#Fields:'):
                        fields_str = line.replace('#Fields:', '').strip()
                        self.IIS_FIELDS = fields_str.split()
                        header_found = True
                        continue
                    
                    if not header_found or line.startswith('#') or not line:
                        continue
                    
                    yield from self._parse_line(line)
        except Exception:
            return
    
    def _parse_line(self, line: str) -> Iterator[LogEntry]:
        try:
            parts = line.split()
            if len(parts) < 8:
                return
            
            data = dict(zip(self.IIS_FIELDS, parts))
            
            date_str = data.get('date', '')
            time_str = data.get('time', '')
            
            if date_str and time_str:
                try:
                    timestamp = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    timestamp = datetime.now(timezone.utc)
            else:
                timestamp = datetime.now(timezone.utc)
            
            status = int(data.get('sc-status', 0))
            substatus = int(data.get('sc-substatus', 0))
            
            level = "Information"
            event_type = "http_request"
            
            if status >= 500:
                level = "Error"
                event_type = "server_error"
            elif status >= 400:
                level = "Warning"
                if status == 401:
                    event_type = "auth_required"
                elif status == 403:
                    event_type = "forbidden"
                elif status == 404:
                    event_type = "not_found"
            
            message = f"{data.get('cs-method')} {data.get('cs-uri-stem')} -> {status}"
            
            yield LogEntry(
                timestamp=timestamp,
                source="IIS",
                event_type=event_type,
                level=level,
                message=message,
                raw=line,
                source_ip=data.get('c-ip'),
                target_user=data.get('cs-username'),
                action=f"{data.get('cs-method')} {data.get('cs-uri-stem')}",
                status="success" if status < 400 else "failed",
                metadata={
                    "uri_query": data.get('cs-uri-query'),
                    "user_agent": data.get('cs(User-Agent)', ''),
                    "referer": data.get('cs(Referer)', ''),
                    "status": status,
                    "substatus": substatus,
                    "win32_status": data.get('sc-win32-status'),
                    "time_taken": data.get('time-taken')
                }
            )
        except Exception:
            return
