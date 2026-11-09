import json
import os
from datetime import datetime, timezone
from typing import Iterator, Any
from .base import BaseParser, LogEntry


class JSONLogParser(BaseParser):
    
    def can_parse(self, filepath: str) -> bool:
        name = filepath.lower()
        return name.endswith('.json') or 'json' in name
    
    def parse(self, filepath: str) -> Iterator[LogEntry]:
        if not os.path.exists(filepath):
            return
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    if line.startswith('[') or line.startswith('{'):
                        yield from self._parse_json(line)
                    else:
                        try:
                            data = json.loads(line)
                            yield from self._parse_dict(data, line)
                        except json.JSONDecodeError:
                            continue
        except Exception:
            return
    
    def _parse_json(self, content: str) -> Iterator[LogEntry]:
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    yield from self._parse_dict(item, content[:200])
            else:
                yield from self._parse_dict(data, content[:200])
        except json.JSONDecodeError:
            return
    
    def _parse_dict(self, data: dict, raw: str) -> Iterator[LogEntry]:
        try:
            timestamp = self._extract_timestamp(data)
            level = self._extract_level(data)
            message = self._extract_message(data)
            source = self._extract_source(data)
            event_type = self._extract_event_type(data)
            
            yield LogEntry(
                timestamp=timestamp,
                source=source,
                event_type=event_type,
                level=level,
                message=message,
                raw=raw,
                source_ip=self._extract_ip(data),
                target_user=self._extract_user(data),
                action=data.get('action') or data.get('event'),
                status=data.get('status') or data.get('result'),
                metadata={k: v for k, v in data.items() 
                         if k not in ('timestamp', 'level', 'message', 'source', 'event', 'status')}
            )
        except Exception:
            return
    
    def _extract_timestamp(self, data: dict) -> datetime:
        ts_fields = ['timestamp', 'time', '@timestamp', 'datetime', 'ts', 'date']
        for field in ts_fields:
            if field in data:
                value = data[field]
                if isinstance(value, (int, float)):
                    if value > 1e10:
                        return datetime.fromtimestamp(value / 1000)
                    return datetime.fromtimestamp(value)
                elif isinstance(value, str):
                    try:
                        if 'T' in value:
                            return datetime.fromisoformat(value.replace('Z', '+00:00'))
                        return datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
                    except Exception:
                        continue
        return datetime.now(timezone.utc)
    
    def _extract_level(self, data: dict) -> str:
        level_fields = ['level', 'severity', 'loglevel', 'log_level', 'lvl']
        for field in level_fields:
            if field in data:
                level = str(data[field]).upper()
                if level in ('ERROR', 'ERR', 'CRITICAL', 'FATAL'):
                    return 'Error'
                elif level in ('WARNING', 'WARN'):
                    return 'Warning'
                elif level in ('DEBUG', 'TRACE', 'VERBOSE'):
                    return 'Verbose'
        return 'Information'
    
    def _extract_message(self, data: dict) -> str:
        msg_fields = ['message', 'msg', 'text', 'log', 'description']
        for field in msg_fields:
            if field in data:
                return str(data[field])
        return str(data)[:200]
    
    def _extract_source(self, data: dict) -> str:
        source_fields = ['source', 'logger', 'service', 'component', 'app', 'application']
        for field in source_fields:
            if field in data:
                return str(data[field])
        return 'Unknown'
    
    def _extract_event_type(self, data: dict) -> str:
        event_fields = ['event', 'event_type', 'type', 'category', 'action']
        for field in event_fields:
            if field in data:
                return str(data[field])
        return 'unknown'
    
    def _extract_ip(self, data: dict) -> str:
        ip_fields = ['ip', 'client_ip', 'remote_addr', 'source_ip', 'clientip', 'srcip', 'cip']
        import re
        for field in ip_fields:
            if field in data:
                value = str(data[field])
                if re.match(r'\d+\.\d+\.\d+\.\d+', value):
                    return value
        return None
    
    def _extract_user(self, data: dict) -> str:
        user_fields = ['user', 'username', 'user_id', 'uid', 'client_user']
        for field in user_fields:
            if field in data:
                return str(data[field])
        return None
