import os
import re
from datetime import datetime
from typing import Iterator, Optional
from .base import BaseParser, LogEntry

EVENT_ID_MAP = {
    4624: ("login_success", "Authentication", "Information"),
    4625: ("login_failure", "Authentication", "Warning"),
    4627: ("login_success", "Authentication", "Information"),
    4634: ("logout", "Session", "Information"),
    4647: ("logout", "Session", "Information"),
    4672: ("privilege_assign", "Privilege", "Critical"),
    4720: ("account_created", "Account", "Warning"),
    4722: ("account_enabled", "Account", "Information"),
    4723: ("password_change", "Account", "Information"),
    4724: ("password_reset", "Account", "Warning"),
    4725: ("account_disabled", "Account", "Warning"),
    4726: ("account_deleted", "Account", "Critical"),
    4740: ("account_locked", "Account", "Warning"),
    4767: ("account_unlocked", "Account", "Information"),
    4768: ("kerberos_tgt_request", "Kerberos", "Information"),
    4769: ("kerberos_tgs_request", "Kerberos", "Information"),
    4771: ("kerberos_preauth_fail", "Kerberos", "Warning"),
    4776: ("ntlm_auth", "Authentication", "Information"),
    4670: ("privilege_modified", "Privilege", "Warning"),
    4688: ("process_created", "Process", "Information"),
    4689: ("process_terminated", "Process", "Information"),
    4698: ("task_created", "Task", "Information"),
    4699: ("task_deleted", "Task", "Warning"),
    4700: ("task_enabled", "Task", "Information"),
    4701: ("task_disabled", "Task", "Information"),
    4702: ("task_updated", "Task", "Information"),
    1102: ("audit_log_cleared", "Audit", "Critical"),
    1104: ("audit_log_cleared", "Audit", "Critical"),
}


class EVTXParser(BaseParser):
    
    def can_parse(self, filepath: str) -> bool:
        return filepath.lower().endswith('.evtx')
    
    def parse(self, filepath: str) -> Iterator[LogEntry]:
        try:
            import evtx
        except ImportError:
            return
        
        if not os.path.exists(filepath):
            return
        
        try:
            with open(filepath, 'rb') as f:
                parser = evtx.PythonEvtxParser(f)
                for record in parser.records():
                    yield from self._parse_record(record)
        except Exception:
            return
    
    def _parse_record(self, record: dict) -> Iterator[LogEntry]:
        try:
            xml_str = record.get('data', {})
            if isinstance(xml_str, dict):
                xml_str = xml_str.get('#text', '')
            
            from xml.etree import ElementTree
            root = ElementTree.fromstring(xml_str)
            
            ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            
            system = root.find('.//ns:System', ns)
            event_data = root.find('.//ns:EventData', ns)
            
            event_id_elem = system.find('ns:EventID', ns) if system is not None else None
            event_id = int(event_id_elem.text) if event_id_elem is not None else 0
            
            time_created = system.find('ns:TimeCreated', ns) if system is not None else None
            timestamp_str = time_created.get('SystemTime') if time_created is not None else None
            
            if timestamp_str:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                timestamp = datetime.utcnow()
            
            level_elem = system.find('ns:Level', ns) if system is not None else None
            level = self._map_level(int(level_elem.text)) if level_elem is not None else "Information"
            
            provider = system.find('ns:Provider', ns) if system is not None else None
            provider_name = provider.get('Name') if provider is not None else "Unknown"
            
            event_type, category, severity = EVENT_ID_MAP.get(event_id, ("unknown", "Unknown", level))
            
            data_items = {}
            if event_data is not None:
                for item in event_data.findall('ns:Data', ns):
                    name = item.get('Name')
                    if name:
                        data_items[name] = item.text
            
            message = self._build_message(event_id, data_items)
            source_ip = self._extract_ip(data_items.get('IpAddress'), data_items.get('SourceAddress'))
            target_user = data_items.get('TargetUserName') or data_items.get('SubjectUserName')
            
            yield LogEntry(
                timestamp=timestamp,
                source=provider_name,
                event_type=event_type,
                level=severity,
                message=message,
                raw=xml_str[:500] if len(xml_str) > 500 else xml_str,
                source_ip=source_ip,
                target_user=target_user,
                action=event_type,
                status="success" if event_type in ("login_success", "logout") else None,
                session_id=data_items.get('TargetLogonId'),
                process_id=int(data_items.get('ProcessId', 0)) or None,
                computer_name=data_items.get('ComputerName'),
                metadata=data_items
            )
        except Exception:
            return
    
    def _map_level(self, level: int) -> str:
        mapping = {0: "LogAlways", 1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose"}
        return mapping.get(level, "Information")
    
    def _extract_ip(self, *values) -> Optional[str]:
        for val in values:
            if val and val not in ('-', '::1', '127.0.0.1', 'localhost'):
                if re.match(r'\d+\.\d+\.\d+\.\d+', val):
                    return val
        return None
    
    def _build_message(self, event_id: int, data: dict) -> str:
        if event_id == 4624:
            return f"User '{data.get('TargetUserName')}' logged in from {data.get('IpAddress', 'N/A')}"
        elif event_id == 4625:
            return f"Failed login for user '{data.get('TargetUserName')}' from {data.get('IpAddress', 'N/A')}"
        elif event_id == 4672:
            return f"Special privileges assigned to '{data.get('SubjectUserName')}'"
        elif event_id == 4688:
            return f"Process created: {data.get('NewProcessName', 'Unknown')}"
        elif event_id == 1102:
            return "Audit log was cleared"
        return f"Event ID {event_id}: {data.get('Message', '')[:100]}"
