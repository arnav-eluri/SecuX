import os
from typing import Iterator, List, Type
from .base import BaseParser, LogEntry
from .evtx import EVTXParser
from .iis import IISParser
from .syslog import SyslogParser
from .json_log import JSONLogParser
from .simple_text import SimpleTextParser


class AutoDetectParser(BaseParser):
    
    def __init__(self):
        self.parsers: List[BaseParser] = [
            EVTXParser(),
            SyslogParser(),
            IISParser(),
            JSONLogParser(),
            SimpleTextParser(),
        ]


    
    def can_parse(self, filepath: str) -> bool:
        return True
    
    def parse(self, filepath: str) -> Iterator[LogEntry]:
        for parser in self.parsers:
            if parser.can_parse(filepath):
                yield from parser.parse(filepath)
                return
        
        yield from self._fallback_parse(filepath)
    
    def _fallback_parse(self, filepath: str) -> Iterator[LogEntry]:
        if not os.path.exists(filepath):
            return
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i > 1000:
                        break
                    
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    from datetime import datetime, timezone
                    yield LogEntry(
                        timestamp=datetime.now(timezone.utc),
                        source=os.path.basename(filepath),
                        event_type="unknown",
                        level="Information",
                        message=line[:200],
                        raw=line[:500]
                    )
        except Exception:
            return
    
    def get_parser_for_file(self, filepath: str) -> Type[BaseParser]:
        for parser in self.parsers:
            if parser.can_parse(filepath):
                return type(parser)
        return BaseParser
