from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Iterator


@dataclass
class LogEntry:
    timestamp: datetime
    source: str
    event_type: str
    level: str
    message: str
    raw: str
    source_ip: Optional[str] = None
    target_user: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    session_id: Optional[str] = None
    process_id: Optional[int] = None
    computer_name: Optional[str] = None
    metadata: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source": self.source,
            "event_type": self.event_type,
            "level": self.level,
            "message": self.message,
            "raw": self.raw,
            "source_ip": self.source_ip,
            "target_user": self.target_user,
            "action": self.action,
            "status": self.status,
            "session_id": self.session_id,
            "process_id": self.process_id,
            "computer_name": self.computer_name,
            "metadata": self.metadata
        }


class BaseParser(ABC):
    
    @abstractmethod
    def parse(self, filepath: str) -> Iterator[LogEntry]:
        pass
    
    @abstractmethod
    def can_parse(self, filepath: str) -> bool:
        pass
    
    def _safe_timestamp(self, ts: Optional[datetime]) -> datetime:
        return ts if ts else datetime.now(timezone.utc)
