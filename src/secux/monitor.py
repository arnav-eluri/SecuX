import os
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable, List, Dict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent

from .Log_Analysis_Agent.parsers.autodetect import AutoDetectParser
from .Log_Analysis_Agent.parsers.base import LogEntry
from .Log_Analysis_Agent.analyzers.anomaly import AnomalyDetector, Anomaly


class LogFileHandler(FileSystemEventHandler):
    
    def __init__(
        self,
        paths: List[str],
        callback: Callable[[List[LogEntry], List[Anomaly]], None],
        analyzer: AnomalyDetector,
        parser: AutoDetectParser,
        interval: int = 60
    ):
        super().__init__()
        self.paths = [Path(p) for p in paths]
        self.callback = callback
        self.analyzer = analyzer
        self.parser = parser
        self.interval = interval
        self.last_positions: Dict[str, int] = {}
        self.last_entry_counts: Dict[str, int] = {}
        self.running = False
        self._thread: Optional[threading.Thread] = None
        
        for path in self.paths:
            if path.exists():
                self.last_positions[str(path)] = path.stat().st_size
    
    def on_modified(self, event):
        if event.is_directory:
            return
        
        if any(str(p) in event.src_path for p in self.paths):
            self._process_file(event.src_path)
    
    def _process_file(self, filepath: str):
        path = Path(filepath)
        if not path.exists():
            return
        
        try:
            current_size = path.stat().st_size
            last_pos = self.last_positions.get(filepath, 0)
            
            if current_size > last_pos:
                new_entries = []
                last_count = self.last_entry_counts.get(filepath, 0)
                all_entries = list(self.parser.parse(filepath))

                for entry in all_entries[last_count:]:
                    if entry.raw:
                        entry.timestamp = self._get_entry_timestamp(entry)
                        new_entries.append(entry)

                self.last_positions[filepath] = current_size
                self.last_entry_counts[filepath] = len(all_entries)
                
                if new_entries:
                    findings = self.analyzer.analyze(new_entries)
                    self.callback(new_entries, findings)
                    
        except Exception:
            pass
    
    def _get_entry_timestamp(self, entry: LogEntry) -> datetime:
        return entry.timestamp if entry.timestamp else datetime.now(timezone.utc)
    
    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
    
    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def _run(self):
        while self.running:
            for path in self.paths:
                if path.exists():
                    self._process_file(str(path))
            
            time.sleep(self.interval)


class LogMonitor:
    
    def __init__(
        self,
        paths: List[str],
        interval: int = 60,
        timeframe_hours: int = 24,
        severity_threshold: str = "LOW"
    ):
        self.paths = paths
        self.interval = interval
        self.timeframe_hours = timeframe_hours
        self.severity_threshold = severity_threshold
        
        self.parser = AutoDetectParser()
        self.analyzer = AnomalyDetector()
        self.handler: Optional[LogFileHandler] = None
        self.observer: Optional[Observer] = None
        
        self.total_events = 0
        self.total_findings = 0
        self.start_time = datetime.now(timezone.utc)
        self.last_update = self.start_time
    
    def start(self, callback: Optional[Callable] = None):
        def default_callback(entries, findings):
            self.total_events += len(entries)
            self.total_findings += len(findings)
            self.last_update = datetime.now(timezone.utc)
            
            if findings and callback is None:
                self._print_alerts(findings)
        
        handler_callback = callback or default_callback
        
        self.handler = LogFileHandler(
            paths=self.paths,
            callback=handler_callback,
            analyzer=self.analyzer,
            parser=self.parser,
            interval=self.interval
        )
        
        self.observer = Observer()
        
        dirs_to_watch = set()
        for path in self.paths:
            p = Path(path)
            if p.is_file():
                dirs_to_watch.add(str(p.parent))
            else:
                dirs_to_watch.add(str(p))
        
        for directory in dirs_to_watch:
            if os.path.exists(directory):
                self.observer.schedule(self.handler, directory, recursive=False)
        
        self.observer.start()
        self.handler.start()
        
        self.start_time = datetime.now(timezone.utc)
    
    def stop(self):
        if self.handler:
            self.handler.stop()
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
    
    def _print_alerts(self, findings: List[Anomaly]):
        from rich.console import Console
        
        console = Console()
        
        for finding in findings:
            severity_color = {
                "CRITICAL": "red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green"
            }.get(finding.severity, "white")
            
            console.print(
                f"[{severity_color}][{finding.severity}][/{severity_color}] "
                f"[cyan]{finding.finding_id}[/cyan]: {finding.description}"
            )
    
    def get_stats(self) -> dict:
        return {
            "running_since": self.start_time.isoformat(),
            "last_update": self.last_update.isoformat(),
            "total_events": self.total_events,
            "total_findings": self.total_findings,
            "monitored_paths": self.paths
        }
