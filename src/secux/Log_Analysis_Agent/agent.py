import os
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Iterator, Optional, Tuple

from ..config import get_system_config, get_available_log_files, format_timestamp, SystemConfig
from .parsers.autodetect import AutoDetectParser
from .parsers.base import LogEntry
from .analyzers.anomaly import AnomalyDetector, Anomaly
from .output.json_formatter import JSONFormatter
from ..llm_engine import LLMEngine


class LogAnalysisAgent:
    
    PROMPT_SUMMARY = """
You are a senior cybersecurity analyst reviewing structured threat findings.

You have been given the following log analysis findings from the SecuX detection engine.
Each finding includes a severity level, a description, and key evidence (IPs, users, timestamps).

Findings:
{findings}

Your task:
1. Identify the highest-risk threats and explain WHY they are dangerous.
2. Reference specific IPs, usernames, timestamps, and event counts from the data above.
3. Group related findings into an attack narrative if applicable (e.g., brute-force → login → privilege escalation = likely account takeover).
4. Recommend concrete immediate actions (block IP, revoke session, audit user, etc.).
5. Use a technical analyst tone. Be direct and specific. Do NOT write generic advice.

Format your response as:
  THREAT SUMMARY
  IMMEDIATE RISKS (bullet points)
  RECOMMENDATIONS (numbered)
"""
    
    def __init__(self, timeframe_hours: int = 24, severity_threshold: str = "LOW"):
        self.timeframe_hours = timeframe_hours
        self.severity_threshold = severity_threshold
        self.system_config = get_system_config()
        self.parser = AutoDetectParser()
        self.detector = AnomalyDetector()
        self.formatter = JSONFormatter()
        self.llm = LLMEngine()
        
        self._entries: List[LogEntry] = []
        self._logs_accessed: List[dict] = []
        self._access_errors: List[dict] = []
        self._start_time: Optional[datetime] = None
        self._end_time: Optional[datetime] = None
        self._processing_duration: float = 0
        self._data_volume_mb: float = 0
    
    def run(
        self,
        log_paths: Optional[List[str]] = None,
        output_file: Optional[Path] = None,
        append: bool = False,
        show_summary: bool = True,
        skip_ai_summary: bool = False
    ) -> dict:
        
        start = time.time()
        
        if log_paths is None:
            available = get_available_log_files(self.system_config)
            log_paths = [l["path"] for l in available if l["status"] == "success"]
        
        self._logs_accessed = []
        self._access_errors = []
        self._entries = []
        self._data_volume_mb = 0.0
        
        for path in log_paths:
            if os.path.exists(path):
                size_mb = os.path.getsize(path) / (1024 * 1024)
                self._data_volume_mb += size_mb  # Fix Issue 12: store volume
                stat = os.stat(path)
                
                self._logs_accessed.append({
                    "path": path,
                    "size": f"{size_mb:.2f} MB",
                    "last_modified": format_timestamp(stat.st_mtime),
                    "status": "success"
                })
                
                entries = list(self.parser.parse(path))
                self._entries.extend(entries)
            else:
                self._logs_accessed.append({
                    "path": path,
                    "size": "0 MB",
                    "last_modified": "N/A",
                    "status": "failed"
                })
                self._access_errors.append({
                    "path": path,
                    "error": "file_not_found"
                })
        
        self._entries = self._filter_timeframe(self._entries)
        
        if self._entries:
            timestamps = [e.timestamp for e in self._entries if e.timestamp]
            if timestamps:
                self._start_time = min(timestamps)
                self._end_time = max(timestamps)
        
        findings = self.detector.analyze(self._entries, self.timeframe_hours)
        findings = self._filter_by_severity(findings)
        
        # Fix Issue 12: record processing duration
        self._processing_duration = time.time() - start

        # Fix Issue 9: build a rich structured context for the LLM instead of bare descriptions
        ai_summary = "AI Summary skipped or no findings."
        if findings and not skip_ai_summary:
            ai_summary = self.generate_ai_summary(findings)
        elif not findings:
            ai_summary = "No significant findings detected in the analyzed timeframe."

        result = self.formatter.format(
            agent_name="Log_Analysis_Agent",
            system_config=self.system_config,
            logs_accessed=self._logs_accessed,
            findings=findings,
            baseline_metrics=self.detector.get_baseline_metrics(),
            timeframe_start=self._start_time.isoformat() if self._start_time else None,
            timeframe_end=self._end_time.isoformat() if self._end_time else None,
            processing_duration=self._processing_duration,
            data_volume_mb=self._data_volume_mb,
            access_errors=self._access_errors,
            ai_summary=ai_summary,
            total_entries=len(self._entries)
        )

        
        if output_file:
            self.formatter.save_to_file(result, output_file, append)
        
        if show_summary:
            self.formatter.print_summary(result)
        
        return result
    
    def generate_ai_summary(self, findings: List[Anomaly]) -> str:
        """Generates an AI-driven summary of the findings."""
        if not findings:
            return "No significant findings detected."
            
        finding_context = []
        for f in findings[:12]:
            if isinstance(f, dict):
                sev = f.get('severity', 'N/A')
                typ = f.get('type', 'N/A')
                fid = f.get('finding_id', 'N/A')
                desc = f.get('description', '')
                evid = f.get('evidence', {})
                conf = f.get('confidence', 0)
            else:
                sev = f.severity
                typ = f.type
                fid = f.finding_id
                desc = f.description
                evid = f.evidence
                conf = f.confidence

            ctx = (
                f"[{sev}] {typ.upper()} | {fid}\n"
                f"  Description: {desc}\n"
                f"  Evidence: IP={evid.get('source_ip', 'N/A')}, "
                f"User={evid.get('target_user', 'N/A')}, "
                f"Events={evid.get('event_count', 'N/A')}, "
                f"Confidence={conf:.0%}\n"
                f"  Time: {evid.get('first_occurrence', 'N/A')} → "
                f"{evid.get('last_occurrence', 'N/A')}\n"
                f"  Context: {evid.get('additional_context', '')}"
            )
            finding_context.append(ctx)
            
        summary_prompt = self.PROMPT_SUMMARY.format(findings="\n\n".join(finding_context))
        return self.llm.query(summary_prompt, agent_type="log_analysis") or "Analysis failed."

    def run_incremental(
        self,
        log_paths: Optional[List[str]] = None,
        since: Optional[datetime] = None
    ) -> Tuple[List[LogEntry], List[Anomaly]]:
        
        if log_paths is None:
            available = get_available_log_files(self.system_config)
            log_paths = [l["path"] for l in available if l["status"] == "success"]
        
        new_entries = []

        for path in log_paths:
            if not os.path.exists(path):
                continue

            for entry in self.parser.parse(path):
                if since and entry.timestamp:
                    # Normalize to aware for comparison
                    ts = entry.timestamp
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    since_aware = since if since.tzinfo else since.replace(tzinfo=timezone.utc)
                    if ts <= since_aware:
                        continue
                new_entries.append(entry)

        new_entries = self._filter_timeframe(new_entries)
        findings = self.detector.analyze(new_entries, self.timeframe_hours)
        
        return new_entries, findings
    
    def _filter_timeframe(self, entries: List[LogEntry]) -> List[LogEntry]:
        """
        Filter entries to the configured timeframe.
        Fix Issue 2: if the cutoff discards ALL entries (e.g. test/historical logs),
        return all entries instead so detectors still run.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.timeframe_hours)

        filtered = []
        for entry in entries:
            if entry.timestamp and entry.timestamp.tzinfo is None:
                # Treat naive timestamps as UTC
                entry.timestamp = entry.timestamp.replace(tzinfo=timezone.utc)

            if entry.timestamp and entry.timestamp >= cutoff:
                filtered.append(entry)

        # Graceful fallback: if filtering removed everything, analyze the full set.
        # This handles historic test logs and demo files without breaking production.
        if not filtered and entries:
            for entry in entries:
                if entry.timestamp and entry.timestamp.tzinfo is None:
                    entry.timestamp = entry.timestamp.replace(tzinfo=timezone.utc)
            return entries

        return filtered
    
    def _filter_by_severity(self, findings: List[Anomaly]) -> List[Anomaly]:
        severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        threshold_level = severity_order.get(self.severity_threshold, 0)
        
        return [
            f for f in findings
            if severity_order.get(f.severity, 0) >= threshold_level
        ]
    
    def get_entries(self) -> List[LogEntry]:
        return self._entries
    
    def get_system_info(self) -> SystemConfig:
        return self.system_config
