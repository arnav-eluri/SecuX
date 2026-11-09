import json
from datetime import datetime, timezone
from typing import List, Optional
from pathlib import Path

from ..analyzers.anomaly import Anomaly
from ...config import SystemConfig, get_available_log_files, format_timestamp


class JSONFormatter:
    
    def format(
        self,
        agent_name: str,
        system_config: SystemConfig,
        logs_accessed: List[dict],
        findings: List[Anomaly],
        baseline_metrics: dict,
        timeframe_start: Optional[str],
        timeframe_end: Optional[str],
        processing_duration: float,
        data_volume_mb: float,
        access_errors: Optional[List[dict]] = None,
        ai_summary: Optional[str] = None,
        total_entries: int = 0
    ) -> dict:

        
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(
            findings,
            key=lambda f: (severity_order.get(f.severity, 4), f.finding_id)
        )
        
        return {
            "agent": agent_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ai_summary": ai_summary,
            "system_info": {
                "os": system_config.os,
                "hostname": system_config.hostname,
                "logs_accessed": logs_accessed,
                "analysis_timeframe": f"{timeframe_start} - {timeframe_end}" if timeframe_start and timeframe_end else "N/A",
                "access_errors": access_errors or []
            },
            "findings": [f.to_dict() for f in sorted_findings],
            "stats": {
                "total_logs_analyzed": len(logs_accessed),
                "log_files_processed": sum(1 for l in logs_accessed if l.get("status") == "success"),
                "total_entries": total_entries,
                "anomalies_detected": len(findings),

                "time_range": f"{timeframe_start} - {timeframe_end}" if timeframe_start and timeframe_end else "N/A",
                "processing_duration": f"{processing_duration:.2f}",
                "data_volume_processed": f"{data_volume_mb:.2f} MB"
            },
            "baseline_metrics": baseline_metrics
        }
    
    def to_json(self, data: dict, pretty: bool = True) -> str:
        if pretty:
            return json.dumps(data, indent=2, default=str)
        return json.dumps(data, default=str)
    
    def save_to_file(self, data: dict, filepath: Path, append: bool = False) -> None:
        if append and filepath.exists():
            with open(filepath, 'r', encoding='utf-8') as f:
                existing = json.load(f)
            
            if isinstance(existing, dict) and "findings" in existing:
                existing_findings_ids = {f["finding_id"] for f in existing["findings"]}
                new_findings = [f for f in data["findings"] if f["finding_id"] not in existing_findings_ids]
                existing["findings"].extend(new_findings)
                existing["stats"]["anomalies_detected"] = len(existing["findings"])
                existing["timestamp"] = datetime.now(timezone.utc).isoformat()
                # Update AI summary if new one provided
                if data.get("ai_summary"):
                    existing["ai_summary"] = data["ai_summary"]
                data = existing
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(self.to_json(data))
    
    def print_summary(self, data: dict) -> None:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text

        console = Console(highlight=False, force_terminal=True)
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in data.get("findings", []):
            severity_counts[finding["severity"]] = severity_counts.get(finding["severity"], 0) + 1
        
        # AI SUMMARY PANEL
        if data.get("ai_summary"):
            console.print("\n[bold purple]AI INSIGHTS[/bold purple]")
            console.print(Panel(Text(data["ai_summary"], style="italic white"), border_style="purple"))

        table = Table(title="SecuX Log Analysis Summary", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("System", data["system_info"]["os"])
        table.add_row("Hostname", data["system_info"]["hostname"])
        table.add_row("Log Files", str(data["stats"]["log_files_processed"]))
        table.add_row("Total Entries", str(data["stats"].get("total_entries", 0)))
        table.add_row("Anomalies Detected", str(data["stats"]["anomalies_detected"]))
        table.add_row("Processing Time", data["stats"]["processing_duration"] + "s")
        table.add_row("Data Volume", data["stats"]["data_volume_processed"])
        
        console.print(table)
        
        severity_table = Table(title="Findings by Severity", show_header=True, header_style="bold cyan")
        severity_table.add_column("Severity", style="white")
        severity_table.add_column("Count", style="white")
        
        for severity, count in severity_counts.items():
            style = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green"
            }.get(severity, "")
            severity_table.add_row(severity, str(count), style=style)
        
        console.print(severity_table)
        
        if data.get("findings"):
            console.print("\n[bold cyan]Top Findings:[/bold cyan]")
            for i, finding in enumerate(data["findings"][:5], 1):
                severity_style = {
                    "CRITICAL": "bold red",
                    "HIGH": "red",
                    "MEDIUM": "yellow",
                    "LOW": "green"
                }.get(finding["severity"], "")
                
                panel = Panel(
                    f"[{severity_style}]{finding['severity']}[/{severity_style}] | "
                    f"[cyan]{finding['finding_id']}[/cyan] | "
                    f"{finding['description'][:60]}...",
                    title=finding["type"],
                    expand=False
                )
                console.print(panel)

