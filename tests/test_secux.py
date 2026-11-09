import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path
import tempfile
import os

from secux.config import get_system_config, SystemConfig
from secux.Log_Analysis_Agent.parsers.base import LogEntry
from secux.Log_Analysis_Agent.parsers.syslog import SyslogParser
from secux.Log_Analysis_Agent.parsers.iis import IISParser
from secux.Log_Analysis_Agent.parsers.json_log import JSONLogParser
from secux.Log_Analysis_Agent.analyzers.anomaly import AnomalyDetector, Anomaly
from secux.Log_Analysis_Agent.output.json_formatter import JSONFormatter


class TestSystemConfig:
    
    def test_get_system_config(self):
        config = get_system_config()
        
        assert config.os in ["windows", "linux", "darwin"]
        assert config.hostname is not None
        assert isinstance(config.is_windows, bool)
        assert isinstance(config.log_paths, dict)


class TestLogEntry:
    
    def test_log_entry_creation(self):
        entry = LogEntry(
            timestamp=datetime.now(timezone.utc),
            source="test",
            event_type="login_failure",
            level="Warning",
            message="Failed login attempt",
            raw="<34>Oct 11 22:14:15 test sshd: Failed password"
        )
        
        assert entry.source == "test"
        assert entry.event_type == "login_failure"
        assert entry.level == "Warning"
    
    def test_log_entry_to_dict(self):
        entry = LogEntry(
            timestamp=datetime.now(timezone.utc),
            source="test",
            event_type="login_failure",
            level="Warning",
            message="Failed login attempt",
            raw="test raw"
        )
        
        data = entry.to_dict()
        
        assert isinstance(data, dict)
        assert data["source"] == "test"
        assert data["event_type"] == "login_failure"


class TestSyslogParser:
    
    def test_can_parse_syslog(self):
        parser = SyslogParser()
        
        assert parser.can_parse("/var/log/auth.log") == True
        assert parser.can_parse("/var/log/syslog") == True
        assert parser.can_parse("/var/log/secure") == True
        assert parser.can_parse("/var/log/messages") == True
        assert parser.can_parse("/var/log/apache2/access.log") == False
    
    def test_parse_syslog_line(self):
        parser = SyslogParser()
        line = "<34>Oct 15 10:30:45 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100"
        
        entries = list(parser._parse_line(line))
        
        assert len(entries) > 0
        entry = entries[0]
        assert entry.source == "server"
        assert entry.event_type == "login_failure"
        assert entry.source_ip == "192.168.1.100"
    
    def test_parse_apache_combined_log(self):
        parser = SyslogParser()
        line = '192.168.1.100 - user [15/Oct/2024:10:30:45 +0000] "GET /admin HTTP/1.1" 401 1234 "-" "Mozilla/5.0"'
        
        entries = list(parser._parse_line(line))
        
        assert len(entries) > 0
        entry = entries[0]
        assert entry.source_ip == "192.168.1.100"
        assert entry.status == "failed"


class TestIISParser:
    
    def test_can_parse_iis(self):
        parser = IISParser()
        
        assert parser.can_parse("C:\\Windows\\System32\\LogFiles\\W3SVC1\\u_ex210115.log") == True
        assert parser.can_parse("/var/log/w3svc/access.log") == True
        assert parser.can_parse("/other/path/file.txt") == False
    
    def test_parse_iis_line(self):
        parser = IISParser()
        line = "2024-10-15 10:30:45 192.168.1.100 GET /admin/login.aspx - 80 - 192.168.1.50 Mozilla/5.0 401 0 0 123"
        
        entries = list(parser._parse_line(line))
        
        assert len(entries) > 0
        entry = entries[0]
        assert entry.source == "IIS"
        assert entry.event_type in ("http_request", "auth_required", "server_error", "unknown")


class TestJSONLogParser:
    
    def test_can_parse_json(self):
        parser = JSONLogParser()
        
        assert parser.can_parse("application.json") == True
        assert parser.can_parse("/var/log/app.json") == True
        assert parser.can_parse("/var/log/app.log") == False
    
    def test_parse_json_line(self):
        parser = JSONLogParser()
        json_str = '{"timestamp": "2024-10-15T10:30:45Z", "level": "ERROR", "message": "Connection failed", "source": "app.db"}'
        
        entries = list(parser._parse_json(json_str))
        
        assert len(entries) > 0
        entry = entries[0]
        assert entry.level == "Error"
        assert entry.source == "app.db"


class TestAnomalyDetector:
    
    def test_detect_brute_force(self):
        detector = AnomalyDetector()
        
        base_time = datetime.now(timezone.utc)
        entries = []
        
        for i in range(6):
            entries.append(LogEntry(
                timestamp=base_time + timedelta(seconds=i),
                source="sshd",
                event_type="login_failure",
                level="Warning",
                message=f"Failed login attempt {i}",
                raw=f"Failed attempt {i}",
                source_ip="192.168.1.100",
                target_user="admin"
            ))
        
        entries.append(LogEntry(
            timestamp=base_time + timedelta(seconds=10),
            source="sshd",
            event_type="login_success",
            level="Information",
            message="Successful login",
            raw="Success",
            source_ip="192.168.1.100",
            target_user="admin"
        ))
        
        anomalies = detector.analyze(entries)
        
        brute_force = [a for a in anomalies if a.type == "brute_force_attempt"]
        assert len(brute_force) > 0
        assert brute_force[0].severity == "CRITICAL"
    
    def test_detect_off_hours_activity(self):
        detector = AnomalyDetector()
        
        base_time = datetime.now(timezone.utc).replace(hour=23, minute=0, second=0)
        entries = []
        
        for i in range(4):
            entries.append(LogEntry(
                timestamp=base_time + timedelta(minutes=i * 10),
                source="system",
                event_type="login_success",
                level="Information",
                message="User logged in",
                raw=f"Login event {i}",
                source_ip="192.168.1.100",
                target_user="admin"
            ))
        
        anomalies = detector.analyze(entries)
        
        off_hours = [a for a in anomalies if a.type == "off_hours_activity"]
        assert len(off_hours) > 0
    
    def test_detect_privilege_escalation(self):
        detector = AnomalyDetector()
        
        entries = [
            LogEntry(
                timestamp=datetime.now(timezone.utc),
                source="Security",
                event_type="privilege_assign",
                level="Critical",
                message="Special privileges assigned to user: Administrator",
                raw="Privilege assignment",
                target_user="Administrator"
            )
        ]
        
        anomalies = detector.analyze(entries)
        
        priv_esc = [a for a in anomalies if a.type == "privilege_escalation"]
        assert len(priv_esc) > 0
        assert priv_esc[0].severity == "CRITICAL"
    
    def test_baseline_metrics(self):
        detector = AnomalyDetector()
        
        entries = [
            LogEntry(
                timestamp=datetime.now(timezone.utc),
                source="auth",
                event_type="login_success",
                level="Information",
                message="Login",
                raw="login",
                source_ip="192.168.1.100",
                target_user="user1"
            ),
            LogEntry(
                timestamp=datetime.now(timezone.utc),
                source="auth",
                event_type="login_failure",
                level="Warning",
                message="Failed login",
                raw="failed",
                source_ip="192.168.1.101",
                target_user="user2"
            )
        ]
        
        detector.analyze(entries)
        metrics = detector.get_baseline_metrics()
        
        assert metrics["unique_source_ips"] == 2
        assert metrics["unique_users"] == 2
        assert metrics["average_login_attempts_per_hour"] >= 0


class TestJSONFormatter:
    
    def test_format_output(self):
        formatter = JSONFormatter()
        
        config = SystemConfig(
            os="windows",
            hostname="test-host",
            is_windows=True,
            is_linux=False,
            is_macos=False
        )
        
        logs_accessed = [
            {
                "path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
                "size": "2.5 MB",
                "last_modified": "2024-10-15T10:30:00Z",
                "status": "success"
            }
        ]
        
        findings = [
            Anomaly(
                finding_id="LA-001",
                type="brute_force_attempt",
                severity="CRITICAL",
                confidence=0.95,
                description="Potential brute force attack",
                evidence={"source_ip": "192.168.1.100"},
                timestamp=datetime.now(timezone.utc).isoformat(),
                log_entries=["sample log"]
            )
        ]
        
        baseline = {
            "average_login_attempts_per_hour": 5.0,
            "average_error_rate": 2.5,
            "unique_source_ips": 10,
            "unique_users": 5
        }
        
        result = formatter.format(
            agent_name="Log_Analysis_Agent",
            system_config=config,
            logs_accessed=logs_accessed,
            findings=findings,
            baseline_metrics=baseline,
            timeframe_start="2024-10-14T00:00:00Z",
            timeframe_end="2024-10-15T00:00:00Z",
            processing_duration=5.5,
            data_volume_mb=10.2
        )
        
        assert result["agent"] == "Log_Analysis_Agent"
        assert result["system_info"]["os"] == "windows"
        assert result["system_info"]["hostname"] == "test-host"
        assert len(result["findings"]) == 1
        assert result["stats"]["anomalies_detected"] == 1
    
    def test_to_json(self):
        formatter = JSONFormatter()
        
        data = {"key": "value", "number": 42}
        
        json_str = formatter.to_json(data, pretty=True)
        
        assert isinstance(json_str, str)
        assert '"key": "value"' in json_str


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
