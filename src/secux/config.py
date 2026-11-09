import os
import platform
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class SystemConfig:
    os: str
    hostname: str
    is_windows: bool
    is_linux: bool
    is_macos: bool
    log_paths: dict = field(default_factory=dict)


def get_system_config() -> SystemConfig:
    system = platform.system().lower()
    hostname = socket.gethostname()
    
    is_windows = system == "windows"
    is_linux = system == "linux"
    is_macos = system == "darwin"
    
    log_paths = _get_log_paths(system)
    
    return SystemConfig(
        os=system,
        hostname=hostname,
        is_windows=is_windows,
        is_linux=is_linux,
        is_macos=is_macos,
        log_paths=log_paths
    )


def _get_log_paths(system: str) -> dict:
    if system == "windows":
        return {
            "security": r"C:\Windows\System32\winevt\Logs\Security.evtx",
            "system": r"C:\Windows\System32\winevt\Logs\System.evtx",
            "application": r"C:\Windows\System32\winevt\Logs\Application.evtx",
            "setup": r"C:\Windows\System32\winevt\Logs\Setup.evtx",
            "iis": r"C:\Windows\System32\LogFiles\W3SVC1",
        }
    elif system == "linux":
        return {
            "auth": "/var/log/auth.log",
            "syslog": "/var/log/syslog",
            "secure": "/var/log/secure",
            "messages": "/var/log/messages",
            "kern": "/var/log/kern.log",
            "apache_access": "/var/log/apache2/access.log",
            "apache_error": "/var/log/apache2/error.log",
            "mysql": "/var/log/mysql/error.log",
            "fail2ban": "/var/log/fail2ban.log",
        }
    elif system == "darwin":
        return {
            "system": "/var/log/system.log",
            "secure": "/var/log/secure.log",
            "apple_system": "/var/log/asl/",
        }
    return {}


def get_available_log_files(config: SystemConfig) -> list[dict]:
    available = []
    for name, path in config.log_paths.items():
        if os.path.exists(path):
            if os.path.isdir(path):
                for f in os.listdir(path):
                    full_path = os.path.join(path, f)
                    if os.path.isfile(full_path):
                        stat = os.stat(full_path)
                        available.append({
                            "name": f"{name}/{f}",
                            "path": full_path,
                            "size": stat.st_size,
                            "modified": stat.st_mtime,
                            "status": "success"
                        })
            else:
                stat = os.stat(path)
                available.append({
                    "name": name,
                    "path": path,
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                    "status": "success"
                })
        else:
            available.append({
                "name": name,
                "path": path,
                "size": 0,
                "modified": 0,
                "status": "failed",
                "error": "file_not_found"
            })
    return available


def format_timestamp(ts: float) -> str:
    from datetime import datetime, timezone
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.isoformat()


def get_default_output_path() -> Path:
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(f"secux_logscan_{timestamp}.json")
