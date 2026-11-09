from dataclasses import dataclass, field
from datetime import datetime, date, time, timezone
from typing import List, Dict, Optional
from collections import defaultdict
from .patterns import PatternMatcher


@dataclass
class Anomaly:
    finding_id: str
    type: str
    severity: str
    confidence: float
    description: str
    evidence: dict
    timestamp: str
    log_entries: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "type": self.type,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "log_entries": self.log_entries
        }


class AnomalyDetector:

    # ─── Tunable thresholds ────────────────────────────────────────────────────
    BRUTE_FORCE_THRESHOLD = 5          # Failed logins per IP to flag brute force
    OFF_HOURS_START = time(22, 0)      # 10 PM
    OFF_HOURS_END = time(6, 0)         # 6 AM
    RAPID_REQUEST_THRESHOLD = 5        # Requests in <2 seconds (per IP or user)
    RAPID_REQUEST_WINDOW_SECONDS = 2
    LOG_GAP_THRESHOLD_SECONDS = 3600   # 1-hour silence = suspicious (5 min is normal activity)
    ERROR_RATE_MULTIPLIER = 3.0

    def __init__(self):
        self.finding_counter = 0
        self.pattern_matcher = PatternMatcher()
        self.baseline_metrics = {
            "login_attempts_per_hour": defaultdict(int),
            "error_rate": defaultdict(int),
            "unique_ips": set(),
            "unique_users": set(),
            "total_events": 0,
            "hourly_events": defaultdict(int),
        }

    # ─── Public API ────────────────────────────────────────────────────────────

    def analyze(self, entries: List, timeframe_hours: int = 24) -> List[Anomaly]:
        anomalies = []

        self._update_baseline(entries)

        anomalies.extend(self._detect_brute_force(entries))
        anomalies.extend(self._detect_off_hours_activity(entries))
        anomalies.extend(self._detect_rapid_requests(entries))
        anomalies.extend(self._detect_error_spikes(entries))
        anomalies.extend(self._detect_privilege_escalation(entries))
        anomalies.extend(self._detect_suspicious_processes(entries))
        anomalies.extend(self._detect_data_exfiltration(entries))
        anomalies.extend(self._detect_log_gaps(entries))
        anomalies.extend(self._detect_unusual_auth_patterns(entries))
        anomalies.extend(self._detect_attack_patterns(entries))

        return anomalies

    # ─── Baseline ─────────────────────────────────────────────────────────────

    def _update_baseline(self, entries: List) -> None:
        for entry in entries:
            self.baseline_metrics["total_events"] += 1

            if hasattr(entry, 'timestamp') and entry.timestamp:
                hour = entry.timestamp.hour
                self.baseline_metrics["hourly_events"][hour] += 1

            if entry.source_ip:
                self.baseline_metrics["unique_ips"].add(entry.source_ip)

            if entry.target_user:
                self.baseline_metrics["unique_users"].add(entry.target_user)

            if entry.event_type in ('login_failure', 'login_success'):
                if hasattr(entry, 'timestamp') and entry.timestamp:
                    self.baseline_metrics["login_attempts_per_hour"][entry.timestamp.hour] += 1

            if entry.level in ('Error', 'Warning', 'Critical'):
                if hasattr(entry, 'timestamp') and entry.timestamp:
                    self.baseline_metrics["error_rate"][entry.timestamp.hour] += 1

    # ─── Brute Force ──────────────────────────────────────────────────────────

    def _detect_brute_force(self, entries: List) -> List[Anomaly]:
        anomalies = []
        login_failures: Dict[str, list] = defaultdict(list)

        for entry in entries:
            if entry.event_type == 'login_failure' and entry.source_ip:
                login_failures[entry.source_ip].append(entry)

        for ip, failures in login_failures.items():
            if len(failures) >= self.BRUTE_FORCE_THRESHOLD:
                success_after = any(
                    e.event_type == 'login_success' and e.source_ip == ip
                    for e in entries
                    if e.timestamp and failures[0].timestamp and
                    self._naive(e.timestamp) >= self._naive(failures[0].timestamp)
                )

                severity = "CRITICAL" if success_after else "HIGH"
                confidence = min(0.95, 0.5 + (len(failures) * 0.05))

                self.finding_counter += 1
                anomalies.append(Anomaly(
                    finding_id=f"LA-{self.finding_counter:03d}",
                    type="brute_force_attempt",
                    severity=severity,
                    confidence=confidence,
                    description=(
                        f"Potential brute force attack detected from IP {ip} — "
                        f"{len(failures)} failed login(s) targeting '{failures[0].target_user}'"
                        + (" followed by successful login (credential compromise likely)" if success_after else "")
                    ),
                    evidence={
                        "log_source": "mixed",
                        "failed_attempts": len(failures),
                        "success_after_failures": success_after,
                        "source_ip": ip,
                        "target_user": failures[0].target_user,
                        "timeframe": self._format_timeframe(failures),
                        "event_count": len(failures),
                        "first_occurrence": failures[0].timestamp.isoformat() if failures else None,
                        "last_occurrence": failures[-1].timestamp.isoformat() if failures else None,
                    },
                    timestamp=failures[0].timestamp.isoformat() if failures else datetime.now(timezone.utc).isoformat(),
                    log_entries=[e.raw[:200] for e in failures[:5]]
                ))

        return anomalies

    # ─── Off-Hours Activity ────────────────────────────────────────────────────

    def _detect_off_hours_activity(self, entries: List) -> List[Anomaly]:
        """
        Flag ANY successful login during off-hours (22:00–06:00).
        Also flag clusters of off-hours events (≥2) from any IP.
        """
        anomalies = []
        seen_single_logins = set()          # avoid duplicates for single-event IPs
        off_hours_all: Dict[str, list] = defaultdict(list)

        for entry in entries:
            if not (entry.timestamp and self._is_off_hours(entry.timestamp)):
                continue

            key = entry.source_ip or entry.target_user or "unknown"
            off_hours_all[key].append(entry)

            # Single off-hours login success → immediate flag
            if entry.event_type == 'login_success' and key not in seen_single_logins:
                seen_single_logins.add(key)
                self.finding_counter += 1
                anomalies.append(Anomaly(
                    finding_id=f"LA-{self.finding_counter:03d}",
                    type="off_hours_login",
                    severity="HIGH",
                    confidence=0.80,
                    description=(
                        f"Successful login during off-hours (22:00–06:00) — "
                        f"user='{entry.target_user}' from {entry.source_ip or 'unknown IP'} "
                        f"at {entry.timestamp.strftime('%H:%M:%S')}"
                    ),
                    evidence={
                        "log_source": entry.source,
                        "source_ip": entry.source_ip,
                        "target_user": entry.target_user,
                        "event_count": 1,
                        "first_occurrence": entry.timestamp.isoformat(),
                        "last_occurrence": entry.timestamp.isoformat(),
                        "additional_context": "Login during restricted hours — possible stolen credentials"
                    },
                    timestamp=entry.timestamp.isoformat(),
                    log_entries=[entry.raw[:200]]
                ))

        # Multi-event off-hours clusters (≥2) not already fully flagged above
        for key, ip_entries in off_hours_all.items():
            if len(ip_entries) >= 2 and key not in seen_single_logins:
                self.finding_counter += 1
                anomalies.append(Anomaly(
                    finding_id=f"LA-{self.finding_counter:03d}",
                    type="off_hours_activity",
                    severity="MEDIUM",
                    confidence=0.70,
                    description=(
                        f"Multiple activities ({len(ip_entries)}) detected from '{key}' "
                        f"during off-hours (22:00–06:00)"
                    ),
                    evidence={
                        "log_source": "mixed",
                        "source_ip": ip_entries[0].source_ip,
                        "target_user": ip_entries[0].target_user,
                        "event_count": len(ip_entries),
                        "first_occurrence": ip_entries[0].timestamp.isoformat(),
                        "last_occurrence": ip_entries[-1].timestamp.isoformat(),
                        "additional_context": "Repeated off-hours access may indicate unauthorized use"
                    },
                    timestamp=ip_entries[0].timestamp.isoformat(),
                    log_entries=[e.raw[:200] for e in ip_entries[:3]]
                ))

        return anomalies

    # ─── Rapid Requests ───────────────────────────────────────────────────────

    def _detect_rapid_requests(self, entries: List) -> List[Anomaly]:
        """
        Detect automated request spikes.  Groups by IP if available, otherwise by
        target_user (handles API logs that have user= but no ip=).
        """
        anomalies = []
        request_times: Dict[str, list] = defaultdict(list)
        request_entries: Dict[str, list] = defaultdict(list)

        for entry in entries:
            if not entry.timestamp:
                continue
            key = entry.source_ip or entry.target_user or None
            if key:
                request_times[key].append(self._naive(entry.timestamp))
                request_entries[key].append(entry)

        reported: set = set()
        for key, times in request_times.items():
            if key in reported:
                continue

            paired = sorted(zip(times, request_entries[key]), key=lambda x: x[0])
            sorted_times = [p[0] for p in paired]
            sorted_ents = [p[1] for p in paired]

            n = self.RAPID_REQUEST_THRESHOLD
            for i in range(len(sorted_times) - n + 1):
                window_secs = (sorted_times[i + n - 1] - sorted_times[i]).total_seconds()
                if window_secs <= self.RAPID_REQUEST_WINDOW_SECONDS:
                    reported.add(key)
                    self.finding_counter += 1
                    anomalies.append(Anomaly(
                        finding_id=f"LA-{self.finding_counter:03d}",
                        type="rapid_requests",
                        severity="HIGH",
                        confidence=0.80,
                        description=(
                            f"Rapid request spike — {n}+ requests in {window_secs:.1f}s "
                            f"from '{key}' — possible automated attack or credential stuffing"
                        ),
                        evidence={
                            "log_source": "mixed",
                            "source_ip": sorted_ents[i].source_ip,
                            "target_user": sorted_ents[i].target_user,
                            "event_count": n,
                            "timeframe": f"{window_secs:.2f} seconds",
                            "first_occurrence": sorted_times[i].isoformat(),
                            "last_occurrence": sorted_times[i + n - 1].isoformat(),
                            "additional_context": f"{n} requests in {window_secs:.1f}s window"
                        },
                        timestamp=sorted_times[i].isoformat(),
                        log_entries=[e.raw[:200] for e in sorted_ents[i:i+n]]
                    ))
                    break

        return anomalies

    # ─── Error Spikes ─────────────────────────────────────────────────────────

    def _detect_error_spikes(self, entries: List) -> List[Anomaly]:
        anomalies = []
        hourly_errors: Dict[int, int] = defaultdict(int)
        hourly_total: Dict[int, int] = defaultdict(int)

        for entry in entries:
            if entry.timestamp:
                hour = entry.timestamp.hour
                hourly_total[hour] += 1
                if entry.level in ('Error', 'Warning', 'Critical'):
                    hourly_errors[hour] += 1

        avg_error_rate = sum(hourly_errors.values()) / max(1, sum(hourly_total.values()))

        for hour, errors in hourly_errors.items():
            rate = errors / max(1, hourly_total[hour])
            if rate > avg_error_rate * self.ERROR_RATE_MULTIPLIER and errors > 5:
                self.finding_counter += 1
                anomalies.append(Anomaly(
                    finding_id=f"LA-{self.finding_counter:03d}",
                    type="error_rate_spike",
                    severity="MEDIUM",
                    confidence=0.65,
                    description=f"Elevated error rate during hour {hour:02d}:00 — {errors} errors ({rate:.1%})",
                    evidence={
                        "log_source": "mixed",
                        "event_count": errors,
                        "timeframe": f"Hour {hour:02d}:00",
                        "first_occurrence": datetime(date.today().year, date.today().month, date.today().day, hour, 0, 0, tzinfo=timezone.utc).isoformat(),
                        "last_occurrence": datetime(date.today().year, date.today().month, date.today().day, hour, 59, 59, tzinfo=timezone.utc).isoformat(),
                        "additional_context": f"Error rate: {rate:.1%} vs avg baseline: {avg_error_rate:.1%}"
                    },
                    timestamp=datetime(date.today().year, date.today().month, date.today().day, hour, 0, 0, tzinfo=timezone.utc).isoformat(),
                    log_entries=[]
                ))

        return anomalies

    # ─── Privilege Escalation ─────────────────────────────────────────────────

    def _detect_privilege_escalation(self, entries: List) -> List[Anomaly]:
        """
        Fires on event_type == 'privilege_escalation' (which now includes role changes
        and sudo usage after parser fix).
        """
        anomalies = []

        for entry in entries:
            if entry.event_type not in ('privilege_escalation', 'privilege_assign'):
                continue

            msg_lower = entry.message.lower()
            is_admin = 'administrator' in msg_lower or 'admin' in msg_lower or '-> admin' in msg_lower
            is_sudo = 'sudo' in msg_lower or 'chmod' in msg_lower or 'chown' in msg_lower

            if is_admin or is_sudo:
                severity = "CRITICAL"
                confidence = 0.95
            else:
                severity = "HIGH"
                confidence = 0.82

            self.finding_counter += 1
            anomalies.append(Anomaly(
                finding_id=f"LA-{self.finding_counter:03d}",
                type="privilege_escalation",
                severity=severity,
                confidence=confidence,
                description=(
                    f"Privilege escalation detected — user='{entry.target_user}' "
                    f"{'gained admin/root privileges' if is_admin else 'executed privileged command'}"
                ),
                evidence={
                    "log_source": entry.source,
                    "source_ip": entry.source_ip,
                    "target_user": entry.target_user,
                    "event_count": 1,
                    "first_occurrence": entry.timestamp.isoformat(),
                    "last_occurrence": entry.timestamp.isoformat(),
                    "additional_context": entry.message
                },
                timestamp=entry.timestamp.isoformat(),
                log_entries=[entry.raw[:200]]
            ))

        return anomalies

    # ─── Suspicious Processes & Outbound Connections ─────────────────────────

    def _detect_suspicious_processes(self, entries: List) -> List[Anomaly]:
        """
        Detects suspicious process launches and outbound connections — classic malware/C2 pattern.
        Correlates process start + outbound connection from same process name.
        """
        anomalies = []
        suspicious_procs = [e for e in entries if e.event_type == 'suspicious_process']
        suspicious_conns = [e for e in entries if e.event_type == 'suspicious_connection']

        for proc_entry in suspicious_procs:
            # Extract process name (name=<x> or process=<x>)
            proc_name = self._extract_value_from_msg(proc_entry.message, 'name') or \
                        self._extract_value_from_msg(proc_entry.message, 'process')
            # Check if there's a matching outbound connection from the same process
            matched_conn = None
            if proc_name:
                for conn in suspicious_conns:
                    conn_proc = self._extract_value_from_msg(conn.message, 'process')
                    if conn_proc and conn_proc.lower() == proc_name.lower():
                        matched_conn = conn
                        break

            severity = "CRITICAL" if matched_conn else "HIGH"
            self.finding_counter += 1
            anomalies.append(Anomaly(
                finding_id=f"LA-{self.finding_counter:03d}",
                type="malicious_process",
                severity=severity,
                confidence=0.90,
                description=(
                    f"Suspicious process '{proc_name or 'unknown'}' launched from "
                    f"'{self._extract_value_from_msg(proc_entry.message, 'path') or 'unknown path'}'"
                    + (f" — outbound C2 connection to {self._extract_ip_from_msg(matched_conn.message)}" if matched_conn else "")
                ),
                evidence={
                    "log_source": proc_entry.source,
                    "process_name": proc_name,
                    "source_ip": matched_conn.source_ip if matched_conn else None,
                    "c2_ip": self._extract_ip_from_msg(matched_conn.message) if matched_conn else None,
                    "event_count": 2 if matched_conn else 1,
                    "first_occurrence": proc_entry.timestamp.isoformat(),
                    "last_occurrence": matched_conn.timestamp.isoformat() if matched_conn else proc_entry.timestamp.isoformat(),
                    "additional_context": "Process + outbound connection indicates C2 callback" if matched_conn else "Suspicious process without known path"
                },
                timestamp=proc_entry.timestamp.isoformat(),
                log_entries=[proc_entry.raw[:200]] + ([matched_conn.raw[:200]] if matched_conn else [])
            ))

        # Flag standalone outbound connections not already covered
        covered_conns = set()
        for proc_entry in suspicious_procs:
            proc_name = self._extract_value_from_msg(proc_entry.message, 'name')
            for conn in suspicious_conns:
                if proc_name and self._extract_value_from_msg(conn.message, 'process') == proc_name:
                    covered_conns.add(id(conn))

        for conn in suspicious_conns:
            if id(conn) not in covered_conns:
                dest_ip = self._extract_ip_from_msg(conn.message)
                self.finding_counter += 1
                anomalies.append(Anomaly(
                    finding_id=f"LA-{self.finding_counter:03d}",
                    type="suspicious_outbound_connection",
                    severity="HIGH",
                    confidence=0.80,
                    description=f"Unexpected outbound connection to {dest_ip or 'unknown IP'}",
                    evidence={
                        "log_source": conn.source,
                        "dest_ip": dest_ip,
                        "event_count": 1,
                        "first_occurrence": conn.timestamp.isoformat(),
                        "last_occurrence": conn.timestamp.isoformat(),
                    },
                    timestamp=conn.timestamp.isoformat(),
                    log_entries=[conn.raw[:200]]
                ))

        return anomalies

    # ─── Data Exfiltration ────────────────────────────────────────────────────

    def _detect_data_exfiltration(self, entries: List) -> List[Anomaly]:
        anomalies = []

        for entry in entries:
            if entry.event_type != 'data_exfiltration':
                continue

            size_str = self._extract_value_from_msg(entry.message, 'size') or "unknown"
            dest = self._extract_value_from_msg(entry.message, 'destination') or \
                   self._extract_ip_from_msg(entry.message) or "unknown"
            user = entry.target_user or "unknown"

            self.finding_counter += 1
            anomalies.append(Anomaly(
                finding_id=f"LA-{self.finding_counter:03d}",
                type="data_exfiltration",
                severity="CRITICAL",
                confidence=0.88,
                description=(
                    f"Potential data exfiltration — user='{user}' transferred {size_str} "
                    f"to external destination '{dest}'"
                ),
                evidence={
                    "log_source": entry.source,
                    "target_user": user,
                    "destination": dest,
                    "transfer_size": size_str,
                    "event_count": 1,
                    "first_occurrence": entry.timestamp.isoformat(),
                    "last_occurrence": entry.timestamp.isoformat(),
                    "additional_context": "Large transfer to external IP — possible data theft"
                },
                timestamp=entry.timestamp.isoformat(),
                log_entries=[entry.raw[:200]]
            ))

        return anomalies

    # ─── Log Gaps ─────────────────────────────────────────────────────────────

    def _detect_log_gaps(self, entries: List) -> List[Anomaly]:
        """
        Detects suspicious silences in the log timeline.
        Normalises timestamps to naive UTC before comparison to avoid
        TypeError when mixing timezone-aware and naive datetimes.
        """
        anomalies = []

        if len(entries) < 2:
            return anomalies

        try:
            sorted_entries = sorted(
                [e for e in entries if e.timestamp],
                key=lambda e: self._naive(e.timestamp)
            )
        except Exception:
            return anomalies

        gaps = []
        for i in range(len(sorted_entries) - 1):
            current = sorted_entries[i]
            next_entry = sorted_entries[i + 1]
            try:
                gap = (self._naive(next_entry.timestamp) - self._naive(current.timestamp)).total_seconds()
            except Exception:
                continue
            if gap > self.LOG_GAP_THRESHOLD_SECONDS:
                gaps.append((gap, current, next_entry))

        # Report only the 3 largest gaps to avoid flooding
        for gap, current, next_entry in sorted(gaps, key=lambda x: x[0], reverse=True)[:3]:
            self.finding_counter += 1
            anomalies.append(Anomaly(
                finding_id=f"LA-{self.finding_counter:03d}",
                type="log_gap",
                severity="MEDIUM",
                confidence=0.60,
                description=f"Suspicious gap in logging: {gap/60:.1f} minutes without entries between "
                            f"{current.timestamp.strftime('%H:%M:%S')} and {next_entry.timestamp.strftime('%H:%M:%S')}",
                evidence={
                    "log_source": "mixed",
                    "gap_minutes": round(gap / 60, 1),
                    "event_count": 0,
                    "first_occurrence": current.timestamp.isoformat(),
                    "last_occurrence": next_entry.timestamp.isoformat(),
                    "additional_context": "Possible log tampering or service interruption"
                },
                timestamp=current.timestamp.isoformat(),
                log_entries=[current.raw[:200], next_entry.raw[:200]]
            ))

        return anomalies

    # ─── Unusual Auth Patterns ────────────────────────────────────────────────

    def _detect_unusual_auth_patterns(self, entries: List) -> List[Anomaly]:
        anomalies = []

        login_events = [e for e in entries if e.event_type in ('login_success', 'login_failure')]
        if len(login_events) > 20:
            failed = sum(1 for e in login_events if e.event_type == 'login_failure')
            ratio = failed / len(login_events)

            if ratio > 0.75:
                self.finding_counter += 1
                anomalies.append(Anomaly(
                    finding_id=f"LA-{self.finding_counter:03d}",
                    type="high_failure_ratio",
                    severity="HIGH",
                    confidence=0.75,
                    description=f"Unusually high authentication failure ratio: {ratio:.1%} ({failed}/{len(login_events)} attempts failed)",
                    evidence={
                        "log_source": "mixed",
                        "failed_attempts": failed,
                        "total_attempts": len(login_events),
                        "failure_ratio": round(ratio, 3),
                        "event_count": len(login_events),
                        "first_occurrence": login_events[0].timestamp.isoformat() if login_events else None,
                        "last_occurrence": login_events[-1].timestamp.isoformat() if login_events else None,
                    },
                    timestamp=login_events[0].timestamp.isoformat() if login_events else datetime.now(timezone.utc).isoformat(),
                    log_entries=[]
                ))

        return anomalies

    # ─── Attack Pattern Matching ──────────────────────────────────────────────

    def _detect_attack_patterns(self, entries: List) -> List[Anomaly]:
        """Run PatternMatcher against each entry's raw message."""
        anomalies = []
        seen: set = set()

        for entry in entries:
            if not entry.raw:
                continue
            matches = self.pattern_matcher.match(entry.raw)
            for m in matches:
                key = (m["type"], entry.source_ip or entry.target_user or entry.raw[:50])
                if key in seen:
                    continue
                seen.add(key)
                self.finding_counter += 1
                ts = entry.timestamp.isoformat() if entry.timestamp else datetime.now(timezone.utc).isoformat()
                anomalies.append(Anomaly(
                    finding_id=f"LA-{self.finding_counter:03d}",
                    type=m["type"],
                    severity=m["severity"],
                    confidence=m["confidence"],
                    description=f"{m['name']} detected — matched '{m['matched_text'][:60]}'",
                    evidence={
                        "log_source": entry.source,
                        "source_ip": entry.source_ip,
                        "target_user": entry.target_user,
                        "matched_text": m["matched_text"],
                        "event_count": 1,
                        "first_occurrence": ts,
                        "last_occurrence": ts,
                    },
                    timestamp=ts,
                    log_entries=[entry.raw[:200]]
                ))

        return anomalies

    # ─── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _naive(dt: datetime) -> datetime:
        """Convert any datetime to naive UTC for safe comparison."""
        if dt is None:
            return datetime.now(timezone.utc).replace(tzinfo=None)
        if dt.tzinfo is not None:
            return dt.replace(tzinfo=None)
        return dt

    def _is_off_hours(self, dt: datetime) -> bool:
        current_time = dt.time()
        if self.OFF_HOURS_START > self.OFF_HOURS_END:  # spans midnight
            return current_time >= self.OFF_HOURS_START or current_time <= self.OFF_HOURS_END
        return self.OFF_HOURS_START <= current_time <= self.OFF_HOURS_END

    def _format_timeframe(self, entries: List) -> str:
        if not entries:
            return "unknown"

        first = getattr(entries[0], 'timestamp', None)
        last = getattr(entries[-1], 'timestamp', None)

        if first and last:
            duration = (self._naive(last) - self._naive(first)).total_seconds()
            if duration < 60:
                return f"{duration:.0f} seconds"
            elif duration < 3600:
                return f"{duration/60:.0f} minutes"
            else:
                return f"{duration/3600:.1f} hours"

        return "unknown"

    @staticmethod
    def _extract_value_from_msg(message: str, key: str) -> Optional[str]:
        import re
        m = re.search(fr'(?<![_a-zA-Z]){key}=([^\s=,]+)', message, re.IGNORECASE)
        return m.group(1) if m else None

    @staticmethod
    def _extract_ip_from_msg(message: str) -> Optional[str]:
        import re
        m = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', message)
        return m.group(1) if m else None

    def get_baseline_metrics(self) -> dict:
        total_events = self.baseline_metrics["total_events"]
        total_login = sum(self.baseline_metrics["login_attempts_per_hour"].values())
        total_errors = sum(self.baseline_metrics["error_rate"].values())
        avg_login_per_hour = total_login / 24 if total_login else 0
        avg_error_rate = (total_errors / total_events * 100) if total_events > 0 else 0

        return {
            "average_login_attempts_per_hour": round(avg_login_per_hour, 2),
            "average_error_rate": round(avg_error_rate, 2),
            "unique_source_ips": len(self.baseline_metrics["unique_ips"]),
            "unique_users": len(self.baseline_metrics["unique_users"])
        }
