# SecuX — Low-Level Design

## 1. Module Map

```
src/secux/
├── cli.py                          # Click CLI entry point, orchestration logic
├── config.py                       # SystemConfig dataclass, OS-specific log paths
├── collector.py                    # DataCollector — live OS telemetry
├── monitor.py                      # LogMonitor + LogFileHandler (watchdog)
├── llm_engine.py                   # LLMEngine — unified LLM abstraction
├── Log_Analysis_Agent/
│   ├── agent.py                    # LogAnalysisAgent
│   ├── parsers/
│   │   ├── autodetect.py           # AutoDetectParser — format routing
│   │   ├── base.py                 # LogEntry dataclass
│   │   ├── syslog.py               # RFC3164 syslog parser
│   │   ├── evtx.py                 # Windows .evtx parser
│   │   ├── iis.py                  # IIS W3C access log parser
│   │   ├── json_log.py             # Newline-delimited JSON parser
│   │   └── simple_text.py          # Plain-text fallback parser
│   ├── analyzers/
│   │   ├── anomaly.py              # AnomalyDetector + Anomaly dataclass
│   │   └── patterns.py             # PatternMatcher — regex/heuristic rules
│   └── output/
│       └── json_formatter.py       # JSONFormatter — structured output + Rich summary
├── Authentication_Agent/agent.py   # AuthenticationAgent
├── Network_Monitoring_Agent/agent.py # NetworkMonitoringAgent
├── Vulnerability_Analysis_Agent/agent.py # VulnerabilityAnalysisAgent
└── Super_Agent/agent.py            # SuperAgent
```

---

## 2. Class Diagram

```mermaid
classDiagram
    class LLMEngine {
        +provider: str
        +local_model: str
        +openrouter_api_key: str
        +openrouter_model: str
        +google_model: GenerativeModel
        +MAX_TOKENS: dict
        +query(prompt, agent_type) str
        -_query_local(prompt, max_tokens) str
        -_query_google(prompt, max_tokens) str
        -_query_openrouter(prompt, agent_type, max_tokens) str
    }

    class LogAnalysisAgent {
        +timeframe_hours: int
        +severity_threshold: str
        +system_config: SystemConfig
        +parser: AutoDetectParser
        +detector: AnomalyDetector
        +formatter: JSONFormatter
        +llm: LLMEngine
        +run(log_paths, output_file, append, show_summary, skip_ai_summary) dict
        +generate_ai_summary(findings) str
        +run_incremental(log_paths, since) Tuple
        -_filter_timeframe(entries) List
        -_filter_by_severity(findings) List
    }

    class AuthenticationAgent {
        +name: str
        +llm: LLMEngine
        +PROMPT: str
        +analyze(data) str
    }

    class NetworkMonitoringAgent {
        +name: str
        +llm: LLMEngine
        +PROMPT: str
        +analyze(data) str
    }

    class VulnerabilityAnalysisAgent {
        +name: str
        +llm: LLMEngine
        +PROMPT: str
        +analyze(data) str
    }

    class SuperAgent {
        +name: str
        +llm: LLMEngine
        +PROMPT_SINGLE_PASS: str
        +analyze(data_from_agents) str
    }

    class AnomalyDetector {
        +BRUTE_FORCE_THRESHOLD: int
        +OFF_HOURS_START: time
        +OFF_HOURS_END: time
        +RAPID_REQUEST_THRESHOLD: int
        +baseline_metrics: dict
        +pattern_matcher: PatternMatcher
        +analyze(entries, timeframe_hours) List~Anomaly~
        -_update_baseline(entries)
        -_detect_brute_force(entries) List
        -_detect_off_hours_activity(entries) List
        -_detect_rapid_requests(entries) List
        -_detect_error_spikes(entries) List
        -_detect_privilege_escalation(entries) List
        -_detect_suspicious_processes(entries) List
        -_detect_data_exfiltration(entries) List
        -_detect_log_gaps(entries) List
        -_detect_unusual_auth_patterns(entries) List
        -_detect_attack_patterns(entries) List
    }

    class Anomaly {
        +finding_id: str
        +type: str
        +severity: str
        +confidence: float
        +description: str
        +evidence: dict
        +timestamp: str
        +log_entries: List~str~
        +to_dict() dict
    }

    class AutoDetectParser {
        +parse(filepath) Iterator~LogEntry~
    }

    class LogEntry {
        +timestamp: datetime
        +level: str
        +source: str
        +message: str
        +raw: str
        +parsed_fields: dict
    }

    class DataCollector {
        +os: str
        +is_windows: bool
        +get_network_context() str
        +get_vulnerability_context() str
        +get_auth_context(log_findings) str
    }

    class SystemConfig {
        +os: str
        +hostname: str
        +is_windows: bool
        +is_linux: bool
        +is_macos: bool
        +log_paths: dict
    }

    class LogMonitor {
        +paths: List~str~
        +interval: int
        +parser: AutoDetectParser
        +analyzer: AnomalyDetector
        +handler: LogFileHandler
        +observer: Observer
        +start(callback)
        +stop()
        +get_stats() dict
    }

    class LogFileHandler {
        +paths: List~Path~
        +last_positions: dict
        +last_entry_counts: dict
        +on_modified(event)
        -_process_file(filepath)
        +start()
        +stop()
    }

    LogAnalysisAgent --> LLMEngine
    LogAnalysisAgent --> AnomalyDetector
    LogAnalysisAgent --> AutoDetectParser
    LogAnalysisAgent --> SystemConfig
    AuthenticationAgent --> LLMEngine
    NetworkMonitoringAgent --> LLMEngine
    VulnerabilityAnalysisAgent --> LLMEngine
    SuperAgent --> LLMEngine
    AnomalyDetector --> Anomaly
    AnomalyDetector --> PatternMatcher
    AutoDetectParser --> LogEntry
    LogMonitor --> LogFileHandler
    LogMonitor --> AnomalyDetector
    LogMonitor --> AutoDetectParser
```

---

## 3. Parser Auto-Detection Pipeline

The `AutoDetectParser` inspects file extension and content to route to the correct format-specific parser. All parsers yield `LogEntry` objects.

```mermaid
graph TD
    FILE["Input File\n(path string)"]
    AD["AutoDetectParser.parse()"]

    FILE --> AD

    AD -->|".evtx extension"| EVTX["EvtxParser\n(Windows Event Log)"]
    AD -->|"W3C header / .log + IIS pattern"| IIS["IISParser\n(IIS W3C access log)"]
    AD -->|"JSON lines"| JSON["JsonLogParser\n(newline-delimited JSON)"]
    AD -->|"RFC3164 syslog pattern"| SYS["SyslogParser\n(Linux auth/syslog)"]
    AD -->|"fallback"| TXT["SimpleTextParser\n(plain text)"]

    EVTX & IIS & JSON & SYS & TXT --> LE["LogEntry\n{timestamp, level, source, message, raw, parsed_fields}"]

    LE --> FILTER["LogAnalysisAgent._filter_timeframe()\n(discard entries outside window;\nfallback: keep all if window empties set)"]
    FILTER --> ANOMALY["AnomalyDetector.analyze()"]
```

---

## 4. Anomaly Detection Pipeline

`AnomalyDetector.analyze()` runs 10 sequential detection passes over the filtered `LogEntry` list and collects `Anomaly` objects.

```mermaid
graph TD
    ENTRIES["List[LogEntry]"]
    BL["_update_baseline()\nbuilds login_attempts_per_hour,\nerror_rate, unique_ips/users,\nhourly_events"]

    ENTRIES --> BL

    BL --> D1["_detect_brute_force()\nthreshold: 5 failed logins / IP"]
    BL --> D2["_detect_off_hours_activity()\n10 PM – 6 AM window"]
    BL --> D3["_detect_rapid_requests()\n5+ requests in <2 s / IP"]
    BL --> D4["_detect_error_spikes()\nerror rate > 3× baseline"]
    BL --> D5["_detect_privilege_escalation()\nprivilege assign / sudo patterns"]
    BL --> D6["_detect_suspicious_processes()\nknown-bad process names"]
    BL --> D7["_detect_data_exfiltration()\nlarge outbound / unusual destinations"]
    BL --> D8["_detect_log_gaps()\nsilence > 1 hour"]
    BL --> D9["_detect_unusual_auth_patterns()\nPatternMatcher regex rules"]
    BL --> D10["_detect_attack_patterns()\nSQLi / XSS / path traversal patterns"]

    D1 & D2 & D3 & D4 & D5 & D6 & D7 & D8 & D9 & D10 --> MERGE["Merged List[Anomaly]"]

    MERGE --> SEV["LogAnalysisAgent._filter_by_severity()\ndrops below threshold (LOW/MED/HIGH/CRIT)"]
    SEV --> OUT["Filtered List[Anomaly]\n→ JSONFormatter / LLM summary"]
```

---

## 5. LLM Engine Internals

```mermaid
graph TD
    CALL["LLMEngine.query(prompt, agent_type)"]

    CALL --> TOKENLOOKUP["MAX_TOKENS lookup\nsuper_agent=700\nlog_analysis=500\nanomaly_detector=300\nvuln_analysis=300\ndefault=400"]

    TOKENLOOKUP --> PROVIDERCHECK{LLM_PROVIDER env var}

    PROVIDERCHECK -->|"local"| OLLAMA["_query_local()\nPOST localhost:11434/api/generate\nmodel: LOCAL_MODEL\nstream: false\ntimeout: 300s"]

    PROVIDERCHECK -->|"google"| GEMINI["_query_google()\ngoogle.generativeai\ngemini-1.5-flash\nmax_output_tokens=cap"]

    PROVIDERCHECK -->|"openrouter"| OR["_query_openrouter()\nOpenRouter API\nmodel from model_config[agent_type]\nor OPENROUTER_MODEL env"]

    OR --> RETRY["Retry loop (max 3)\nexponential backoff: 5s → 10s → 20s\non 429 / 503"]
    RETRY --> ORAPI["POST openrouter.ai/api/v1/chat/completions"]

    OLLAMA & GEMINI & ORAPI --> RESP["str response\n(or error string)"]
```

---

## 6. DataCollector Methods

| Method | Command / source | Returns | Limit |
|---|---|---|---|
| `get_network_context()` | `netstat -ano` (Windows) | LISTENING + ESTABLISHED lines | Top 50 lines |
| `get_vulnerability_context()` | `tasklist /NH /FO CSV` + `platform` | OS info + unique process names | Top 40 processes |
| `get_auth_context(log_findings)` | Filters `List[dict]` from log scan | Auth-related finding strings | Top 20 findings |

Auth-related finding types matched: `brute_force_attempt`, `login_failure`, `login_success`, `off_hours_login`, `off_hours_activity`, `high_failure_ratio`, `privilege_escalation`, `privilege_assign`.

---

## 7. Config — OS Log Path Discovery

`get_system_config()` calls `_get_log_paths(system)` based on `platform.system()`:

| OS | Log paths auto-discovered |
|---|---|
| Windows | `Security.evtx`, `System.evtx`, `Application.evtx`, `Setup.evtx`, IIS `W3SVC1/` |
| Linux | `auth.log`, `syslog`, `secure`, `messages`, `kern.log`, Apache, MySQL, fail2ban |
| macOS | `system.log`, `secure.log`, `/var/log/asl/` |

`get_available_log_files()` stats each path — returns `status: "success"` or `"failed"` per path.

---

## 8. Severity Levels

| Level | Integer rank | Meaning |
|---|---|---|
| `LOW` | 0 | Informational / weak signal |
| `MEDIUM` | 1 | Suspicious, warrants review |
| `HIGH` | 2 | Active attack indicator |
| `CRITICAL` | 3 | Confirmed breach / immediate action required |

The `--severity` flag sets the minimum rank; findings below it are discarded before the AI summary and output.
