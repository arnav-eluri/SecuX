# SecuX — Data Flow

---

## 1. `secux audit` — Full 3-Phase Parallel Orchestration

```mermaid
sequenceDiagram
    actor User
    participant CLI as cli.py<br/>run_full_audit()
    participant Pool1 as ThreadPool (×3)<br/>Phase 1
    participant LA as LogAnalysisAgent
    participant COL as DataCollector
    participant Pool2 as ThreadPool (×4)<br/>Phase 2
    participant AA as AuthenticationAgent
    participant NM as NetworkMonitoringAgent
    participant VA as VulnerabilityAnalysisAgent
    participant SA as SuperAgent
    participant LLM as LLMEngine

    User->>CLI: secux audit [--timeframe N] [--severity S] [--paths ...]

    note over CLI,Pool1: Phase 1 — Concurrent data collection
    CLI->>Pool1: submit(LogAnalysisAgent.run, skip_ai_summary=True)
    CLI->>Pool1: submit(DataCollector.get_network_context)
    CLI->>Pool1: submit(DataCollector.get_vulnerability_context)

    par parallel
        Pool1->>LA: run(log_paths, skip_ai_summary=True)
        LA->>LA: AutoDetectParser.parse() per file
        LA->>LA: AnomalyDetector.analyze() — 10 detectors
        LA-->>Pool1: log_results {findings, metadata}
    and
        Pool1->>COL: get_network_context()
        COL->>COL: netstat -ano (Windows)
        COL-->>Pool1: net_context (top-50 connections)
    and
        Pool1->>COL: get_vulnerability_context()
        COL->>COL: tasklist /NH /FO CSV + platform info
        COL-->>Pool1: vuln_context (OS + process list)
    end

    note over CLI,COL: Phase 1.5 — Auth context (depends on log results)
    CLI->>COL: get_auth_context(log_results.findings)
    COL->>COL: filter by AUTH_TYPES set<br/>(brute_force, login_failure, privilege_escalation, …)
    COL-->>CLI: auth_context string

    note over CLI,Pool2: Phase 2 — Parallel AI analysis
    CLI->>Pool2: submit(AuthenticationAgent.analyze, auth_context)
    CLI->>Pool2: submit(NetworkMonitoringAgent.analyze, net_context)
    CLI->>Pool2: submit(VulnerabilityAnalysisAgent.analyze, vuln_context)
    CLI->>Pool2: submit(LogAnalysisAgent.generate_ai_summary, findings)

    par parallel
        Pool2->>AA: analyze(auth_context)
        AA->>LLM: query(prompt, agent_type="anomaly_detector")
        LLM-->>AA: JSON findings string
        AA-->>Pool2: auth_results

    and
        Pool2->>NM: analyze(net_context)
        NM->>LLM: query(prompt, agent_type="anomaly_detector")
        LLM-->>NM: JSON findings string
        NM-->>Pool2: net_results

    and
        Pool2->>VA: analyze(vuln_context)
        VA->>LLM: query(prompt, agent_type="vuln_analysis")
        LLM-->>VA: JSON findings string
        VA-->>Pool2: vuln_results

    and
        Pool2->>LA: generate_ai_summary(findings)
        LA->>LLM: query(summary_prompt, agent_type="log_analysis")
        LLM-->>LA: narrative summary
        LA-->>Pool2: log_ai_summary
    end

    note over CLI,SA: Phase 3 — Super-Agent correlation (sequential)
    CLI->>CLI: build summary_context dict<br/>{log_analysis, auth_intelligence,<br/>network_patterns, vulnerabilities}
    CLI->>SA: analyze(summary_context)
    SA->>LLM: query(SITREP_prompt, agent_type="super_agent")
    LLM-->>SA: SITREP string
    SA-->>CLI: final_report

    CLI->>User: Rich console output<br/>(THREAT LEVEL · ATTACK CHAIN · IOCs · ACTIONS)
```

---

## 2. `secux logscan` — Single Scan

```mermaid
sequenceDiagram
    actor User
    participant CLI as cli.py<br/>run_single_scan()
    participant LA as LogAnalysisAgent
    participant PAR as AutoDetectParser
    participant DET as AnomalyDetector
    participant LLM as LLMEngine
    participant FMT as JSONFormatter

    User->>CLI: secux logscan [-t N] [-s LEVEL] [-o FILE] [-p PATH ...]

    CLI->>CLI: resolve output path<br/>(default: output/secux_logscan_YYYYMMDD_HHMMSS.json)
    CLI->>LA: run(log_paths, output_file, append, show_summary)

    LA->>LA: get_system_config() → discover log paths<br/>(if no --paths given)

    loop for each log file
        LA->>PAR: parse(filepath)
        PAR->>PAR: detect format (EVTX / Syslog / IIS / JSON / Text)
        PAR-->>LA: Iterator[LogEntry]
    end

    LA->>LA: _filter_timeframe(entries)<br/>(keep entries within last N hours;<br/>fallback: keep all if window empties)

    LA->>DET: analyze(entries, timeframe_hours)
    DET->>DET: _update_baseline()
    DET->>DET: run 10 detectors
    DET-->>LA: List[Anomaly]

    LA->>LA: _filter_by_severity(findings)<br/>(drop below --severity threshold)

    LA->>LLM: query(summary_prompt, agent_type="log_analysis")
    LLM-->>LA: ai_summary string

    LA->>FMT: format(agent_name, system_config, logs_accessed,<br/>findings, baseline_metrics, timestamps, …)
    FMT-->>LA: result dict

    LA->>FMT: save_to_file(result, output_file, append)
    LA->>FMT: print_summary(result)

    FMT-->>CLI: Rich console tables + file written
    CLI->>User: "Results saved to: output/secux_logscan_...json"
```

---

## 3. `secux logscan --monitor` — Continuous Monitoring

```mermaid
sequenceDiagram
    actor User
    participant CLI as cli.py<br/>run_monitoring()
    participant LA as LogAnalysisAgent
    participant MON as LogMonitor<br/>(monitor.py)
    participant WD as Watchdog Observer<br/>+ LogFileHandler thread
    participant PAR as AutoDetectParser
    participant DET as AnomalyDetector

    User->>CLI: secux logscan --monitor [-i SECONDS] [-t N]

    CLI->>LA: LogAnalysisAgent(timeframe, severity)
    CLI->>CLI: last_scan = now()

    loop every --interval seconds (Ctrl+C to stop)
        CLI->>LA: run_incremental(log_paths, since=last_scan)
        LA->>PAR: parse each file
        LA->>LA: filter entries where timestamp > since
        LA->>LA: _filter_timeframe()
        LA->>DET: analyze(new_entries, timeframe_hours)
        DET-->>LA: List[Anomaly]
        LA-->>CLI: (new_entries, new_findings)

        alt new events detected
            CLI->>CLI: print counts + top-3 finding descriptions
            CLI->>LA: run(full scan, append=True, show_summary=False)
            CLI->>CLI: print "Updated: <output file>"
        end

        CLI->>CLI: last_scan = now()
        CLI->>CLI: sleep(interval)
    end

    User->>CLI: Ctrl+C
    CLI->>User: "Monitoring stopped."

    note over MON,WD: LogMonitor (used by programmatic API, not CLI --monitor)
    note over MON: LogMonitor.start() sets up Watchdog Observer<br/>+ LogFileHandler polling thread
    note over WD: on file growth → parse new lines →<br/>AnomalyDetector → callback(entries, findings)
```

---

## 4. Log Parsing Pipeline — Internal Flow

```mermaid
flowchart TD
    FILE["Log file path\n(str)"]

    AD["AutoDetectParser.parse(filepath)"]

    SNIFF{"can_parse() checks\n(in order)"}

    E1["EvtxParser\n.evtx extension\n→ python-evtx or xml"]
    E2["IISParser\nW3C header or iis/w3c filename\n→ field-delimited columns"]
    E3["JsonLogParser\nfirst non-empty line is valid JSON\n→ json.loads() per line"]
    E4["SyslogParser\nRFC3164 pattern OR\nApache combined/common\n→ regex extraction"]
    E5["SimpleTextParser\nYYYY-MM-DD HH:MM:SS LEVEL MSG\n→ fallback for any .log"]

    LE["LogEntry\n{timestamp: datetime\n level: str\n source: str\n message: str\n raw: str\n parsed_fields: dict\n event_type: str}"]

    TF["_filter_timeframe()\nkeep entries ≥ (now − timeframe_hours)\nfallback: return all if cutoff empties set"]

    AD["AnomalyDetector.analyze()"]
    PM["PatternMatcher\n25 compiled regexes\n(SQLi, XSS, SSH brute, LSASS,\nPowerShell, etc.)"]

    AN["List[Anomaly]\n{finding_id: LA-NNN\n type: str\n severity: LOW→CRITICAL\n confidence: 0.0–1.0\n description: str\n evidence: dict\n timestamp: str\n log_entries: List[str]}"]

    FILE --> AD
    AD --> SNIFF
    SNIFF -->|".evtx"| E1
    SNIFF -->|"W3C header"| E2
    SNIFF -->|"JSON lines"| E3
    SNIFF -->|"syslog / apache"| E4
    SNIFF -->|"fallback"| E5
    E1 & E2 & E3 & E4 & E5 --> LE
    LE --> TF
    TF --> AD
    AD --> PM
    PM -->|"regex match → attack_pattern finding"| AN
    AD -->|"statistical detectors"| AN
```

---

## 5. LLM Query Lifecycle

```mermaid
flowchart TD
    CALL["LLMEngine.query(prompt, agent_type)"]

    TC["Lookup MAX_TOKENS\nsuper_agent → 700\nlog_analysis → 500\nanomaly_detector → 300\nvuln_analysis → 300\ndefault → 400"]

    PC{LLM_PROVIDER\nenv var}

    LOCAL["_query_local()\nPOST localhost:11434/api/generate\nmodel: LOCAL_MODEL\nstream: false\ntimeout: 300s\n→ response.json()['response']"]

    GOOGLE["_query_google()\ngoogle.generativeai\nGenerationConfig(max_output_tokens)\n→ response.text"]

    OR["_query_openrouter()\nmodel = model_config[agent_type]\nor OPENROUTER_MODEL env"]

    ORPOST["POST openrouter.ai/api/v1/chat/completions\nheaders: Authorization, HTTP-Referer, X-Title\nbody: {model, max_tokens, messages}"]

    R429{HTTP 429\nor 503?}

    RETRY["wait Retry-After\n(or backoff: 5s→10s→20s)\nmax 3 attempts"]

    RATELIMITED["return rate-limit error string\n(attempt 3 exhausted)"]

    EXTRACT["choices[0].message.content"]

    RESP["str response returned to agent"]

    CALL --> TC --> PC
    PC -->|"local"| LOCAL
    PC -->|"google"| GOOGLE
    PC -->|"openrouter"| OR

    OR --> ORPOST
    ORPOST --> R429
    R429 -->|"yes, attempt < 3"| RETRY --> ORPOST
    R429 -->|"yes, attempt = 3"| RATELIMITED --> RESP
    R429 -->|"no"| EXTRACT --> RESP

    LOCAL --> RESP
    GOOGLE --> RESP
```

---

## 6. Finding Output Schema

Each `Anomaly` produced by the detector pipeline serialises to this JSON structure (via `JSONFormatter`):

```json
{
  "finding_id": "LA-001",
  "type": "brute_force_attempt",
  "severity": "CRITICAL",
  "confidence": 0.95,
  "description": "12 failed login attempts from 192.168.1.50 targeting root",
  "evidence": {
    "source_ip": "192.168.1.50",
    "target_user": "root",
    "event_count": 12,
    "time_window": "00:03:22"
  },
  "timestamp": "2024-01-15T22:14:33+00:00",
  "log_entries": [
    "Jan 15 22:14:31 host sshd[1234]: Failed password for root from 192.168.1.50 port 54321 ssh2",
    "..."
  ]
}
```

---

## 7. Output File Structure

`secux logscan` writes to `output/secux_logscan_YYYYMMDD_HHMMSS.json`:

```json
{
  "agent": "Log_Analysis_Agent",
  "scan_metadata": {
    "hostname": "...",
    "os": "windows",
    "timeframe_hours": 24,
    "processing_duration_seconds": 3.14,
    "data_volume_mb": 12.5,
    "total_entries_analyzed": 4821
  },
  "logs_accessed": [
    {"path": "...", "size": "5.20 MB", "last_modified": "...", "status": "success"}
  ],
  "access_errors": [],
  "timeframe": {"start": "...", "end": "..."},
  "findings": [ ... ],
  "baseline_metrics": { ... },
  "ai_summary": "THREAT SUMMARY: ..."
}
```

Append mode (`--append`) deduplicates by `finding_id` before writing.
