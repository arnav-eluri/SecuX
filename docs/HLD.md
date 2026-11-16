# SecuX — High-Level Design

## 1. Overview

SecuX is a CLI-based, AI-driven security orchestration tool. A single command (`secux audit`) spins up a network of four specialist AI agents in parallel, correlates their findings through a Super-Agent, and produces a prioritised incident report (SITREP) from raw system logs and live OS telemetry — all locally, with no data leaving the machine.

---

## 2. System Architecture

```mermaid
graph TB
    User(["👤 Operator"])

    subgraph CLI ["CLI Layer  (src/secux/cli.py)"]
        CMD_AUDIT["secux audit"]
        CMD_LOGSCAN["secux logscan"]
        CMD_STANDALONE["secux auth-scan\nnetwork-scan\nvuln-scan"]
    end

    subgraph ORCHESTRATOR ["Orchestrator  (run_full_audit)"]
        PHASE1["Phase 1 — Parallel Data Collection\n(ThreadPoolExecutor × 3)"]
        PHASE15["Phase 1.5 — Auth Context\n(sequential)"]
        PHASE2["Phase 2 — Parallel AI Analysis\n(ThreadPoolExecutor × 4)"]
        PHASE3["Phase 3 — Super-Agent Correlation\n(sequential)"]
    end

    subgraph AGENTS ["Specialist Agents"]
        LA["LogAnalysisAgent\n(src/secux/Log_Analysis_Agent/)"]
        AA["AuthenticationAgent\n(src/secux/Authentication_Agent/)"]
        NM["NetworkMonitoringAgent\n(src/secux/Network_Monitoring_Agent/)"]
        VA["VulnerabilityAnalysisAgent\n(src/secux/Vulnerability_Analysis_Agent/)"]
        SA["SuperAgent\n(src/secux/Super_Agent/)"]
    end

    subgraph INFRA ["Infrastructure"]
        LLM["LLMEngine\n(src/secux/llm_engine.py)"]
        CFG["SystemConfig\n(src/secux/config.py)"]
        COL["DataCollector\n(src/secux/collector.py)"]
        MON["LogMonitor\n(src/secux/monitor.py)"]
    end

    subgraph DATASOURCES ["Data Sources"]
        LOGS["System Log Files\n(.evtx / syslog / IIS / JSON)"]
        NET["Live Network State\n(netstat -ano)"]
        SYS["Running Processes\n(tasklist / platform)"]
    end

    subgraph LLMPROVIDERS ["LLM Providers"]
        OLLAMA["Local — Ollama\n(llama3.2:3b)"]
        OPENROUTER["OpenRouter\n(qwen/qwen3.7-flash)"]
        GEMINI["Google Gemini\n(gemini-1.5-flash)"]
    end

    User --> CMD_AUDIT
    User --> CMD_LOGSCAN
    User --> CMD_STANDALONE

    CMD_AUDIT --> ORCHESTRATOR
    CMD_LOGSCAN --> LA
    CMD_STANDALONE --> AA & NM & VA

    PHASE1 --> LA & COL
    PHASE15 --> COL
    PHASE2 --> AA & NM & VA & LA
    PHASE3 --> SA

    LA --> LLM
    AA --> LLM
    NM --> LLM
    VA --> LLM
    SA --> LLM

    LA --> CFG
    CFG --> LOGS
    COL --> NET & SYS

    CMD_LOGSCAN --> MON

    LLM --> OLLAMA
    LLM --> OPENROUTER
    LLM --> GEMINI
```

---

## 3. Agent Network

SecuX runs four specialist agents in parallel (Phase 2). Each agent receives a focused context string and returns structured JSON findings via LLM inference.

```mermaid
graph LR
    subgraph INPUT ["Input Context"]
        I1["Log Findings\n(structured anomalies)"]
        I2["Auth Anomalies\n(filtered from logs)"]
        I3["Network State\n(netstat output)"]
        I4["System Info\n(OS, processes)"]
    end

    subgraph PARALLEL ["Phase 2 — Parallel AI Agents"]
        direction TB
        A1["LogAnalysisAgent\n→ generate_ai_summary()"]
        A2["AuthenticationAgent\n→ analyze()"]
        A3["NetworkMonitoringAgent\n→ analyze()"]
        A4["VulnerabilityAnalysisAgent\n→ analyze()"]
    end

    subgraph OUTPUT ["Super-Agent"]
        SA["SuperAgent.analyze()\n→ SITREP"]
    end

    I1 --> A1
    I2 --> A2
    I3 --> A3
    I4 --> A4

    A1 & A2 & A3 & A4 --> SA
    SA --> SITREP["Prioritised Incident Report\n(THREAT LEVEL · ATTACK CHAIN · IOCs · ACTIONS)"]
```

---

## 4. LLM Abstraction

The `LLMEngine` provides a single `.query(prompt, agent_type)` interface over three pluggable backends, selected by the `LLM_PROVIDER` environment variable.

| Provider | Env var | Default model | Token cap (super_agent) |
|---|---|---|---|
| `local` | `LOCAL_MODEL`, `LOCAL_LLM_URL` | `llama3.2:3b` via Ollama | 700 |
| `openrouter` | `OPENROUTER_API_KEY`, `OPENROUTER_MODEL` | `qwen/qwen3.7-flash` | 700 |
| `google` | `GEMINI_API_KEY` | `gemini-1.5-flash` | 700 |

Per-agent token caps enforce cost/latency budgets: `super_agent=700`, `log_analysis=500`, `anomaly_detector=300`, `vuln_analysis=300`.

---

## 5. Data Sources

| Source | Collection method | Used by |
|---|---|---|
| Windows `.evtx` logs | `python-evtx` or `AutoDetectParser` | `LogAnalysisAgent` |
| Linux `/var/log/*` | File read + `SyslogParser` | `LogAnalysisAgent` |
| IIS W3C logs | `IISParser` | `LogAnalysisAgent` |
| Newline-delimited JSON logs | `JsonLogParser` | `LogAnalysisAgent` |
| Active network connections | `netstat -ano` (Windows) | `NetworkMonitoringAgent` |
| Running processes + OS info | `tasklist` + `platform` module | `VulnerabilityAnalysisAgent` |
| Auth anomalies | Filtered from log findings | `AuthenticationAgent` |

Nothing is transmitted to external services — LLM calls go to whichever provider is configured (local by default).

---

## 6. CLI Commands Summary

| Command | Mode | Key behaviour |
|---|---|---|
| `secux audit` | Full parallel orchestration | 3-phase parallel audit → SITREP |
| `secux logscan` | Single scan | Log parse → anomaly detect → JSON report |
| `secux logscan --monitor` | Continuous | Watchdog + polling loop, incremental scan every N seconds |
| `secux auth-scan <data>` | Standalone | Direct `AuthenticationAgent.analyze()` call |
| `secux network-scan <data>` | Standalone | Direct `NetworkMonitoringAgent.analyze()` call |
| `secux vuln-scan <data>` | Standalone | Direct `VulnerabilityAnalysisAgent.analyze()` call |
| `secux logscan --list-logs` | Diagnostic | Lists discovered log files and their status |
