<p align="center">
  <img src="assets/banner.png" alt="SecuX Banner" width="700">
</p>

<h1 align="center">SecuX</h1>
<p align="center"><b>Multi-Agent Security Audit & Log Analysis System</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10%2B-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-orange.svg" alt="License">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/LLM-OpenRouter%20%7C%20Gemini%20%7C%20Ollama-purple.svg" alt="LLM">
</p>

---

SecuX is a CLI-based, AI-driven security orchestration tool. It runs a network of specialized agents in parallel — Log Analysis, Authentication Intelligence, Network Monitoring, and Vulnerability Assessment — correlates their findings through a Super-Agent, and produces a prioritized incident report (SITREP) from raw system logs.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Detection Coverage](#detection-coverage)
- [Evaluation (F1 Score)](#evaluation-f1-score)
- [Supported Log Formats](#supported-log-formats)
- [Technology Stack](#technology-stack)
- [Legal Disclaimer](#legal-disclaimer)

---

## Features

| Feature | Description |
|:---|:---|
| **Parallel Multi-Agent Audit** | Log, Auth, Network, and Vuln agents run concurrently via `ThreadPoolExecutor` |
| **Super-Agent Correlation** | Synthesizes all agent findings into a cohesive attack narrative |
| **Attack Chain Reconstruction** | Maps Initial Access → Privilege Escalation → Lateral Movement → Exfiltration |
| **Real-time Monitoring** | `--monitor` flag enables continuous log tailing with live anomaly alerts |
| **Pattern Matching** | Regex-based detection of SQLi, XSS, path traversal, command injection, and scanning tools |
| **Vendor-Agnostic LLM** | Plug in OpenRouter, Google Gemini, or a local Ollama model |
| **Structured JSON Output** | Every scan produces a machine-readable report with finding IDs, evidence, and IOCs |
| **F1 Evaluation Harness** | Built-in script to benchmark detection quality against labeled datasets |

---

## Architecture

```
secuxproject/
├── src/
│   └── secux/
│       ├── cli.py                        # Click CLI entry point
│       ├── config.py                     # System config & log path discovery
│       ├── collector.py                  # Real-time system data collection
│       ├── monitor.py                    # Watchdog-based file monitoring
│       ├── llm_engine.py                 # Unified LLM client (OpenRouter / Gemini / Ollama)
│       ├── Log_Analysis_Agent/
│       │   ├── agent.py                  # Orchestrates parsing → detection → AI summary
│       │   ├── parsers/
│       │   │   ├── autodetect.py         # Routes files to the correct parser
│       │   │   ├── syslog.py             # Linux syslog + Apache combined log
│       │   │   ├── evtx.py               # Windows Event Log (.evtx)
│       │   │   ├── iis.py                # IIS W3C extended log
│       │   │   ├── json_log.py           # Structured JSON log
│       │   │   └── simple_text.py        # Fallback plain-text parser
│       │   ├── analyzers/
│       │   │   ├── anomaly.py            # Rule-based anomaly detectors
│       │   │   └── patterns.py           # Regex attack pattern library
│       │   └── output/
│       │       └── json_formatter.py     # Report formatting & Rich terminal output
│       ├── Authentication_Agent/         # Auth-focused LLM analyst
│       ├── Network_Monitoring_Agent/     # Network pattern LLM analyst
│       ├── Vulnerability_Analysis_Agent/ # Vulnerability LLM analyst
│       └── Super_Agent/                  # Correlates all agent outputs → SITREP
├── tests/                                # Pytest unit tests
├── scripts/
│   └── evaluate.py                       # F1 / precision / recall evaluation harness
├── datasets/
│   └── sample_labeled.json               # Minimal labeled dataset for smoke-testing
├── docs/
│   └── BUGS.md                           # Bug tracking
├── setup.py
├── requirements.txt
├── pytest.ini
├── .env.example
└── README.MD
```

**Data flow:**

```
System Logs
    │
    ▼
AutoDetectParser  ──►  AnomalyDetector  ──►  LogAnalysisAgent
                            │
              ┌─────────────┼──────────────┐
              ▼             ▼              ▼
        AuthAgent    NetworkAgent    VulnAgent
              └─────────────┬──────────────┘
                            ▼
                       SuperAgent
                            │
                            ▼
                    SITREP (JSON + Rich terminal)
```

---

## Installation

**Prerequisites:** Python 3.10+, pip

```bash
# 1. Clone the repository
git clone https://github.com/itseluriiiiii/SecuX.git
cd SecuX

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install the secux package
pip install -e .

# 4. (Optional) Google Gemini support
pip install -e ".[google]"

# 5. (Optional) Windows .evtx parsing support
pip install -e ".[evtx]"
```

> If the `secux` command is not found after install (PATH not updated), use:
> ```bash
> python -m secux.cli <command>
> ```

---

## Configuration

Copy `.env.example` to `.env` and set your LLM provider:

```env
# .env

LLM_PROVIDER=openrouter          # local | openrouter | google

# OpenRouter (https://openrouter.ai — many free models available)
OPENROUTER_API_KEY=your_key_here
OPENROUTER_MODEL=meta-llama/llama-3.3-70b-instruct:free

# Local Ollama (no API key needed)
LOCAL_MODEL=llama3.2:3b
LOCAL_LLM_URL=http://localhost:11434/api/generate

# Google Gemini (requires pip install -e ".[google]")
GEMINI_API_KEY=your_key_here
```

The `.env` file is gitignored — it will never be committed.

---

## Usage

### Commands

| Command | Description |
|:---|:---|
| `secux audit` | Full parallel multi-agent audit → SITREP |
| `secux logscan` | Log-only scan with optional real-time monitoring |
| `secux auth-scan <data>` | Targeted authentication analysis |
| `secux network-scan <data>` | Targeted network pattern analysis |
| `secux vuln-scan <data>` | Targeted vulnerability assessment |

### Examples

```bash
# Full audit — last 24 hours, all severities
secux audit

# Full audit — last 48 hours, HIGH+ only, specific log file
secux audit --timeframe 48 --severity HIGH --path /var/log/auth.log

# Log scan — save output to JSON
secux logscan --output report.json

# Log scan — real-time monitoring, 30-second interval
secux logscan --monitor --interval 30

# Log scan — specific file, last 72 hours
secux logscan --paths /var/log/syslog --timeframe 72

# List available log files on this system
secux logscan --list-logs
```

### Output

<p align="center">
  <img src="assets/audit_phases.png" alt="Audit Phases" width="700">
  <img src="assets/audit_phases1.png" alt="Audit Phases continued" width="700">
</p>

A standard SITREP includes:

**Attack Chain Summary** — chronological breakdown:
- Phase 1 (Initial Access): e.g., brute force from `203.0.113.45` targeting `admin`
- Phase 2 (Privilege Escalation): e.g., `chmod 777 /etc/passwd` by user `arnav`
- Phase 3 (C2 Callback): e.g., `unknown.exe` with outbound connection to `185.220.101.x`

**Indicators of Compromise (IOCs):**
- Attacker source IPs and C2 destinations
- Targeted usernames and compromised accounts
- Suspicious process names and listening ports

**Recommended Actions** (priority-ranked):
- 🔴 IMMEDIATE: Block IPs, isolate hosts, revoke sessions
- 🟠 INVESTIGATE: Audit lateral movement paths, review specific log windows
- 🟡 MONITOR: Watch for new outbound connections or privilege grants

<p align="center">
  <img src="assets/sitrep_1.png" alt="SITREP Part 1" width="700">
  <img src="assets/sitrep_2.png" alt="SITREP Part 2" width="700">
</p>

---

## Detection Coverage

The rule-based `AnomalyDetector` covers:

| Detection Type | Method | Trigger |
|:---|:---|:---|
| `brute_force_attempt` | Statistical | ≥5 login failures from same IP |
| `off_hours_login` | Rule | Successful login between 22:00–06:00 |
| `off_hours_activity` | Rule | ≥2 events from same source during off-hours |
| `rapid_requests` | Statistical | ≥5 requests in ≤2 seconds from same IP |
| `error_rate_spike` | Statistical | Hourly error rate > 3× baseline |
| `privilege_escalation` | Event type | `sudo`, `chmod`, `chown`, role changes |
| `malicious_process` | Event type | Suspicious process + outbound C2 connection |
| `suspicious_outbound_connection` | Event type | Outbound connection from unexpected process |
| `data_exfiltration` | Event type | Large transfer to external destination |
| `log_gap` | Temporal | >1 hour silence in log timeline (top 3 gaps) |
| `high_failure_ratio` | Statistical | >75% failure rate across ≥20 auth events |
| `sql_injection` | Regex | UNION SELECT, OR '1'='1', xp_cmdshell, etc. |
| `xss` | Regex | `<script>`, `onerror=`, `javascript:`, etc. |
| `path_traversal` | Regex | `../`, `%2e%2e`, `/etc/passwd`, etc. |
| `command_injection` | Regex | `; cat`, `\| ncat`, `& nc`, `; wget`, etc. |
| `malicious_execution` | Regex | `powershell`, `Invoke-Expression`, `iex`, etc. |
| `reconnaissance` | Regex | `/.git/`, `/.env`, `/admin`, `/wp-login`, etc. |
| `scanning` | Regex | `sqlmap`, `nmap`, `nikto`, `masscan`, `burp` |
| `dos` | Regex | Flood patterns in HTTP logs |

---

## Evaluation (F1 Score)

SecuX ships a lightweight evaluation harness to measure detection quality against any labeled log dataset.

### Running the evaluator

```bash
# Against the included smoke-test dataset
python scripts/evaluate.py datasets/sample_labeled.json

# Verbose — shows per-record expected vs detected
python scripts/evaluate.py datasets/my_dataset.json --verbose

# Save results to JSON
python scripts/evaluate.py datasets/my_dataset.json --out results.json
```

### Dataset format

```json
{
  "entries": [
    {
      "raw": "<34>Oct 15 10:30:45 server sshd[1234]: Failed password for admin from 192.168.1.100",
      "source": "auth.log",
      "expected_types": ["brute_force_attempt"]
    },
    {
      "raw": "192.168.1.50 - - [15/Oct/2024:14:30:00 +0000] \"GET /index.php?id=1' OR '1'='1 HTTP/1.1\" 200 1234",
      "source": "access.log",
      "expected_types": ["sql_injection"]
    },
    {
      "raw": "192.168.1.1 - - [15/Oct/2024:09:00:00 +0000] \"GET /api/status HTTP/1.1\" 200 64",
      "source": "access.log",
      "expected_types": []
    }
  ]
}
```

`expected_types: []` marks a benign entry. Use any detection type from the coverage table above.

### Where to get labeled datasets

The evaluator works with any log dataset you label. These public sources are ready to use:

| Dataset | Format | Attack Types | Link |
|:---|:---|:---|:---|
| **Loghub (LogPAI)** | Plain text (syslog, HDFS, Apache, etc.) | Various system failures & anomalies | [github.com/logpai/loghub](https://github.com/logpai/loghub) |
| **EVTX-ATTACK-SAMPLES** | Windows .evtx | MITRE ATT&CK techniques | [github.com/sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) |
| **Security Datasets** | JSON / EVTX | APT, red-team exercises | [github.com/OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) |
| **CICIDS 2017** | CSV (network + pcap) | DoS, brute force, infiltration, botnets | [unb.ca/cic/datasets](https://www.unb.ca/cic/datasets/ids-2017.html) |
| **UNSW-NB15** | CSV | 9 attack categories + normal traffic | [research.unsw.edu.au/projects/unsw-nb15-dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset) |

**Recommended workflow:**

1. Download **Loghub** (syslog/auth.log format — directly parseable by SecuX)
2. Pick the labeled subset (anomalous vs normal entries are marked)
3. Convert to the SecuX dataset format using the schema above
4. Run `python scripts/evaluate.py your_dataset.json`

> **Note**: An F1 score is not shown here because it depends entirely on which dataset you use. The number only means something relative to a specific corpus. Run the evaluator on your data to get a real, honest figure.

---

## Supported Log Formats

| Parser | Formats | Detection |
|:---|:---|:---|
| `SyslogParser` | Linux `auth.log`, `syslog`, `secure`, `kern.log`; Apache combined/common log | SSH, sudo, service events |
| `EVTXParser` | Windows Event Log `.evtx` | Security, System, Application events |
| `IISParser` | IIS W3C extended log (`u_ex*.log`, `w3svc*`) | HTTP requests, auth failures |
| `JSONLogParser` | Newline-delimited JSON, JSON arrays | Any structured log |
| `SimpleTextParser` | `YYYY-MM-DD HH:MM:SS LEVEL message` | Fallback for plain-text logs |

The `AutoDetectParser` selects the correct parser automatically based on filename. Order of precedence: EVTX → Syslog → IIS → JSON → SimpleText.

---

## Technology Stack

| Layer | Technology |
|:---|:---|
| CLI | Python Click |
| Terminal UI | Rich |
| File monitoring | Watchdog |
| Parallelism | `concurrent.futures.ThreadPoolExecutor` |
| LLM (cloud) | OpenRouter API (Llama 3.3, Qwen, etc.) |
| LLM (cloud) | Google Gemini 1.5 Flash |
| LLM (local) | Ollama (any model) |
| Output | JSON reports |
| Testing | Pytest |

---

## Legal Disclaimer

> [!IMPORTANT]
> **This tool is for authorized security testing and educational purposes only.**
> Usage against systems without prior written consent is illegal and strictly prohibited.
> The developers assume no liability for misuse.
