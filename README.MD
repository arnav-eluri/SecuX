<p align="center">
  <img src="assets/banner.png" alt="SecuX Banner" width="700">
</p>

<h1 align="center">SecuX</h1>
<p align="center"><b>Multi-Agent Security Audit & Log Analysis System</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10%2B-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/tests-16%20passed-brightgreen.svg" alt="Tests">
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
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Detection Coverage](#detection-coverage)
- [Datasets](#datasets)
- [Evaluation (F1 Score)](#evaluation-f1-score)
- [Supported Log Formats](#supported-log-formats)
- [Technology Stack](#technology-stack)
- [License](#license)
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
| **Auto-detecting Syslog Parser** | Content-sniffs `.log` files to route plain syslog (RFC3164 without priority prefix) correctly |
| **Vendor-Agnostic LLM** | Plug in OpenRouter, Google Gemini, or a local Ollama model |
| **Structured JSON Output** | Every scan produces a machine-readable report with finding IDs, evidence, and IOCs |
| **F1 Evaluation Harness** | Built-in script to benchmark detection quality against labeled datasets |
| **One-Command Setup** | `run.bat` / `run.sh` installs everything and launches the CLI in a single step |

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
│       │   │   ├── syslog.py             # Linux syslog + Apache; content-sniffs .log files
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
├── tests/
│   └── test_secux.py                     # Pytest unit tests (16 tests, all passing)
├── scripts/
│   └── evaluate.py                       # F1 / precision / recall evaluation harness
├── datasets/
│   ├── OpenSSH_2k.log                    # LogHub — 2k real SSH brute force log lines
│   ├── OpenSSH_2k.log_structured.csv     # Same data with pre-parsed EventId labels
│   ├── empire_mimikatz_*.json            # OTRF — Mimikatz/Empire red-team (6,026 records)
│   ├── cmd_service_mod_fax_*.json        # OTRF — Fax service hijack via cmd.exe (437 records)
│   ├── UNSW-NB15_1–4.csv                 # UNSW-NB15 — 2.5M network flow records
│   ├── NUSW-NB15_GT.csv                  # UNSW-NB15 ground truth (321,283 labeled attacks)
│   └── secux_training_labeled.json       # Hand-labeled evaluation dataset (48 entries)
├── docs/
│   ├── BUGS.md                           # Bug tracking — all 25 bugs resolved
│   └── DATASETS.md                       # Dataset documentation & format guide
├── run.bat                               # Windows one-command setup & launch
├── run.sh                                # Bash one-command setup & launch
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

## Quick Start

The fastest way to get running — no manual steps:

```bat
# Windows — PowerShell or CMD (double-click also works)
.\run.bat
```

```bash
# Linux / macOS / Git Bash terminal
bash run.sh
```

> **Windows PowerShell users:** use `.\run.bat`. Running `bash run.sh` in PowerShell invokes WSL bash, which will fail if WSL is not fully configured. `run.bat` does the exact same steps natively.

Both scripts: verify Python, install all dependencies, install the `secux` package, and launch the CLI with the full banner and command list.

---

## Installation

**Prerequisites:** Python 3.10+, pip

```bash
# 1. Clone the repository
git clone https://github.com/itseluriiiiii/SecuX.git
cd SecuX

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install the secux package (editable)
pip install -e .

# 4. (Optional) Google Gemini support
pip install -e ".[google]"

# 5. (Optional) Windows .evtx parsing support
pip install -e ".[evtx]"
```

> If the `secux` command is not found after install, use:
> ```bash
> python -m secux.cli <command>
> ```

---

## Configuration

Copy `.env.example` to `.env` and set your LLM provider. Scanning works without an LLM configured — the AI summary panel is skipped gracefully. An LLM is only needed for the narrative analysis in `logscan` and `audit`.

```env
# .env

LLM_PROVIDER=openrouter          # local | openrouter | google

# OpenRouter (https://openrouter.ai — free models available)
OPENROUTER_API_KEY=your_key_here
OPENROUTER_MODEL=meta-llama/llama-3.3-70b-instruct:free

# Local Ollama (no API key needed)
LOCAL_MODEL=llama3.2:3b
LOCAL_LLM_URL=http://localhost:11434/api/generate

# Google Gemini (requires: pip install -e ".[google]")
GEMINI_API_KEY=your_key_here
```

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
| `secux help` | Show help and all options |

### Examples

```bash
# Scan the included OpenSSH sample dataset (no LLM needed)
secux logscan --paths datasets/OpenSSH_2k.log

# Full audit on a specific file — last 48 hours, HIGH+ only
secux audit --timeframe 48 --severity HIGH --paths /var/log/auth.log

# Log scan — save output to JSON
secux logscan --output report.json

# Log scan — real-time monitoring, 30-second interval
secux logscan --monitor --interval 30

# Log scan — specific file, last 72 hours
secux logscan --paths /var/log/syslog --timeframe 72

# See what log files are auto-detected on this system
secux logscan --list-logs

# Run the test suite
python -m pytest tests/ -v
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
- IMMEDIATE: Block IPs, isolate hosts, revoke sessions
- INVESTIGATE: Audit lateral movement paths, review specific log windows
- MONITOR: Watch for new outbound connections or privilege grants

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
| `log_gap` | Temporal | >1 hour silence in log timeline (top 3 gaps reported) |
| `high_failure_ratio` | Statistical | >75% failure rate across ≥20 auth events |
| `sql_injection` | Regex | UNION SELECT, OR '1'='1', xp_cmdshell, etc. |
| `xss` | Regex | `<script>`, `onerror=`, `javascript:`, etc. |
| `path_traversal` | Regex | `../`, `%2e%2e`, `/etc/passwd`, etc. |
| `command_injection` | Regex | `; cat`, `\| ncat`, `& nc`, `; wget`, etc. |
| `malicious_execution` | Regex | `powershell`, `Invoke-Expression`, `iex`, encoded commands |
| `service_modification` | Regex | `sc.exe create`, service registry writes, malicious `binpath=` |
| `reconnaissance` | Regex | `/.git/`, `/.env`, `/admin`, `/wp-login`, nmap, nikto, etc. |
| `scanning` | Regex | `sqlmap`, `nmap`, `nikto`, `masscan`, `burp` |
| `dos` | Regex | Flood patterns in HTTP logs |

---

## Datasets

The `datasets/` folder contains the real public log data SecuX was built and evaluated against. All files are from open security research repositories.

| File | Source | Records | Type |
|:---|:---|:---:|:---|
| `OpenSSH_2k.log` | [LogPAI/loghub](https://github.com/logpai/loghub) | 2,000 | Linux syslog — real SSH brute force campaign |
| `OpenSSH_2k.log_structured.csv` | [LogPAI/loghub](https://github.com/logpai/loghub) | 2,000 | Same data, pre-parsed with EventId labels |
| `empire_mimikatz_logonpasswords_*.json` | [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) | 6,026 | Windows Sysmon + Security events — Mimikatz/Empire red-team |
| `cmd_service_mod_fax_*.json` | [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) | 437 | Windows Sysmon + Security events — Fax service hijack via cmd.exe |
| `UNSW-NB15_1–4.csv` | [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) | 2,540,047 | Network flow records — 9 attack categories + normal traffic |
| `NUSW-NB15_GT.csv` | [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) | 321,283 | Ground truth labels (attack category, protocol, source/dest IPs) |
| `UNSW-NB15_LIST_EVENTS.csv` | [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) | — | Event type descriptions for all 49 feature columns |
| `secux_training_labeled.json` | Derived from SSH + OTRF | 48 | Hand-labeled evaluation dataset (33 attack, 15 benign) |

### Key findings per dataset

**OpenSSH_2k.log** — 990 brute force events across 5 attacker IPs (`5.36.59.76`, `52.80.34.196`, `202.100.179.208`, `173.234.31.186`, `112.95.230.3`). Top patterns: `Failed password` (383), `pam_unix authentication failure` (494), `POSSIBLE BREAK-IN ATTEMPT` / rDNS mismatch (85).

**empire_mimikatz** — Mimikatz `sekurlsa::logonpasswords` via Empire C2 on user `pgustavo`. Key IOCs: `powershell.exe → lsass.exe` with `GrantedAccess 0x1010/0x2000`, `SeDebugPrivilege` assigned (EventID 4672), encoded PowerShell stager (`-encodedcommand`), `whoami`/`net`/`ipconfig` recon from PowerShell parent.

**cmd_service_mod_fax** — Fax service registry hijack. Key IOCs: `sc.exe create FaxSvc binpath= cmd.exe`, `cmd.exe` writing to `HKLM\...\Services\Fax`, ROT13-encoded UserAssist entry for `powershell.exe` (`JvaqbjfCbjreFuryy`).

**UNSW-NB15** — 2.54M synthetic network flows generated by the IXIA PerfectStorm tool at UNSW. 9 attack categories: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms. Included as training corpus for future ML-based network flow detection. The current rule-based engine is designed for text logs (syslog, Windows Sysmon JSON) — raw network flow CSV records produce 0 detections.

---

## Evaluation (F1 Score)

Two complementary benchmarks: a curated 48-entry harness for per-type regression testing, and a full-dataset run against the complete real SSH log — the primary benchmark.

```bash
python scripts/evaluate.py datasets/secux_training_labeled.json
python scripts/evaluate.py datasets/secux_training_labeled.json --verbose
python scripts/evaluate.py datasets/secux_training_labeled.json --out results.json
```

### Curated eval harness (48 entries — `secux_training_labeled.json`)

Hand-picked representative lines from the SSH and OTRF datasets; used for per-type regression testing.

| Detection Type | TP | FP | FN | F1 |
|:---|:---:|:---:|:---:|:---:|
| `brute_force_attempt` | 12 | 0 | 0 | **100%** |
| `malicious_execution` | 13 | 0 | 0 | **100%** |
| `privilege_escalation` | 6 | 0 | 0 | **100%** |
| `reconnaissance` | 3 | 0 | 0 | **100%** |
| `service_modification` | 5 | 0 | 0 | **100%** |
| **Overall binary** | 33 | 0 | 0 | **100%** |

### Full-dataset benchmark — OpenSSH (primary)

Scored against the complete 2,000-entry SSH log using `OpenSSH_2k.log_structured.csv` as ground truth (1,540 attack lines, 460 benign).

| Metric | Value |
|:---|:---:|
| True Positives | 1,347 |
| False Positives | 2 |
| False Negatives | 193 |
| True Negatives | 460 |
| Precision | **99.9%** |
| Recall | **87.5%** |
| **F1 Score** | **93.3%** |

**FN breakdown** (193 missed lines): E21 `pam_unix(sshd:auth): check pass; user unknown` (135); E7 `error: Received disconnect` (45); E18 `PAM service ignoring max retries` (7). These are secondary events in the brute-force chain, not primary attack indicators.

**FP breakdown** (2): E15 `PAM 1 more authentication failure` — occurs during active brute-force sessions; classified benign only because LogHub's EventId set didn't include E15 in the attack group.

### Supplementary — OTRF Windows Sysmon (recall only)

| Dataset | Entries | Detected | Missed | Recall |
|:---|:---:|:---:|:---:|:---:|
| Mimikatz / Empire OTRF | 6,026 | 5,085 | 941 | **84.4%** |
| cmd_service_mod OTRF | 437 | 322 | 115 | **73.7%** |

### Labeled dataset format

```json
{
  "entries": [
    { "raw": "Dec 10 07:13:43 LabSZ sshd[24227]: Failed password for root from 5.36.59.76 port 42393 ssh2",
      "source": "auth.log", "expected_types": ["brute_force_attempt"] },
    { "raw": "{\"EventID\": 10, \"SourceImage\": \"powershell.exe\", \"TargetImage\": \"lsass.exe\", \"GrantedAccess\": \"0x1010\"}",
      "source": "sysmon.json", "expected_types": ["privilege_escalation", "malicious_execution"] },
    { "raw": "Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu from 119.137.62.142 port 49116 ssh2",
      "source": "auth.log", "expected_types": [] }
  ]
}
```

`expected_types: []` = benign. Use any type from the Detection Coverage table.

---

## Supported Log Formats

| Parser | Formats | Auto-detect Method |
|:---|:---|:---|
| `SyslogParser` | Linux `auth.log`, `syslog`, `secure`, `kern.log`; Apache combined/common log; any `.log` file in RFC3164 format | Filename match **or** content sniff of first non-comment line |
| `EVTXParser` | Windows Event Log `.evtx` | File extension |
| `IISParser` | IIS W3C extended log (`u_ex*.log`, `w3svc*`) | Filename contains `iis`, `w3svc`, or `u_ex` |
| `JSONLogParser` | Newline-delimited JSON, JSON arrays | File extension `.json` or `json` in name |
| `SimpleTextParser` | `YYYY-MM-DD HH:MM:SS LEVEL message` | File extension `.log` or `.txt` (last-resort fallback) |

The `AutoDetectParser` selects the correct parser automatically. Order of precedence: EVTX → Syslog → IIS → JSON → SimpleText.

> **Note on plain syslog files:** Files like `OpenSSH_2k.log` use standard RFC3164 syslog format without the `<priority>` prefix. The `SyslogParser` now auto-detects these by peeking at the first line of any `.log` file and matching against the syslog regex.

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
| Testing | Pytest (16 tests, 100% passing) |

---

## License

SecuX is released under the [MIT License](LICENSE.md). You are free to use, modify, and distribute it for any purpose, including commercial use, with attribution.

---

## Legal Disclaimer

> [!IMPORTANT]
> **This tool is for authorized security testing and educational purposes only.**
> Usage against systems without prior written consent is illegal and strictly prohibited.
> The developers assume no liability for misuse.
