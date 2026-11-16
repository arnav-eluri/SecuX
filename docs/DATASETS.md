# SecuX Datasets & Data Collection

## Where does SecuX get its data?

SecuX reads from two sources: **live system data** collected at runtime, and **log files** you point it at (or that it auto-discovers).

### Live data collected at runtime (`audit` mode)

| Agent | Collection method | Data collected |
|:---|:---|:---|
| Network Monitoring | `netstat -ano` (Windows) | Active TCP/UDP connections, listening ports, associated PIDs |
| Vulnerability Analysis | `tasklist` + `platform` module | Running process names, OS version, architecture |
| Authentication Intelligence | Log scan results (filtered) | Auth-related anomalies extracted from the log parse phase |

Nothing is sent to any external service. All collection happens locally via standard OS commands.

### Log file auto-discovery

When no `--paths` flag is given, SecuX looks for logs in standard system locations:

**Windows** — `C:\Windows\System32\winevt\Logs\Security.evtx`, `System.evtx`, `Application.evtx`, `Setup.evtx`
> Requires Administrator privileges or the `python-evtx` library (`pip install -e ".[evtx]"`).

**Linux** — `/var/log/auth.log`, `/var/log/syslog`, `/var/log/secure`, `/var/log/messages`, Apache/MySQL/fail2ban logs

**macOS** — `/var/log/system.log`, `/var/log/secure.log`

Use `secux logscan --list-logs` to see which paths exist and are readable on the current machine.

### Targeting specific files

```bash
secux logscan --paths /var/log/auth.log
secux logscan --paths file1.log --paths file2.evtx --paths file3.json
```

Supported formats: Linux syslog (RFC3164), Windows `.evtx`, IIS W3C, newline-delimited JSON, plain-text. The parser is auto-detected.

---

## Bundled datasets in `datasets/`

These are **public research datasets** used to test and benchmark the detection engine — not live system data. They are read locally like any log file and are never uploaded anywhere.

| File | Purpose |
|:---|:---|
| `OpenSSH_2k.log` | Quick demo and smoke test — `secux logscan --paths datasets/OpenSSH_2k.log` |
| `OpenSSH_2k.log_structured.csv` | Ground truth labels for F1 benchmarking |
| `empire_mimikatz_*.json` | Windows red-team dataset for detection rule testing |
| `cmd_service_mod_fax_*.json` | Windows service hijack dataset for detection rule testing |
| `UNSW-NB15_*.csv` | Network flow research corpus (future ML training) |
| `secux_training_labeled.json` | 48-entry hand-labeled eval harness — `python scripts/evaluate.py` |

---

## Public datasets for further evaluation

This section lists public log datasets you can use with `scripts/evaluate.py` to get real F1/precision/recall numbers.

## Recommended (log format — directly parseable)

### 1. Loghub (LogPAI)
- **URL**: https://github.com/logpai/loghub
- **Formats**: syslog, auth.log, Apache, SSH, HDFS, Android, Windows
- **Why**: Large collection of real system logs with labeled anomalies. The SSH and Linux auth subsets map directly to SecuX's syslog parser.
- **How to use**: Download the SSH or Linux subset, label each line with `expected_types` based on the provided anomaly ground truth, save as SecuX dataset JSON.

### 2. EVTX-ATTACK-SAMPLES
- **URL**: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- **Formats**: Windows .evtx
- **Why**: Real attack event logs mapped to MITRE ATT&CK techniques. Good for testing the EVTX parser and privilege escalation detection.

### 3. Security Datasets (OTRF)
- **URL**: https://github.com/OTRF/Security-Datasets
- **Formats**: JSON, EVTX
- **Why**: Red-team and APT simulation datasets with detailed attack annotations. Covers credential theft, lateral movement, and C2.

## Network/CSV format (requires conversion)

### 4. CICIDS 2017
- **URL**: https://www.unb.ca/cic/datasets/ids-2017.html
- **Formats**: CSV (pre-extracted features) + raw PCAP
- **Why**: Widely cited IDS benchmark. Covers DoS, DDoS, brute force, web attacks, and infiltration.
- **Note**: CSV features are already extracted — you would need to map them to SecuX detection types manually.

### 5. UNSW-NB15
- **URL**: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- **Formats**: CSV
- **Why**: 9 labeled attack categories (Fuzzers, Analysis, Backdoor, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms) plus normal traffic.

## Converting to SecuX dataset format

```python
# Example: convert a CSV with columns [raw_log, label] to SecuX format
import json, csv

TYPE_MAP = {
    "brute_force": "brute_force_attempt",
    "sql_injection": "sql_injection",
    "normal": None,  # None → benign
}

entries = []
with open("source.csv") as f:
    for row in csv.DictReader(f):
        label = TYPE_MAP.get(row["label"])
        entries.append({
            "raw": row["raw_log"],
            "source": row.get("source", "unknown"),
            "expected_types": [label] if label else []
        })

with open("datasets/my_dataset.json", "w") as f:
    json.dump({"entries": entries}, f, indent=2)
```

Then run:
```bash
python scripts/evaluate.py datasets/my_dataset.json
```
