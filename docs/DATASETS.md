# Labeled Datasets for SecuX Evaluation

This document lists public log datasets you can use with `scripts/evaluate.py` to get real F1/precision/recall numbers.

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
