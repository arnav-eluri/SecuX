# SecuX — Bug Tracker

> **Status**: All 25 tracked bugs are resolved. The table below is preserved as a record of what was found, what was fixed, and when.

---

## Summary Table

| ID | Severity | File | Description | Status |
|----|----------|------|-------------|--------|
| BUG-01 | CRITICAL | `monitor.py` | Typo `dirs_toatch` — NameError, `--monitor` crashes | ✅ Fixed |
| BUG-02 | CRITICAL | `monitor.py` | File seek dead code; parser re-reads full file, generates duplicates | ✅ Fixed |
| BUG-03 | HIGH | `autodetect.py` | Parser order wrong — syslog/auth.log parsed by SimpleText, misses events | ✅ Fixed |
| BUG-04 | HIGH | `iis.py` | `can_parse` matched every `.log` file, swallowed non-IIS logs | ✅ Fixed |
| BUG-05 | HIGH | `cli.py` | Monitor double-write overwrote appended data | ✅ Fixed |
| BUG-06 | HIGH | `setup.py` | `requests` missing from `install_requires` | ✅ Fixed |
| BUG-07 | HIGH | `anomaly.py` | Log gap detector flooded report (one finding per gap, threshold too low) | ✅ Fixed |
| BUG-08 | HIGH | `cli.py` | Rich markup passed to `click.echo` printed as raw text | ✅ Fixed |
| BUG-09 | HIGH | `patterns.py` | `PatternMatcher` (SQLi, XSS, traversal, injection) never called | ✅ Fixed |
| BUG-10 | MEDIUM | `anomaly.py` | Error spike stored `"22:00"` instead of ISO timestamp | ✅ Fixed |
| BUG-11 | MEDIUM | `collector.py` | Windows-only network context returned wrong type on Linux/macOS | ✅ Fixed |
| BUG-12 | MEDIUM | `json_formatter.py` | UI hardcoded "Mistral Small" regardless of configured model | ✅ Fixed |
| BUG-13 | MEDIUM | `agent.py` | `run_incremental` skipped timeframe filter, may reprocess full history | ✅ Fixed |
| BUG-14 | MEDIUM | `requirements.txt` | `google-generativeai` missing; Gemini provider failed at import | ✅ Fixed |
| BUG-15 | LOW | multiple | `datetime.utcnow()` deprecated in Python 3.12+ | ✅ Fixed |
| BUG-16 | LOW | `cli.py`, `json_formatter.py` | Unclosed file objects for Rich console | ✅ Fixed |
| BUG-17 | LOW | `cli.py` | `import json/time` inside `while True` monitoring loop | ✅ Fixed |
| BUG-18 | DOC | `README.MD` | Unresolved git merge conflict markers in README | ✅ Fixed |
| BUG-19 | DOC | `README.MD` | Example used `--timeframe 24h` and `--threshold` (both invalid flags) | ✅ Fixed |
| BUG-20 | SEC | `.env` | `.env` file was git-tracked — API keys in version history | ✅ Fixed |
| BUG-21 | BLOCKER | install | Editable install pointed to wrong repo (`HackSet/backend`) | ✅ Fixed |
| BUG-22 | HIGH | `syslog.py` | Plain syslog files (no `<priority>` prefix) fell through to SimpleTextParser | ✅ Fixed |
| BUG-23 | MEDIUM | `evtx.py`, `simple_text.py` | `datetime.utcnow()` still present in 3 parsers after BUG-15 pass | ✅ Fixed |
| BUG-24 | MEDIUM | `tests/test_secux.py` | `test_detect_off_hours_activity` asserted wrong anomaly type | ✅ Fixed |
| BUG-25 | LOW | `json_log.py` | `datetime.fromtimestamp()` returned naive local time instead of UTC | ✅ Fixed |
| BUG-26 | HIGH | `cli.py` | `sys.path.insert(0, .../src)` loaded vendored `src/rich` instead of installed version — UnicodeEncodeError on banner | ✅ Fixed |

---

## Detailed Fix Record

---

### BUG-01 · Typo `dirs_toatch` — NameError in `LogMonitor.start()`

**File**: `src/secux/monitor.py`  
**Fix**: Renamed `dirs_toatch` → `dirs_to_watch`.

---

### BUG-02 · File seek dead code in monitor incremental parser

**File**: `src/secux/monitor.py`  
**Fix**: Removed the `f.seek(last_pos)` dead code. The monitor now tracks entry counts per file and slices only new entries from the parsed list, preventing duplicate findings.

---

### BUG-03 · Parser order: SimpleTextParser ran before SyslogParser

**File**: `src/secux/Log_Analysis_Agent/parsers/autodetect.py`  
**Fix**: Reordered parsers — EVTXParser, SyslogParser, IISParser, JSONLogParser, SimpleTextParser (most-specific first). SimpleTextParser is now the last-resort fallback.

---

### BUG-04 · `IISParser.can_parse()` matched every `.log` file

**File**: `src/secux/Log_Analysis_Agent/parsers/iis.py`  
**Fix**: Removed the `endswith('.log')` branch. IIS files are now identified by `iis` / `w3svc` in the path or `u_ex` in the basename only.

---

### BUG-05 · Double-write in `--monitor` loop overwrote appended data

**File**: `src/secux/cli.py`  
**Fix**: Removed the second `with open(output, 'w')` block. `agent.run()` already handles saving with `append=True`.

---

### BUG-06 · `requests` missing from `setup.py` `install_requires`

**File**: `setup.py`  
**Fix**: Added `"requests>=2.31.0"` to `install_requires`.

---

### BUG-07 · Log gap detector flooded report

**File**: `src/secux/Log_Analysis_Agent/analyzers/anomaly.py`  
**Fix**: Raised `LOG_GAP_THRESHOLD_SECONDS` from 300 (5 min) to 3600 (1 hour). Added a cap of 3 gap findings per analysis run (the 3 largest gaps only).

---

### BUG-08 · Rich markup in `click.echo` printed as raw text

**File**: `src/secux/cli.py`  
**Fix**: Replaced `click.echo(f"[#00B7B5]...[/#00B7B5]")` with `Console().print(...)` throughout.

---

### BUG-09 · `PatternMatcher` never called

**File**: `src/secux/Log_Analysis_Agent/analyzers/anomaly.py`, `patterns.py`  
**Fix**: Added `_detect_attack_patterns()` to `AnomalyDetector.analyze()`. It runs `PatternMatcher.match()` against each entry's raw text, activating SQLi, XSS, path traversal, command injection, PowerShell, service modification, and UNSW-NB15 network flow detection.

---

### BUG-10 · Error spike stored time string instead of ISO timestamp

**File**: `src/secux/Log_Analysis_Agent/analyzers/anomaly.py`  
**Fix**: Replaced `timestamp=f"{hour:02d}:00"` with a proper `datetime(..., tzinfo=timezone.utc).isoformat()` construction.

---

### BUG-11 · Windows-only `get_network_context()` returned wrong type on Linux/macOS

**File**: `src/secux/collector.py`  
**Fix**: Changed the non-Windows branch to return `None`. All callers use `(net_results or "No network data available...")` to handle `None` gracefully.

---

### BUG-12 · AI INSIGHTS panel hardcoded "Mistral Small"

**File**: `src/secux/Log_Analysis_Agent/output/json_formatter.py`  
**Fix**: Changed the label to `[bold purple]AI INSIGHTS[/bold purple]` with no model name, since the model is configurable per `.env`.

---

### BUG-13 · `run_incremental` skipped timeframe filter

**File**: `src/secux/Log_Analysis_Agent/agent.py`  
**Fix**: Added a `_filter_timeframe()` call inside `run_incremental` after the `since`-based filtering pass.

---

### BUG-14 · `google-generativeai` missing from dependencies

**File**: `setup.py`  
**Fix**: Added to `extras_require`: `"google": ["google-generativeai>=0.4.0"]`. Install with `pip install -e ".[google]"`.

---

### BUG-15 · `datetime.utcnow()` deprecated

**Files**: Multiple  
**Fix**: Initial pass replaced the most visible occurrences with `datetime.now(timezone.utc)`. BUG-23 completed the remaining parsers.

---

### BUG-16 · Unclosed file objects for Rich console

**File**: `src/secux/cli.py`, `json_formatter.py`  
**Fix**: Replaced `Console(file=open(...))` patterns with `Console(force_terminal=True)` which does not create an extra file object.

---

### BUG-17 · `import json/time` inside `while True` loop

**File**: `src/secux/cli.py`  
**Fix**: Moved both imports to the top-level import block.

---

### BUG-18 · Unresolved git merge conflict in README

**File**: `README.MD`  
**Fix**: Resolved conflict markers; merged both sides into a single coherent document.

---

### BUG-19 · README used invalid `--timeframe 24h` and `--threshold` flags

**File**: `README.MD`  
**Fix**: Corrected all examples to use `--timeframe 24` (integer) and `--severity` (the correct flag name).

---

### BUG-20 · `.env` file git-tracked

**Fix**: Added `**/.env` to `.gitignore`. Ran `git rm --cached .env` to remove it from tracking without deleting the local file.

---

### BUG-21 · Editable install pointed to wrong repo

**Symptom**: `pip show secux` showed `Editable project location: C:\...\HackSet\backend` — a completely different project. Tests failed with `ModuleNotFoundError: No module named 'secux'`.  
**Fix**: Ran `pip install -e .` from this project's root directory to replace the stale install.

---

### BUG-22 · Plain syslog files bypassed `SyslogParser`

**File**: `src/secux/Log_Analysis_Agent/parsers/syslog.py`  
**Root cause**: `SYSLOG_REGEX` required `<priority>` prefix (`<34>`). Files like `OpenSSH_2k.log` use standard syslog format without it. `SyslogParser.can_parse()` also only matched by filename keywords (`syslog`, `auth.log`, etc.), so `OpenSSH_2k.log` fell through to `SimpleTextParser` where all entries became `event_type="unknown"` — brute-force, off-hours, and privilege-escalation detectors got zero hits.

**Fix**:
1. Made `<priority>` optional in `SYSLOG_REGEX`: `r'^(?:<(?P<priority>\d+)>)?...'`
2. Extended `can_parse()` to content-sniff `.log` files — peeks at the first non-comment line and returns `True` if it matches the syslog regex.

**Result**: `OpenSSH_2k.log` now correctly routes to `SyslogParser` and yields 2,000 structured entries (`login_failure: 1,257`, `error: 133`, `generic: 565`, etc.) instead of 2,000 `unknown` events.

---

### BUG-23 · `datetime.utcnow()` remaining in three parsers

**Files**: `src/secux/Log_Analysis_Agent/parsers/evtx.py:84`, `simple_text.py:40`, `simple_text.py:128`  
**Fix**: Added `from datetime import datetime, timezone` imports where missing; replaced all three `datetime.utcnow()` calls with `datetime.now(timezone.utc)`.

---

### BUG-24 · Test asserted wrong off-hours anomaly type

**File**: `tests/test_secux.py:194`  
**Root cause**: `_detect_off_hours_activity` fires `off_hours_login` for `login_success` events (key added to `seen_single_logins`), which blocks `off_hours_activity` from firing for the same key. The test fed 4 `login_success` entries from one IP and checked for `off_hours_activity`, which was never emitted.  
**Fix**: Changed assertion from `a.type == "off_hours_activity"` to `a.type == "off_hours_login"`.

---

### BUG-25 · `JSONLogParser` naive local-time timestamps from Unix epochs

**File**: `src/secux/Log_Analysis_Agent/parsers/json_log.py:79-81`  
**Fix**: Added `tz=timezone.utc` to both `datetime.fromtimestamp()` calls so Unix timestamps are interpreted as UTC, not local system time.

---

### BUG-26 · `sys.path.insert` loaded vendored `src/rich` over installed version

**File**: `src/secux/cli.py`  
**Root cause**: `sys.path.insert(0, str(Path(__file__).parent.parent))` put `src/` at the front of `sys.path`. The `src/` directory contains vendored copies of all dependencies (including an old `rich`). This made Python import `src/rich` instead of the properly installed `rich>=13`, which crashed on the box-drawing characters in the ASCII banner with `UnicodeEncodeError: 'charmap' codec can't encode characters`.  
**Fix**: Removed the `sys.path.insert` line entirely. The package is correctly installed via `pip install -e .`, so no manual path manipulation is needed.
