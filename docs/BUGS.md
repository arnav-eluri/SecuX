# SecuX — Bug Report & Fix Guide

> **Scope**: Full codebase audit. Findings are ranked by severity (crash → logic error → missing feature → stale/misleading content).  
> **Frontend verdict**: The React frontend (`Frontend/`) serves no functional purpose for a CLI tool. It is a landing page that bundles the backend as a zip download. It has no connection to the CLI, no API it talks to, and no test coverage. If this project is CLI-only, the entire `Frontend/` directory can be removed.

---

## CRITICAL — Will Crash at Runtime

---

### BUG-01 · Typo causes `NameError` crash in `LogMonitor.start()`

**File**: `Backend/src/secux/monitor.py:146`

```python
# BUG: "dirs_toatch" is not defined — NameError at runtime
dirs_toatch.add(str(p.parent))

# FIX: should be "dirs_to_watch"
dirs_to_watch.add(str(p.parent))
```

**Impact**: Any call to `LogMonitor.start()` with a file path (not a directory) crashes immediately with `NameError: name 'dirs_toatch' is not defined`. The `--monitor` flag in `secux logscan` is completely broken.

---

### BUG-02 · `monitor.py` incremental parser re-reads entire file — seek is dead code

**File**: `Backend/src/secux/monitor.py:56–62`

```python
# BUG: f.seek(last_pos) seeks a local file handle that is NEVER read.
# self.parser.parse(filepath) opens the file from the beginning independently.
with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
    f.seek(last_pos)                       # ← this seek has no effect
    for entry in self.parser.parse(filepath):   # ← opens its own file handle
        ...
```

**Impact**: The file monitor re-parses the entire file on every polling tick, generating duplicate findings for every entry that was already processed. The seek serves no purpose. Any monitored log file will generate growing duplicate alerts until memory is exhausted.

**Fix**: Either pass `last_pos` as an offset to the parser, or read the new bytes directly from the seeked file handle instead of calling `self.parser.parse(filepath)`.

---

## HIGH — Incorrect Behaviour

---

### BUG-03 · Parser order: `SimpleTextParser` intercepts all `.log` files before `SyslogParser`

**File**: `Backend/src/secux/Log_Analysis_Agent/parsers/autodetect.py:14–20`

```python
# BUG: SimpleTextParser is first and matches any .log/.txt file.
# Auth logs like /var/log/auth.log are matched by SimpleTextParser,
# never reaching SyslogParser which has proper syslog+Apache parsing.
self.parsers = [
    SimpleTextParser(),   # matches *.log and *.txt — too broad, runs first
    EVTXParser(),
    IISParser(),          # also matches *.log — same problem
    SyslogParser(),       # never reached for auth.log / syslog / etc.
    JSONLogParser(),
]
```

**Impact**: Linux auth/syslog files are parsed by the wrong parser. Brute-force and privilege-escalation events from real syslog entries are missed because `SimpleTextParser` only recognises its own `YYYY-MM-DD HH:MM:SS LEVEL` format and silently falls through to the "unknown" event type.

**Fix**: Reorder parsers so the most specific ones run first:

```python
self.parsers = [
    EVTXParser(),
    SyslogParser(),
    IISParser(),
    JSONLogParser(),
    SimpleTextParser(),   # last: broadest fallback
]
```

---

### BUG-04 · `IISParser.can_parse()` matches every `.log` file

**File**: `Backend/src/secux/Log_Analysis_Agent/parsers/iis.py:16–19`

```python
def can_parse(self, filepath: str) -> bool:
    name = filepath.lower()
    return ('iis' in filepath.lower() or
            'w3svc' in filepath.lower() or
            filepath.lower().endswith('.log'))  # ← matches EVERY .log file
```

**Impact**: Any log file not matched earlier in the autodetect chain (e.g., a custom `.log`) gets parsed as IIS. IIS parsing will silently skip every line until it finds `#Software:`, meaning 100% of a non-IIS log file is silently swallowed.

**Fix**: Remove the `endswith('.log')` branch. IIS files are identified by name or path alone:

```python
return 'iis' in name or 'w3svc' in name or 'u_ex' in os.path.basename(filepath).lower()
```

---

### BUG-05 · Double write in `--monitor` loop overwrites what `agent.run()` just saved

**File**: `Backend/src/secux/cli.py:240–249`

```python
# agent.run() saves the result to `output` with append=True
full_result = agent.run(log_paths=paths, output_file=output, append=True, show_summary=False)

# Then this block opens the SAME file in 'w' mode and overwrites it:
with open(output, 'w', encoding='utf-8') as f:
    import json
    json.dump(full_result, f, indent=2, default=str)
```

**Impact**: The file is written twice per monitoring tick. The second `open(..., 'w')` truncates the file and re-writes the same data, defeating the purpose of `append=True` in `agent.run()`. Any entries that were appended by the first save are lost.

**Fix**: Remove the second `with open(...)` block entirely — `agent.run()` already handles saving.

---

### BUG-06 · `setup.py` missing `requests` from `install_requires`

**File**: `Backend/setup.py:8–13`

```python
install_requires=[
    "click>=8.0.0",
    "python-dotenv>=1.0.0",
    "rich>=13.0.0",
    "watchdog>=3.0.0",
    # MISSING: "requests>=2.31.0"
],
```

**Impact**: Anyone installing via `pip install -e .` or packaging the tool will get an environment without `requests`. All LLM calls (`_query_local`, `_query_openrouter`) will fail with `ModuleNotFoundError: No module named 'requests'`. The `requirements.txt` has it, but `setup.py` is authoritative for packaging.

**Fix**: Add `"requests>=2.31.0"` to `install_requires`.

---

### BUG-07 · `_detect_log_gaps` floods the report with one finding per log gap

**File**: `Backend/src/secux/Log_Analysis_Agent/analyzers/anomaly.py:510–540`

The detector iterates over every consecutive pair of sorted entries and emits a `log_gap` finding for every gap over 5 minutes. A typical 24-hour log with entries every 10–30 minutes (e.g., cron, systemd, heartbeats) will generate dozens to hundreds of `log_gap` findings, drowning real security events.

**Fix**: Deduplicate by collapsing consecutive gaps, or limit to the single largest gap per log source, or raise the threshold to something meaningful (e.g., 60+ minutes):

```python
LOG_GAP_THRESHOLD_SECONDS = 3600  # 1 hour is a suspicious silence; 5 min is normal
```

Or cap the number of gap findings per analysis run (e.g., top 3 by gap size).

---

### BUG-08 · Rich markup used in `click.echo` — raw tags printed to terminal

**File**: `Backend/src/secux/cli.py:190, 193`

```python
# click.echo does NOT parse Rich markup — these print literally as text:
click.echo(f"\n[#00B7B5]Results saved to:[/#00B7B5] {output.absolute()}")
click.echo(f"[red]Error during analysis:[/red] {str(e)}", err=True)
```

**Impact**: The terminal shows `[#00B7B5]Results saved to:[/#00B7B5]` instead of a coloured message. The error line similarly shows `[red]...[/red]` as literal text.

**Fix**: Either use `Console().print(...)` (like the rest of the file does) or strip the markup:

```python
from rich.console import Console
console = Console()
console.print(f"\n[#00B7B5]Results saved to:[/#00B7B5] {output.absolute()}")
```

---

### BUG-09 · `patterns.py` — `PatternMatcher` is defined but never called anywhere

**File**: `Backend/src/secux/Log_Analysis_Agent/analyzers/patterns.py`

`PatternMatcher` has regex patterns for SQL injection, XSS, path traversal, command injection, and more. It is never imported or used anywhere in the codebase. The `AnomalyDetector` does not call it. All these detections are silently dead.

**Impact**: SQL injection, XSS, path traversal, command injection, and scanning tool detection (sqlmap, nmap, nikto) are never triggered, even when the patterns exist and are correct.

**Fix**: Either integrate `PatternMatcher` into `AnomalyDetector.analyze()` to scan log entry messages, or delete the file and document why these patterns are deferred.

---

## MEDIUM — Logic Errors / Misleading Behaviour

---

### BUG-10 · `_detect_error_spikes` stores a time string instead of an ISO timestamp

**File**: `Backend/src/secux/Log_Analysis_Agent/analyzers/anomaly.py:308, 313–315`

```python
anomalies.append(Anomaly(
    ...
    timestamp=f"{hour:02d}:00",   # ← "22:00" — not a valid timestamp
    log_entries=[]
))
```

**Impact**: The `Anomaly.timestamp` field is supposed to be an ISO datetime string (every other detector uses `entry.timestamp.isoformat()`). Storing `"22:00"` breaks any downstream code that tries to parse this as a datetime. The `JSONFormatter` will silently emit a non-parseable timestamp in the output JSON.

**Fix**: 
```python
from datetime import date
timestamp=datetime(date.today().year, date.today().month, date.today().day, hour, 0, 0, tzinfo=timezone.utc).isoformat()
```

---

### BUG-11 · Windows-only network context misleads AI agents on Linux/macOS

**File**: `Backend/src/secux/collector.py:25–28`

```python
else:
    return "Network monitoring only supported on Windows in this version."
```

**Impact**: On Linux/macOS, the string `"Network monitoring only supported on Windows in this version."` is passed verbatim as network context to `NetworkMonitoringAgent.analyze()`. The LLM receives this as "network data" and may produce a confused or hallucinated report rather than simply noting there is no network data.

**Fix**: Return `None` or an empty string, and in `run_full_audit()`, skip sending the agent context if it's empty/None. Or add Linux support via `ss -tulnp` / `netstat -an`.

---

### BUG-12 · AI insights panel hardcodes "Mistral Small" regardless of actual model

**File**: `Backend/src/secux/Log_Analysis_Agent/output/json_formatter.py:102`

```python
console.print("\n[bold purple]🧠 AI INSIGHTS (Mistral Small)[/bold purple]")
```

**Impact**: Whether the user has configured OpenRouter with Qwen, Gemini, or a local Ollama model, the UI always says "Mistral Small". This is confusing and inaccurate.

**Fix**: Pass the model name through to the formatter, or remove the model name from the display label entirely (just call it "AI INSIGHTS").

---

### BUG-13 · `run_incremental` in `LogAnalysisAgent` does not apply timeframe filter

**File**: `Backend/src/secux/Log_Analysis_Agent/agent.py:186–209`

`run_incremental` takes a `since` parameter but only uses it to skip entries with `entry.timestamp <= since`. It does NOT call `_filter_timeframe()`. If `since` is `None`, all entries in the file are analysed without any timeframe bound.

**Impact**: Monitoring mode may analyse the entire log history on each tick instead of only new entries, inflating finding counts and processing time.

---

### BUG-14 · `google-generativeai` not in `requirements.txt` or `setup.py`

**File**: `Backend/requirements.txt`, `Backend/setup.py`

`llm_engine.py` does `import google.generativeai as genai` when `GEMINI_API_KEY` is set, but `google-generativeai` appears nowhere in the dependency files.

**Impact**: Any user who sets `LLM_PROVIDER=google` will get `ModuleNotFoundError` at startup even though the README lists Gemini as a supported provider.

**Fix**: Add to `setup.py` extras:
```python
extras_require={
    "evtx": ["py-evtx>=0.4.0"],
    "google": ["google-generativeai>=0.4.0"],
},
```
And document the install command: `pip install -e ".[google]"`.

---

## LOW — Style / Deprecations / Minor Issues

---

### BUG-15 · `datetime.utcnow()` is deprecated since Python 3.12

**Files**: `anomaly.py` (multiple), `base.py:54`, `syslog.py:73/108`, `iis.py:63/65`, `json_log.py:88`

`datetime.utcnow()` is deprecated in Python 3.12 and will be removed in a future version. It also returns a naive datetime, which the codebase inconsistently mixes with timezone-aware datetimes.

**Fix**: Replace all occurrences with `datetime.now(timezone.utc)`.

---

### BUG-16 · Unclosed file objects created for Rich console on every call

**File**: `Backend/src/secux/cli.py:31–33, 322–325`; `json_formatter.py:92–94`

```python
# Pattern used in multiple places:
console = Console(
    file=open(sys.stdout.fileno(), mode='w', encoding='utf-8', closefd=False)
)
```

The `open(...)` call creates a file object that is never explicitly closed. With `closefd=False`, the fd isn't closed, but the wrapper object leaks. On short-lived CLI calls this is harmless, but calling `run_full_audit` or `print_summary` in a loop (e.g., from monitoring) will accumulate leaked objects.

**Fix**: Use a `with` statement or assign the file object and close it after the console is done.

---

### BUG-17 · `--monitor` mode: `import json` and `import time` inside the loop body

**File**: `Backend/src/secux/cli.py:248, 255`

```python
while True:
    ...
    import json       # inside the loop
    ...
    import time       # inside the loop
    time.sleep(interval)
```

Python caches imports so this won't cause failures, but it's misleading and a minor performance smell. Move both imports to the top of the file.

---

## Documentation / Repository Issues

---

### BUG-18 · Unresolved git merge conflict in `README.MD`

**File**: `README.MD:61–142`

The file contains unresolved conflict markers:
```
<<<<<<< HEAD
...
=======
...
>>>>>>> ae476baba89b0052332e1fc7b3bc794bf1a222cb
```

**Impact**: GitHub renders this as literal text. Anyone reading the README on the repo sees the conflict markers. The installation instructions are split across both sides of the conflict.

**Fix**: Resolve the conflict — the `HEAD` side has the full setup instructions; the other side has only the `python -m` execution note (which can be merged into the main text as an additional note).

---

### BUG-19 · README example uses non-existent flags

**File**: `README.MD:47–49`

```powershell
# From the README:
secux audit --timeframe 24h --threshold LOW
```

Neither flag exists as written:
- `--timeframe 24h` — the actual type is `int`, so `24h` will raise `Error: Invalid value for '--timeframe': '24h' is not a valid integer.`
- `--threshold` — does not exist. The correct flag is `--severity`.

**Fix**:
```powershell
secux audit --timeframe 24 --severity LOW
```

---

### BUG-20 · `Backend/.env` appears to be tracked by git

**File**: `Backend/.env`

The git status shows `M Backend/.env` (modified), meaning the `.env` file is tracked. API keys and secrets should never be in version control.

**Fix**: Add `Backend/.env` to `.gitignore`, then run `git rm --cached Backend/.env` to untrack it without deleting it locally.

---

## Summary Table

| ID | Severity | File | Description |
|----|----------|------|-------------|
| BUG-01 | **CRITICAL** | `monitor.py:146` | Typo `dirs_toatch` → NameError, `--monitor` crashes |
| BUG-02 | **CRITICAL** | `monitor.py:58–62` | File seek is dead; parser re-reads entire file, generates duplicates |
| BUG-03 | **HIGH** | `autodetect.py:14` | Parser order wrong; syslog/auth.log parsed by SimpleText, misses events |
| BUG-04 | **HIGH** | `iis.py:19` | `can_parse` matches every `.log` file, swallows non-IIS logs |
| BUG-05 | **HIGH** | `cli.py:240–249` | Monitor double-write overwrites appended data |
| BUG-06 | **HIGH** | `setup.py:8` | `requests` missing from `install_requires`, packaging broken |
| BUG-07 | **HIGH** | `anomaly.py:510` | Log gap detector floods report (one finding per gap) |
| BUG-08 | **HIGH** | `cli.py:190,193` | Rich markup in `click.echo` prints as raw text |
| BUG-09 | **HIGH** | `patterns.py` | `PatternMatcher` (SQLi, XSS, traversal, injection) never called |
| BUG-10 | **MEDIUM** | `anomaly.py:308` | Error spike stores `"22:00"` instead of ISO timestamp |
| BUG-11 | **MEDIUM** | `collector.py:28` | "Windows only" string passed as AI context on Linux/macOS |
| BUG-12 | **MEDIUM** | `json_formatter.py:102` | UI hardcodes "Mistral Small" regardless of configured model |
| BUG-13 | **MEDIUM** | `agent.py:186` | `run_incremental` skips timeframe filter, may reprocess full history |
| BUG-14 | **MEDIUM** | `requirements.txt` | `google-generativeai` missing; Gemini provider fails at import |
| BUG-15 | **LOW** | multiple files | `datetime.utcnow()` deprecated in Python 3.12+ |
| BUG-16 | **LOW** | `cli.py`, `json_formatter.py` | Unclosed file objects for Rich console |
| BUG-17 | **LOW** | `cli.py:248,255` | `import json/time` inside `while True` loop |
| BUG-18 | **DOC** | `README.MD:61` | Unresolved git merge conflict markers |
| BUG-19 | **DOC** | `README.MD:47` | Example uses `--timeframe 24h` and `--threshold` (both wrong) |
| BUG-20 | **SEC** | `Backend/.env` | `.env` file is git-tracked — API keys in version history |
