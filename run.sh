#!/usr/bin/env bash
set -euo pipefail
export PYTHONUTF8=1

echo
echo " ========================================="
echo "  SecuX  |  Multi-Agent Security Auditor"
echo " ========================================="
echo

# ── 1. Verify Python 3.10+ ────────────────────────────────────────────────
if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
    echo " [ERROR] Python not found. Install Python 3.10+ and try again."
    exit 1
fi

PYTHON=$(command -v python3 2>/dev/null || command -v python)
PYVER=$("$PYTHON" --version 2>&1 | awk '{print $2}')
echo " [OK] $("$PYTHON" --version 2>&1) found"

# ── 2. Install dependencies ───────────────────────────────────────────────
echo " [..] Installing dependencies from requirements.txt ..."
"$PYTHON" -m pip install -r requirements.txt --quiet --disable-pip-version-check
echo " [OK] Dependencies installed"

# ── 3. Install secux package ──────────────────────────────────────────────
echo " [..] Installing SecuX package (editable) ..."
"$PYTHON" -m pip install -e . --quiet --disable-pip-version-check
echo " [OK] SecuX package installed"

# ── 4. Launch CLI ─────────────────────────────────────────────────────────
echo
echo " [>>] Launching SecuX CLI ..."
echo
secux
