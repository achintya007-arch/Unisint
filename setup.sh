#!/usr/bin/env bash
# UNISINT one-command setup for WSL / Linux / macOS.
# Creates a venv, installs UNISINT + the wrapped OSINT tools, runs a self-check,
# then launches the console. Safe to re-run.
set -e
cd "$(dirname "$0")"

echo "== UNISINT setup =="

# 1. Python check
if ! command -v python3 >/dev/null; then
  echo "python3 not found. On WSL/Ubuntu: sudo apt update && sudo apt install -y python3 python3-venv python3-pip"
  exit 1
fi
PYV=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')
echo "Python $PYV detected"

# 2. venv + install UNISINT (editable)
if [ ! -d .venv ]; then python3 -m venv .venv; fi
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install -q --upgrade pip
python -m pip install -q -e .
echo "UNISINT installed in .venv"

# 3. Optional: wrapped tools into the private ~/.unisint/tools venv
echo "Installing optional OSINT tools (Sherlock, Maigret, holehe, ...)"
bash ./install_tools.sh || echo "(some optional tools skipped; the app still runs)"

# 4. exiftool (optional, for rich image metadata)
if ! command -v exiftool >/dev/null; then
  if command -v apt >/dev/null; then
    echo "Installing exiftool (needs sudo)..."; sudo apt-get install -y libimage-exiftool-perl || \
      echo "Skip exiftool: run 'sudo apt install libimage-exiftool-perl' later."
  elif command -v brew >/dev/null; then
    brew install exiftool || true
  else
    echo "exiftool not installed (optional). Install it with your package manager for richer image metadata."
  fi
fi

# 5. Self-check
echo; python -m unisint doctor || true

# 6. Launch
echo; echo "Launching UNISINT at http://127.0.0.1:8777  (Ctrl-C to stop)"
exec python -m unisint
