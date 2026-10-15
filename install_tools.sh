#!/usr/bin/env bash
# Install the optional wrapped tools into ~/.unisint/tools.
set -e
HOME_DIR="${UNISINT_HOME:-$HOME/.unisint}"
VENV="$HOME_DIR/tools/venv"
GOBIN="$HOME_DIR/tools/go/bin"
mkdir -p "$GOBIN"
python3 -m venv "$VENV"
"$VENV/bin/pip" install -U -r requirements-tools.txt
if command -v go >/dev/null; then
  GOBIN="$GOBIN" go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
  GOBIN="$GOBIN" go install github.com/owasp-amass/amass/v4/...@master || true
fi
echo "Done. exiftool (optional): apt install libimage-exiftool-perl"
