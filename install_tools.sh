#!/usr/bin/env bash
# Install the optional wrapped tools into ~/.unisint/tools.
set -e
HOME_DIR="${UNISINT_HOME:-$HOME/.unisint}"
VENV="$HOME_DIR/tools/venv"
GOBIN="$HOME_DIR/tools/go/bin"
mkdir -p "$GOBIN"
python3 -m venv "$VENV"
"$VENV/bin/pip" install -U -r requirements-tools.txt
# theHarvester: current source needs Python >= 3.14 -> installed with uv,
# which provisions that interpreter itself.
HSRC="$HOME_DIR/tools/theHarvester-src"
if command -v uv >/dev/null; then
  if [ -d "$HSRC/.git" ]; then git -C "$HSRC" pull --ff-only || true
  else git clone --depth 1 https://github.com/laramies/theHarvester "$HSRC" || true; fi
  uv sync --directory "$HSRC" || echo "theHarvester: uv sync failed (see above)"
else
  echo "theHarvester skipped: install uv first (curl -LsSf https://astral.sh/uv/install.sh | sh)"
fi

# Go tools. subfinder needs Go >= 1.26; Go >= 1.21 fetches that automatically.
if command -v go >/dev/null; then
  GOV=$(go version | sed -E 's/.*go([0-9]+)\.([0-9]+).*/\1 \2/')
  set -- $GOV
  if [ "$1" -gt 1 ] || [ "$2" -ge 21 ]; then
    GOBIN="$GOBIN" go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || echo "subfinder install failed (see error above)"
    GOBIN="$GOBIN" go install -v github.com/owasp-amass/amass/v4/...@master || echo "amass install failed (see error above)"
  else
    echo "Go $1.$2 is too old (need >= 1.21). Install Go from https://go.dev/dl/ — apt's golang-go is too old."
  fi
else
  echo "Go not found: skipping subfinder/Amass. Install from https://go.dev/dl/"
fi
echo "Done. exiftool (optional): apt install libimage-exiftool-perl"
