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

# Go tools — pinned versions. Minimum Go comes from each pinned go.mod:
#   subfinder v2.17.0 -> go 1.26.0     amass v4.2.0 -> go 1.19
# A local Go >= 1.21 with GOTOOLCHAIN=auto (the default) downloads a newer
# toolchain itself; Go < 1.21, or GOTOOLCHAIN=local, cannot.
SUBFINDER=github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0
AMASS='github.com/owasp-amass/amass/v4/...@v4.2.0'
if command -v go >/dev/null; then
  read -r GOMAJ GOMIN <<<"$(go env GOVERSION | sed -E 's/^go([0-9]+)\.([0-9]+).*/\1 \2/')"
  GOTC="$(go env GOTOOLCHAIN)"
  echo "Go $GOMAJ.$GOMIN (GOTOOLCHAIN=$GOTC)"
  can_switch=0
  if [ "$GOMAJ" -gt 1 ] || [ "$GOMIN" -ge 21 ]; then
    case "$GOTC" in auto|*+auto|"") can_switch=1 ;; esac
  fi
  # subfinder: needs >= 1.26, or switching
  if [ "$GOMAJ" -gt 1 ] || [ "$GOMIN" -ge 26 ] || [ "$can_switch" = 1 ]; then
    GOBIN="$GOBIN" go install -v "$SUBFINDER" || echo "subfinder install failed (see error above)"
  else
    echo "subfinder skipped: needs Go >= 1.26 (or Go >= 1.21 with GOTOOLCHAIN=auto). Install from https://go.dev/dl/"
  fi
  # amass: needs >= 1.19
  if [ "$GOMAJ" -gt 1 ] || [ "$GOMIN" -ge 19 ] || [ "$can_switch" = 1 ]; then
    GOBIN="$GOBIN" go install -v "$AMASS" || echo "amass install failed (see error above)"
  else
    echo "amass skipped: needs Go >= 1.19. Install from https://go.dev/dl/"
  fi
else
  echo "Go not found: skipping subfinder/Amass. Install from https://go.dev/dl/"
fi
echo "Done. exiftool (optional): apt install libimage-exiftool-perl"
