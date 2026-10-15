# UNISINT

A unified OSINT console with a "movie-hacker" web UI. It wraps proven
open-source tools (Sherlock, Maigret, holehe, socialscan, ignorant,
theHarvester, subfinder, Amass, exiftool) plus native keyless lookups
(GitHub, GitLab, Reddit, Keybase, Gravatar, DNS, RDAP/WHOIS, crt.sh,
Shodan InternetDB, ip-api, Wayback, EXIF) behind **one input box**, runs
them together, correlates the results into a single dossier, and draws a
live link graph as it pivots from one finding to the next.

## Two modes — and only two

UNISINT is built for the uses that are yours to run:

- **SELF-AUDIT** — map your *own* digital footprint: which sites expose
  your usernames/emails, what leaks from your public commits, EXIF GPS in
  your photos, etc. — so you can lock it down.
- **RECON** — passive reconnaissance of **domains / IPs you own or are
  explicitly contracted to assess** (pentest, bug bounty). Subdomains,
  DNS, certs, open ports, known CVEs, tech fingerprint.

On launch you must acknowledge that you own or are authorized to assess
the targets you enter. UNISINT uses **public sources only** — no breach
password dumps, no login bypass, no SMTP probing, no face recognition.

## Quick start (Windows + WSL — recommended)

Open a terminal, then:

```bash
wsl                                        # drop into Ubuntu
sudo apt update && sudo apt install -y git python3 python3-venv python3-pip
git clone https://github.com/achintya007-arch/Unisint.git
cd Unisint && git checkout build-unisint
./setup.sh                                 # one command: installs, self-checks, launches
```

Then open **http://127.0.0.1:8777** in your Windows browser (WSL forwards
localhost automatically). `setup.sh` is safe to re-run; after the first time
you can just `source .venv/bin/activate && unisint`.

### Other platforms

```bash
./run.sh                 # installs core deps, opens http://127.0.0.1:8777
# or
pip install -r requirements.txt
python -m unisint
# or install as a package (provides a `unisint` command)
pip install .
unisint
```

### Check your setup / find gaps

```bash
python -m unisint doctor   # reports Python, modules, tools, and network reachability
```

It writes the same report to `~/.unisint/doctor-report.txt`. While testing, use
the in-app **REPORT GAP** button (top bar) to jot what's missing — it logs to
`~/.unisint/gaps.md`, which you can paste back for follow-up.

Everything runs **locally**. No data leaves your machine except the public
lookups each module performs.

## Optional tools (the "ARSENAL")

Core features work with zero extra installs. To light up the wrapped
tools, either click **INSTALL** on the in-app ARSENAL tab, or run:

```bash
./install_tools.sh
```

Tools install into a private area (`~/.unisint/tools/`) so they never
clash with UNISINT's own dependencies. Missing tools are simply skipped;
the scan still runs with whatever is available.

## Using it

1. Pick **SELF-AUDIT** or **RECON**.
2. Paste anything (username, email, phone, domain, IP) — the type is
   auto-detected — or drop an image.
3. Choose **QUICK / STANDARD / DEEP** and hit **ENGAGE**.
4. Watch the live feed and graph. Click any node to open or inspect it.
5. Review the **DOSSIER**. In SELF-AUDIT mode it ends with a
   **REMEDIATION // FIX THIS** section: per-account lock-down links, how to
   rotate an email leaked in public commits, how to scrub photo GPS, and
   data-broker opt-out links. Check the **MAP** for geolocated findings, and
   **EXPORT** JSON, CSV, or a standalone HTML report.

Optional API keys (Shodan, HIBP, Hunter, VirusTotal, Anthropic for an AI
summary) can be added under **SETTINGS**; they are stored only in
`~/.unisint/config.json`.

## Architecture

- `unisint/engine.py` — async entity graph, de-dup, auto-pivot, streaming.
- `unisint/base.py` — module framework + registry (adapters + native share it).
- `unisint/adapters/` — wrappers around external CLI tools.
- `unisint/native/` — pure-Python keyless lookups.
- `unisint/synthesis.py` — builds the dossier / subject profile.
- `unisint/app.py` — FastAPI server + WebSocket stream.
- `unisint/static/` — the console UI (vanilla JS, no build step).

## Legal & ethical use

You are responsible for how you use UNISINT. Only investigate yourself or
assets you are authorized to assess. Many jurisdictions regulate
collecting information on other people; unauthorized profiling can be
illegal. This project is for defensive self-audit and authorized security
testing.
