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

The ARSENAL shows a **health-checked state**, not just "file exists":
`unavailable` → `installed` → `runnable` (its `--version`/`-h` works) →
`operational` (a real run succeeded this session); or `misconfigured` /
`failing`, with the actual error.

Tool-specific requirements (verified):

| Tool | Requirement |
|---|---|
| theHarvester | Current source needs **Python ≥ 3.14** → installed with **uv** into `~/.unisint/tools/theHarvester-src/.venv` (uv provisions Python). Install uv: `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| subfinder | Module requires **Go ≥ 1.26**; any Go **≥ 1.21** downloads that toolchain automatically. Ubuntu's `apt install golang-go` is too old — install Go from https://go.dev/dl/ |
| Amass | `go install …/amass/v4/...@master` (v4.2.0). Needs direct UDP DNS to public resolvers; restricted networks fail with "unable to build the pool of untrusted resolvers". |
| exiftool | `sudo apt install libimage-exiftool-perl` |

Extra tool locations can be added with `UNISINT_TOOL_PATHS=/dir1:/dir2`.

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

## How to read results

UNISINT separates **what a source observed** from **what that means**:

- Every item carries its **provenance** (which tool/API, from which lookup,
  the URL the source itself returned) — open "why?" on any row.
- **Links** show a validation state when **VERIFY LINKS** is on:
  `reachable` (a page loaded — *not* proof an account exists), `not_found`,
  `soft_404`, `login_wall`, `blocked` (e.g. anti-bot page), `rate_limited`,
  `timeout`, `error`, `unsafe` (private/loopback/metadata address refused),
  `invalid`; otherwise `unchecked`. Checks are rate-limited per host,
  redirects are re-validated hop by hop, and private-network targets are
  refused at connect time (SSRF / DNS-rebinding defence).
- **Labels** explain how an item relates to what you entered:
  *Seeded* · *Linked — verified proof* · *Linked — stated on your profile* ·
  *Handle match — corroborated* · **Handle match — unconfirmed** (same
  handle elsewhere is not proof it's you) · *Weak* · *Candidate — unverified*,
  plus **conflicting evidence** when something points the other way.
  These are evidence descriptions, not probabilities.
- A **full name is a search key, not a finding**. Username guesses from a
  name are shown as candidates and never scanned automatically — click a
  candidate and **SCAN AS SEED** only if it's yours.
- **Pivots are bounded**: only seeds and strong links expand; names,
  candidates and same-handle matches are recorded, not expanded. Every
  expand/skip decision has a stated reason (dossier → PIVOTS). RECON only
  actively probes the seed domain, its subdomains and the IPs they resolve to.
- **Module status** is honest: `ok` (found something), `empty` (ran, found
  nothing), `error` (failed — with the reason), `unavailable`.

Exports (JSON / evidence CSV / HTML report) are produced from the same
dossier the UI shows.

## Web search (optional)

Real retrieval — not generated Google links — through any of:

| Provider | Configure in SETTINGS |
|---|---|
| Brave Search API | API key |
| Google Programmable Search JSON API | key + search engine ID (cx). Google has closed this API to new customers; existing keys still work for now. |
| Your own SearXNG instance | base URL (enable `json` in `search.formats`) |

Without a provider the web-search module reports itself `unavailable`, and
the old dork links are offered as clearly-labelled *manual search links*.
Query templates can be overridden with `~/.unisint/search_queries.json`.
Keys live in `~/.unisint/config.json` (mode 0600) and are redacted from logs.

## Architecture

- `unisint/engine.py` — async entity graph, provenance-preserving de-dup, streaming.
- `unisint/pivot.py` — pivot policy, scope guard and limits.
- `unisint/urls.py` — URL normalisation, SSRF guard, link validation.
- `unisint/search/` — query templates, search-API providers, dedup.
- `unisint/resolve.py` — explainable labels (supports / conflicts / unknown).
- `unisint/report.py` — server-rendered HTML/CSV exports.
- `unisint/base.py` — module framework + registry (adapters + native share it).
- `unisint/adapters/` — wrappers around external CLI tools.
- `unisint/native/` — pure-Python keyless lookups.
- `unisint/synthesis.py` — builds the dossier (single builder for UI + exports).
- `unisint/toolmanager.py` — tool discovery, health checks, installation.
- `unisint/app.py` — FastAPI server + WebSocket stream.
- `unisint/static/` — the console UI (vanilla JS, no build step).

## Legal & ethical use

You are responsible for how you use UNISINT. Only investigate yourself or
assets you are authorized to assess. Many jurisdictions regulate
collecting information on other people; unauthorized profiling can be
illegal. This project is for defensive self-audit and authorized security
testing.
