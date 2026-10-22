# UNISINT — gaps & roadmap

Use this while testing. Known-deferred items are checklisted below; add your
own findings at the bottom (or use the in-app **REPORT GAP** button, which logs
to `~/.unisint/gaps.md`).

## Known deferred (not yet built)
- [ ] **Avatar correlation** — perceptual-hash profile pictures to link
      accounts that share an image.
- [ ] **Timeline view** — plot account-creation / commit / archive dates
      (data is collected, not yet charted).
- [ ] **AI analyst** — use the stored Anthropic key to summarise a dossier and
      suggest next pivots.
- [ ] **Key-gated adapters** — Shodan (full), HIBP (breach names), Hunter,
      VirusTotal: keys can be stored but no module reads them yet.
- [ ] **More tools** — WhatsMyName, Blackbird, PhoneInfoga, Mastodon,
      PGP keyservers.
- [ ] **Live web search unverified with real credentials.** Only the error
      path was exercised live (Google, fake key → auth_error). Run
      `unisint search-test example.com` with a real provider to verify.
- [ ] **Amass upstream status**: Amass is still judged by exit code only
      (subfinder/theHarvester now read per-source status).
- [ ] **Successful upstream runs of subfinder/theHarvester not observed live**
      (all sources blocked in the dev sandbox); the success parsers are tested
      on synthetic data in the real output format.
- [ ] **Resume** a scan after a disconnect (partial results are saved, but
      the scan is not resumed).
- [ ] **CVE enrichment** — show severity/summary, not just the CVE id.
- [ ] **Reverse image search** — currently links only (manual upload).

## Shipped (v3.0)
- **Central scope policy** (`scope.py`): one engine classifies every target
  (seed / in-scope / discovered / unresolved / unsafe), re-authorizes each
  active probe at connect time (DNS-rebinding / TOCTOU defence) over the SSRF
  guard, and records an audit trail surfaced in the dossier.
- **Investigation PLAN preview** (`planner.py`, `/api/plan`): before ENGAGE,
  shows per source whether it will run / needs credentials / is unavailable /
  needs authorization / is active.
- **Source-run contract + status vocabulary**: ok / empty / partial / error /
  blocked / rate_limited / auth_error / unavailable / not_configured / timeout
  / skipped, plus contacted / live-vs-fixture / truncated / findings per run.
  A failed or throttled source can be re-run alone via **RETRY**
  (`/api/rerun-source`) — no full re-scan.
- **Graph/dossier view filters**: filter by type / source / validation state /
  evidence strength; graph dims to match; a legend and self-explaining empty
  states.

## Shipped (v2.1)
- Per-source upstream status for theHarvester (structured JSONL) and
  subfinder (-stats table): error / partial / empty / ok.
- theHarvester output-path fix (it writes into CWD).
- Pinned Go tools with verified minimum Go; per-tool Go/GOTOOLCHAIN checks.
- Search credentials via env vars, key clearing, `unisint search-test`.
- SSRF guard fails closed.

## Shipped (v2.0)
- Provenance on every entity; link validation states; SSRF/DNS-rebinding guard.
- Real web search (Brave / Google CSE / SearXNG) with provenance-preserving dedup.
- Bounded, explained pivots; RECON scope guard for active probes.
- Conservative labels with supports / conflicts / unknown; names are search keys.
- Health-checked tool states; reproducible theHarvester (uv) and Go installs.
- Honest module status; single server-side dossier builder for UI + exports.

## Shipped (v1.0–v1.2)
- Two modes (SELF-AUDIT / RECON) behind an authorization gate.
- Native keyless modules + wrapped tools (Sherlock, Maigret, holehe,
  socialscan, ignorant, theHarvester, subfinder, Amass, exiftool).
- Live graph, dossier, map, CSV/JSON/HTML export.
- Self-audit **remediation** guidance; **doctor** self-check; **REPORT GAP**.
- Partial-case autosave; reduced-motion support; pip-installable.

## Your findings
<!-- Add gaps you hit here, or export ~/.unisint/gaps.md and paste it back. -->
- 
