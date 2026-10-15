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
- [ ] **Per-source error parsing** for theHarvester/subfinder: when every
      upstream source fails the tool still exits 0, so UNISINT reports
      `empty` rather than `error`.
- [ ] **Resume** a scan after a disconnect (partial results are saved, but
      the scan is not resumed).
- [ ] **CVE enrichment** — show severity/summary, not just the CVE id.
- [ ] **Reverse image search** — currently links only (manual upload).

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
