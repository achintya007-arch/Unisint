# UNISINT — gaps & roadmap

Use this while testing. Known-deferred items are checklisted below; add your
own findings at the bottom (or use the in-app **REPORT GAP** button, which logs
to `~/.unisint/gaps.md`).

## Known deferred (not yet built)
- [ ] **Recon scope guard** — fence pivots/active probes to the asset you
      entered; don't fingerprint third-party hosts surfaced via crt.sh/DNS.
- [ ] **Avatar correlation** — perceptual-hash profile pictures to link
      accounts that share an image.
- [ ] **Timeline view** — plot account-creation / commit / archive dates
      (data is collected, not yet charted).
- [ ] **AI analyst** — use the stored Anthropic key to summarise a dossier and
      suggest next pivots.
- [ ] **Key-gated adapters** — Shodan (full), HIBP (breach names), Hunter,
      VirusTotal: keys can be stored but no module reads them yet.
- [ ] **More tools** — WhatsMyName, Blackbird, PhoneInfoga, GHunt, Mastodon,
      PGP keyservers.
- [ ] **CVE enrichment** — show severity/summary, not just the CVE id.
- [ ] **Reverse image search** — currently links only (manual upload).

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
