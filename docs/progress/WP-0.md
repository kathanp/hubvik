# WP-0

Date: 2026-10-17. Package: `iotwarden@0.4.0`. Spec 3.0.

## What was built

- `scripts/spec-coverage.mjs` parses every Part B table that has an `ID` column and a `Rel` column. It writes `docs/DETECTORS.md` and is part of `npm run gate`.
- Every shipped detector exports `meta` with `rel`, `fpRisk`, and, when the JSON tables have them, `attack` and `stage`.
- `type: 'discovery'` was already accepted. An unknown proto is now dropped with `warning` `FIELD_DROPPED`. A known proto (`mdns`, `ssdp`, `ws-discovery`, `coap`) is kept. No detector reads the event yet.
- The B7 `identity-change` cell said `00.5`. The same spec says that row is Rel 0.5, so the cell is `0.5`.
- `class-violation` had no Rel row. B19 now has one: severity high, Rel 0.3, which matches the code.

## Not implemented, and not a failure at 0.4.0

`identity-change`, `tier-silent`, `egress-flood`, and `proxy-sdk-traffic` are listed as Rel 0.5, not yet implemented. They fail the script only after core is bumped to 0.5.0.

## Gate

`npm run gate` passed: 92/92 tests, 97.19% lines, 84.97% branches.

`npm run pack:check`: `packages/core` is 146 files, 305543 bytes unpacked.

`spec-coverage`: 122 rows, 105 detector files.

`npm run demo` prints the camera hijack and one critical incident whose stages are c2, recon, and impact.

Stopped here. WP-1 is next, after the four questions in `docs/QUESTIONS.md`.
