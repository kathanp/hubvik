# Checkpoint A

Date: 2026-10-17. After WP-4. Package: `iotwarden@0.4.0`.

Gate passed. Coverage run: 106/106 tests, lines 97.58%, branches 86.26%.

Demo printed `went-silent`, `volume-spike`, `volume-spike-hourly`, and incident stages `c2`, `recon`, `impact`.

## Gate tail

```
packages/core: 148 files, 319951 bytes unpacked
packages/export-ocsf: 5 files, 13780 bytes unpacked
packages/export-syslog: 5 files, 13828 bytes unpacked
packages/export-webhook: 5 files, 14499 bytes unpacked
pack-check: ok
spec-coverage: 122 rows, 106 detector files, core 0.4.0
pending: `identity-change` — Rel 0.5, not yet implemented
pending: `egress-flood` — Rel 0.5, not yet implemented
pending: `proxy-sdk-traffic` — Rel 0.5, not yet implemented
spec-coverage: ok

> bench
> node scripts/noop.mjs bench

bench: no-op until Phase 5

> fuzz
> node scripts/noop.mjs fuzz

fuzz: no-op until Phase 5
```
