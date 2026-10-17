# Checkpoint B

Date: 2026-10-17. After WP-10. Package before the bump: `iotwarden@0.4.0`.

Gate passed. Coverage run: 118/118 tests, lines 97.50%, branches 86.67%. Bench median 25.75 µs, 2.46 KB/device.

Demo printed `went-silent`, `volume-spike`, `volume-spike-hourly`, and incident stages `c2`, `recon`, `impact`.

## Gate tail

```
packages/core: 152 files, 337414 bytes unpacked
packages/export-ocsf: 5 files, 14867 bytes unpacked
packages/export-syslog: 5 files, 13828 bytes unpacked
packages/export-webhook: 5 files, 14499 bytes unpacked
pack-check: ok
spec-coverage: 122 rows, 109 detector files, core 0.4.0
spec-coverage: ok

> bench
> node bench/run.js

bench median 25.75 µs, 2.46 KB/device, devices 100
bench: over the x86 budget; recorded, not tuned

> fuzz
> node fuzz/feed.fuzz.js && node fuzz/baseline.fuzz.js && node fuzz/checkpoint.fuzz.js

feed fuzz: 100000 inputs, 33401 rejected
baseline fuzz: 100000 inputs, 100000 rejected
checkpoint fuzz: 100000 inputs, 100000 rejected
```
