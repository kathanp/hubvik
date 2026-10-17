# WP-8

Date: 2026-10-17. Package: `iotwarden@0.4.0`.

## What changed

`npm run fuzz` runs 100,000 seeded inputs through `feed()`, `importBaseline()`, and `restore()`. `npm run bench` times `feed()` with every tier on. `spec-coverage` treats Rel 0.5 as due while the package is still 0.4.0, so a missing 0.5 row fails.

## Tests added

The fuzz scripts are the new inputs. They rejected 33,401 of 100,000 feed inputs and all 100,000 baseline and checkpoint inputs, then accepted one more event. No prototype pollution.

## Fast check

```
✔ a known SNI that changes certificate issuer is a MITM (7.223ms)
✔ maps an anomaly to a Detection Finding (1.2465ms)
✔ formats RFC 5424 with a CEF message (1.486125ms)
✔ retries, then sends the HMAC header (1.611459ms)
✔ throws after the last failed attempt (0.348417ms)
✔ a large UDP upload to one public address is an egress flood during learning (7.754208ms)
✔ a smart TV proxy SDK followed by a LAN session is one incident (15.162417ms)
ℹ tests 117
ℹ suites 0
ℹ pass 117
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 156587.972375
```

## Thresholds

None. Bench median `feed()` was 24.29 µs and memory was 2.46 KB per device. The 10 µs budget was missed. The number is in `docs/BENCHMARKS.md`. The detectors were not tuned.
