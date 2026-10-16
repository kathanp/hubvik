# Phase 1

Date: 2026-10-16. Package: `iotwarden@0.1.0`.

## What was built

- The prototype rules are plugins: `new-destination`, `fan-out`, `volume-spike`, `wrong-time`.
- `createEngine` feeds T0–T5 events, closes epoch-aligned windows, and emits `anomaly`, `learned`, `device-new`, and `warning`.
- Baseline v2, optional HMAC-SHA256, and import of the v1 prototype shape. Import validates the whole document before it changes engine state.
- Caps on devices, destinations, alert keys, window history, and per-window destinations.
- Seeded fixtures for seven device classes. Fourteen benign days of each class produce no anomalies.

## What was skipped, and why

- Detectors past the original four belong to later phases. The spec lists 118; this release ships 4.
- `bench` and `fuzz` stay no-ops until Phase 5.
- No git remote and no `npm publish`.

## Gate

`npm run check` passed: lint, types, and 52/52 tests.

`npm run gate` passed coverage at 98.93% lines and 88.99% branches. Thresholds are 90% lines and 80% branches.

`npm run pack:check`: 21 files, 83907 bytes unpacked.

`npm run demo` still prints the camera hijack: new destination, wrong hour, fan-out, then the volume spike.

Not validated on real traffic.
