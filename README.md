> Version: 3.2.0 · Updated: 2026-10-31

# hubvik

Per-device network anomaly detection for IoT gateways. The publishable package is [`packages/core`](packages/core).

Status: **hubvik 3.2.0 prototype — not validated on real traffic.** On 2026-10-31, `npm view hubvik dist-tags --json` returned `{ "latest": "3.2.0" }`. Every `@hubvik/*` package returned 404 (not published). The library only reports. It does not block, drop, or rewrite traffic. A default engine emits the same live anomalies as 1.6.0. Open gates: the 0.6 gate, the Raspberry Pi 4 bench, the API freeze, the security review, and the 30-day pilot. The 3.2.0 notes are in [`packages/core/CHANGELOG.md`](packages/core/CHANGELOG.md). `h2-fanout`, `onion-name`, `proxy-fanin`, and `scatter-udp` are shadow rows from 2.0.1.

Roadmap: docs/SPEC.md section 0.20 (planned, not built).

How to feed events, indicators, and policy is [`docs/DEVELOPERS.md`](docs/DEVELOPERS.md). The detector catalog is in [`docs/features.md`](docs/features.md). `overview(now)` returns attacks, waves, incidents, campaigns, shadow hits, and counts in one call.

## Install

```
npm install hubvik
```

## Use

```js
const { createEngine } = require('hubvik');

const engine = createEngine({ learnMs: 7 * 24 * 3600e3 }); // learn for 7 days

engine.feed({ device: 'aa:bb:cc:dd:ee:ff', dst: 'video.vendor.com', bytes: 2048, ts: Date.now() });

engine.on('anomaly', (a) => {
  // { device, detector, severity, ts, actual, expected }
  // The host product decides the action.
});

setInterval(() => engine.flush(Date.now()), 60e3); // live hosts pass now; bare flush() is end-of-input only

const baseline = engine.exportBaseline();
otherEngine.importBaseline(baseline);
```

hubvik never blocks anything by itself. It only reports.

```
npm test
npm run demo
```

## Options

| Option               | Default  | Meaning                                                      |
| -------------------- | -------- | ------------------------------------------------------------ |
| `learnMs`            | 7 days   | Learning period per device, from its first event             |
| `windowMs`           | 60 s     | Traffic window size                                          |
| `sigma`              | 4        | Volume spike sensitivity                                     |
| `minFanout`          | 10       | Never flag fan-out below this many hosts per window          |
| `minBytes`           | 1 MB     | Never flag volume below this per window                      |
| `maxNewDstPerWindow` | 3        | Cap on new-destination alerts per window                     |
| `hourOf`             | UTC hour | Function `(ts) => hour`; pass local time if needed           |
| `fanoutFactor`       | 3        | Fan-out limit is at least this times the learned max         |
| `peakFactor`         | 2        | Volume limit is at least this times the learned max          |
| `tiers`              | `['T0']` | Event tiers the host is sending                              |
| `correlate`          | `false`  | Copy a DNS or TLS name onto a later flow with the same `uid` |

## Limits

- Sees only traffic that passes through the gateway.
- Encrypted traffic hides content; who, how much, and when stay visible.
- Attacks that stay inside normal behavior are not caught.
- If the device is already compromised during learning, that behavior becomes normal. Use `lock()` after reviewing the baseline.
- A compromised gateway defeats everything.

## Validation status

IoT-23 malware capture (`eval/results/iot23-malware/iot23.md`): Detection: n too small (17 detected, 17 attack instances). Strict detection: 9/17 = 52.9% (95% Wilson 31.0%–73.8%). False positives: 314 anomalies at medium or above, 72.7037175925926 benign device-days, 4.31889881834587 per benign device-day.

IoT-23 honeypot capture (`eval/results/iot23-honeypot/iot23.md`): Detection: no rate. Strict detection: no rate. False positives: 0 anomalies at medium or above, 0 benign device-days, no rate (0 device-days). That file has 0 benign device-days, so it states no false-positive rate.

CICIoT2023: not run. `eval/results` has no CICIoT2023 result file.

No 30-day pilot. No Raspberry Pi 4 measurement.

The same malware file records the bogon-destination ablation as `bogon-destination: 0 unique detections, 307 false positives, zero unique` and the proposal `bogon-destination: zero unique detections and 307 medium false positives over 72.7037175925926 benign device-days, above the C6.3 gate. Proposal: set detectors.bogon-destination.enabled to false, or set severity to info` (`eval/results/iot23-malware/iot23.md`). `packages/core/CHANGELOG.md` for 2.1.0 says that severity is now info. The result file still counts those 307 as medium. Those two records disagree, so this page quotes the result file. The severity decision and that measurement use the same capture, so the rate above is not a holdout result.

There is no alert-level false-positive rate in `eval/results/iot23-malware/iot23.md` or in the top-level fields of `eval/results/iot23-malware/iot23.json`.

Harness: [eval/README.md](eval/README.md). The C6.3 false-positive gate is not met.

## License

Apache-2.0
