# hubvik

Per-device network anomaly detection for IoT gateways. The publishable package is [`packages/core`](packages/core).

Status: **2.0.4 prototype — not validated on real traffic.** The library only reports. It does not block, drop, or rewrite traffic. The 2.0.4 notes are in [`packages/core/CHANGELOG.md`](packages/core/CHANGELOG.md). `hubvik@2.0.3` is the version on npm until this tag is published. The 0.6 gate, the Raspberry Pi 4 bench, the API freeze, the security review, and the 30-day pilot are open. The new detectors are shadow only: `h2-fanout`, `onion-name`, `proxy-fanin`, and `scatter-udp`. A default engine emits the same anomalies as 1.6.0.

How to feed events, indicators, and policy is [`docs/DEVELOPERS.md`](docs/DEVELOPERS.md). The detector catalog is [`docs/DETECTORS.md`](docs/DETECTORS.md).

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

## Evaluation

IoT-23 was scored by `eval/run.mjs`. The numbers below are copied from those result files. The C6.3 false-positive gate is not met. Harness: [eval/README.md](eval/README.md).

Malware capture (`eval/results/iot23-malware/iot23.md`): detection n too small (17 detected, 17 attack instances); strict detection 9/17 = 52.9% (95% Wilson 31.0%–73.8%); 4.31889881834587 false positives per benign device-day.

Honeypot capture (`eval/results/iot23-honeypot/iot23.md`): detection no rate; strict detection no rate; 0 benign device-days.

## License

Apache-2.0
