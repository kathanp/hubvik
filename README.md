# hubvik

Per-device network anomaly detection for IoT gateways. The publishable package is [`packages/core`](packages/core).

Status: **1.0.0 prototype — published as `hubvik@1.0.0`, not validated on real traffic.** The library only reports. It does not block, drop, or rewrite traffic. The 1.0.0 notes are in [`packages/core/CHANGELOG.md`](packages/core/CHANGELOG.md). The 0.6 gate, the Raspberry Pi 4 bench, the API freeze, the security review, and the 30-day pilot are open. The `@hubvik/*` packages are not on npm. The `@hubvik` scope is not on the registry.

How to feed events, indicators, and policy is [`docs/DEVELOPERS.md`](docs/DEVELOPERS.md). The detector catalog is [`docs/DETECTORS.md`](docs/DETECTORS.md).

```
npm test
npm run demo
```

## Evaluation

IoT-23 was scored by `eval/run.mjs`. The numbers below are copied from those result files. The C6.3 false-positive gate is not met. Harness: [eval/README.md](eval/README.md).

Malware capture (`eval/results/iot23-malware/iot23.md`): detection n too small (17 detected, 17 attack instances); strict detection 9/17 = 52.9% (95% Wilson 31.0%–73.8%); 4.31889881834587 false positives per benign device-day.

Honeypot capture (`eval/results/iot23-honeypot/iot23.md`): detection no rate; strict detection no rate; 0 benign device-days.
