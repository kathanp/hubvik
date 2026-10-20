# hubvik

Per-device network anomaly detection for IoT gateways. The publishable package is [`packages/core`](packages/core).

Status: **0.8.0 prototype — not validated on real traffic.** The library only reports. It does not block, drop, or rewrite traffic. The 0.9 modules are in this tree (load shedding, incremental checkpoints, federation, the extra adapters, and the CLI) and are not a 0.9 release: core is still 0.8.0, and `npm run gate` has not been re-run since they landed. Nothing in this repo is published to npm.

How to feed events, indicators, and policy is [`docs/DEVELOPERS.md`](docs/DEVELOPERS.md). The detector catalog is [`docs/DETECTORS.md`](docs/DETECTORS.md).

```
npm test
npm run demo
```

## Evaluation

IoT-23 was scored by `eval/run.mjs`. The numbers below are copied from those result files. The C6.3 false-positive gate is not met. Harness: [eval/README.md](eval/README.md).

Malware capture (`eval/results/iot23-malware/iot23.md`): detection n too small (17 detected, 17 attack instances); strict detection 9/17 = 52.9% (95% Wilson 31.0%–73.8%); 4.31889881834587 false positives per benign device-day.

Honeypot capture (`eval/results/iot23-honeypot/iot23.md`): detection no rate; strict detection no rate; 0 benign device-days.
