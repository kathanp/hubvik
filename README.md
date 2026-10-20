# iotwarden

Per-device network anomaly detection for IoT gateways. The publishable package is [`packages/core`](packages/core).

Status: **0.8.0 prototype — not validated on real traffic.** The library only reports. It does not block, drop, or rewrite traffic. Release 0.9 (load shedding, federation, extra adapters, the CLI) is specified and not finished. Nothing in this repo is published to npm.

The behavior spec is [`docs/SPEC.md`](docs/SPEC.md). How to feed events, indicators, and policy is [`docs/DEVELOPERS.md`](docs/DEVELOPERS.md). The build order is [`CURSOR_BUILD.md`](CURSOR_BUILD.md).

```
npm test
npm run demo
```

## Evaluation

IoT-23 was scored by `eval/run.mjs`. The numbers below are copied from those result files. The C6.3 false-positive gate is not met. Harness: [eval/README.md](eval/README.md).

Malware capture (`eval/results/iot23-malware/iot23.md`): detection n too small (17 detected, 17 attack instances); strict detection 9/17 = 52.9% (95% Wilson 31.0%–73.8%); 4.31889881834587 false positives per benign device-day.

Honeypot capture (`eval/results/iot23-honeypot/iot23.md`): detection no rate; strict detection no rate; 0 benign device-days.
