# iotwarden

Per-device network anomaly detection for IoT gateways. The publishable package is [`packages/core`](packages/core).

Status: **0.4.0 prototype — not validated on real traffic.** The catalog in the spec is larger than what this release implements. 0.4.0 adds TLS metadata, building-protocol writes, MQTT and ONVIF checks, and fleet comparison. It still only reports.

The behavior spec is [`docs/SPEC.md`](docs/SPEC.md). How to feed events, indicators, and policy is [`docs/DEVELOPERS.md`](docs/DEVELOPERS.md). The build order is [`CURSOR_BUILD.md`](CURSOR_BUILD.md).

```
npm test
npm run demo
```

## Evaluation

Not yet evaluated on real traffic. Harness: [eval/README.md](eval/README.md).
