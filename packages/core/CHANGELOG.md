# Changelog

## 0.1.0

Plugin engine. The original four detectors are plugins. Adds typed events, baseline v2 with optional HMAC-SHA256, and the public methods from the spec (`feedBatch`, `lock`, `relearn`, `allow`, `suppress`, `ack`, `forget`, `setPeerGroup`, `use`, `stats`, `loadIndicators`). Version 1 baselines still import. Not validated on real traffic.

## 0.0.1

Prototype engine, kept as the regression baseline. Four detectors: `new-destination`, `fan-out`, `volume-spike`, `wrong-time`. Not validated on real traffic.
