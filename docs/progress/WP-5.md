# WP-5

Date: 2026-10-17. Package: `iotwarden@0.4.0`.

## What changed

DHCP events accept an opaque `fingerprint` of at most 255 characters. `identity-change` learns one fingerprint per MAC while the device is learning, keeps at most 5,000 MACs on the shared scratch table, and alerts at high severity while watching when that MAC presents a different fingerprint. A MAC that was never learned does not alert.

## Tests added

`identity-change.test.js`: fires after lock, stays quiet for 14 rich days on every profile, stops at 5,000 MACs and rejects a larger import, and keeps the learned fingerprint across export and import.

`spec-coverage` no longer lists `identity-change` as pending.

## Fast check

```
✔ building protocols and MQTT topics (4.588208ms)
✔ fleet wave and peer divergence (1.147458ms)
✔ a tv box relaying consumer sites from the first hour is a supply-chain suspect (11.579917ms)
✔ a new master writes a setpoint out of range and then silences the controller (6.668125ms)
✔ proxy session, LAN ADB sweep, and an RPC lookup become one incident (14.08425ms)
✔ a telnet scan plus a GRE flood is a multi-stage incident (8.601083ms)
✔ a known SNI that changes certificate issuer is a MITM (3.968166ms)
✔ maps an anomaly to a Detection Finding (1.182208ms)
✔ formats RFC 5424 with a CEF message (8.766583ms)
✔ retries, then sends the HMAC header (1.354459ms)
✔ throws after the last failed attempt (0.67725ms)
ℹ tests 110
ℹ suites 0
ℹ pass 110
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 55210.524084
```

## Thresholds

| Item            | Before         | After |
| --------------- | -------------- | ----- |
| MACs remembered | not a detector | 5000  |
