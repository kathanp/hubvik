# WP-4

Date: 2026-10-17. Package: `iotwarden@0.4.0`.

## What changed

Anomalies now include `schema` 1, a SHA-256 `fingerprint` (first 16 hex chars of detector, device, and actual text), and `evidence` unless `createEngine({ evidence: false })`. `evidence.sample` drops the engine-stamped `tier` and stays at most one event of 1 KB. `dns-rebinding` and `private-answer-for-public-name` share `dedupGroup` `private-answer`. `reflection-participation` and `coap-amplification` share `reflection`. `proxy-relay` and `credential-stuffing-out` share `proxy-relay`. An incident scores one contribution per group: the highest severity weight times confidence.

## Tests added

`evidence.test.js`: a `0.0.0.0` answer still emits both detectors, the incident score is 45, and the fingerprint matches after `exportBaseline` / `importBaseline`. A second test omits `evidence` when the option is false.

## Fast check

```
✔ proxy session, LAN ADB sweep, and an RPC lookup become one incident (27.144375ms)
✔ a telnet scan plus a GRE flood is a multi-stage incident (30.4315ms)
✔ a known SNI that changes certificate issuer is a MITM (16.7655ms)
✔ maps an anomaly to a Detection Finding (3.437958ms)
✔ formats RFC 5424 with a CEF message (1.725583ms)
✔ retries, then sends the HMAC header (0.858ms)
✔ throws after the last failed attempt (0.293042ms)
ℹ tests 106
ℹ suites 0
ℹ pass 106
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 55952.209209
```

## Thresholds

None.
