# WP-3

Date: 2026-10-17. Package: `iotwarden@0.4.0`.

## What changed

`tier-silent` fires when an enabled tier has had no events for 6 h while another enabled tier is still live. Learning warnings use `SUSPICIOUS_LEARNING` with one of six reasons. `stats().learningQuality` reports windows, families, suspicious reasons, and `ready`. `minLearnWindows` defaults to 0. A device held past `learnMs` emits `LEARNING_EXTENDED` once. `lock()` on a device that is not ready emits `LOCKED_UNREVIEWED` and still enters watching.

The all-tier simulator now keeps every enabled tier fresh: a one-byte T0 summary beside each flow, DHCP and ARP once per active hour, and a quiet MQTT publish on classes that do not already emit an app event. That is fixture traffic, not a detector change. `tier-silent` still treats a tier that was never seen as quiet.

## Tests added

`learning-quality.test.js` fires each suspicious-learning reason, `LOCKED_UNREVIEWED`, and `LEARNING_EXTENDED`. `tier-silent.test.js` stops DNS for 6 h and expects the DNS detectors named on tier T2. Both benign matrices assert no `SUSPICIOUS_LEARNING` warnings.

## Fast check

```
✔ a telnet scan plus a GRE flood is a multi-stage incident (230.677917ms)
✔ a known SNI that changes certificate issuer is a MITM (8.267459ms)
✔ maps an anomaly to a Detection Finding (16.191708ms)
✔ formats RFC 5424 with a CEF message (5.71175ms)
✔ retries, then sends the HMAC header (3.009042ms)
✔ throws after the last failed attempt (1.769291ms)
ℹ tests 104
ℹ suites 0
ℹ pass 104
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 110624.197292
```

## Thresholds

| Item              | Before        | After       |
| ----------------- | ------------- | ----------- |
| `minLearnWindows` | not an option | 0           |
| `tierSilentMs`    | not an option | 21600000 ms |
