# WP-7

Date: 2026-10-17. Package: `iotwarden@0.4.0`.

## What changed

`checkpoint()` writes the baseline, the watermark, per-device learning progress, and the LAN scratch tables (`arp-spoof`, `identity-change`, `dhcp-starvation`, `fleet-wave`). A snapshot over 16 MB drops the oldest ARP bindings, then the oldest learned MACs, and emits `CHECKPOINT_TRUNCATED`. `restore()` checks the snapshot, including the same HMAC path as baselines, and replaces state only after that check. An unknown scratch table is rejected.

## Tests added

`checkpoint.test.js`: an ARP binding survives restore and the next claim of the gateway IP is `arp-spoof`. A fresh engine that never saw the original binding stays quiet. One thousand seeded corrupt checkpoints throw and leave the baseline unchanged.

## Fast check

```
✔ formats RFC 5424 with a CEF message (2.907084ms)
✔ retries, then sends the HMAC header (0.882833ms)
✔ throws after the last failed attempt (0.292375ms)
✔ a large UDP upload to one public address is an egress flood during learning (45.601791ms)
✔ a smart TV proxy SDK followed by a LAN session is one incident (39.081583ms)
ℹ tests 117
ℹ suites 0
ℹ pass 117
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 92336.939792
```

## Thresholds

| Item             | Before        | After |
| ---------------- | ------------- | ----- |
| checkpoint bytes | not an option | 16 MB |
