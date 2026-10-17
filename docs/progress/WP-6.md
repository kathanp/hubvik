# WP-6

Date: 2026-10-17. Package: `iotwarden@0.4.0`.

## What changed

`egress-flood` reports a one-way flow to a public address that reaches 50,000 packets or 200 MB in one window. While watching it also reports at least 5,000 packets and ten times the learned per-destination maximum. `proxy-sdk-traffic` matches a host-supplied `proxy-sdk` indicator on `qname`, `dstName`, or SNI. Severity is medium, with `consentPossible: true`, on `smart-tv` and `tv-box`, and high otherwise. `packet-flood` already reported `bytesPerPacket`; it now shares `dedupGroup` `flood` with `egress-flood`. `browser-mimic` reads `allowsBrowserJa4` from the class file. That flag is true for `tv-box`, `nas`, `hub`, and `smart-tv`.

## Tests added

`test/replay/large-udp-flood.test.js` and `test/replay/smart-tv-proxy-sdk.test.js`. `browser-mimic.test.js` keeps a smart TV quiet and fires on a camera. `egress-flood.test.js` covers the learned-maximum path. `proxy-sdk-traffic.test.js` expects high severity on a camera.

## Fast check

```
✔ a known SNI that changes certificate issuer is a MITM (9.613708ms)
✔ maps an anomaly to a Detection Finding (1.577875ms)
✔ formats RFC 5424 with a CEF message (4.907875ms)
✔ retries, then sends the HMAC header (0.875583ms)
✔ throws after the last failed attempt (0.282334ms)
✔ a large UDP upload to one public address is an egress flood during learning (28.736167ms)
✔ a smart TV proxy SDK followed by a LAN session is one incident (11.381959ms)
ℹ tests 115
ℹ suites 0
ℹ pass 115
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 103295.441083
```

## Thresholds

| Item                       | Before         | After                              |
| -------------------------- | -------------- | ---------------------------------- |
| `egress-flood.minPkts`     | not a detector | 50000                              |
| `egress-flood.minBytesOut` | not a detector | 200000000                          |
| `egress-flood.watchFactor` | not a detector | 10                                 |
| `egress-flood.watchFloor`  | not a detector | 5000                               |
| `allowsBrowserJa4`         | hard-coded set | true on tv-box, nas, hub, smart-tv |
