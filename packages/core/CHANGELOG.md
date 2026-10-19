# Changelog

## Unreleased

`explain(anomalyId)` returns why an anomaly fired: `test`, `observed`, and either `threshold` or `learned`, plus `suppressWith`. `explainCap` (default 1,000) is an engine-wide LRU. A hard-rule explanation never offers `allow()`, and `suppress` lasts at most 24 hours. `spec-coverage` prints `explains: X of Y detectors`.

When `reorderMs` is greater than 0, `feed()` holds events and delivers them in timestamp order. `reorderMs: 0` does not create a buffer. The hold is capped by `maxBuffered` (default 50,000) and is part of `checkpoint()`. Hosts that merge two log sources set `reorderMs: 5000`; alerts wait that long.

A checkpoint keeps each detector's live state, including open-window counters that `exportBaseline()` does not store, and `restore()` puts that state back.

`packages/core/src/engine/stats/` holds Welford, EWMA, P², HyperLogLog, Count-Min, Page CUSUM, Page–Hinkley, and a seeded FNV-1a/fmix32 hash. No detector reads them yet. Count-Min is LAN-wide scratch only.

`volume-spike`, `fan-out`, and `volume-spike-hourly` keep a Welford summary (count, mean, M2, max) instead of a sample ring. Baseline version 3. A version 2 baseline still imports by folding its samples. Idle learning windows still count as zero. The 200-device 7-day bench retained 66.96 KB/device.

`exploit-probe-http`, `young-domain`, and `ttl-anomaly` run in shadow mode and stay enabled. A shadow draft is a `shadow-anomaly`. It has no `incidentId`, does not count toward `alert-storm`, and is not passed to `post-update-drift` or `supply-chain-suspect`. `detectors[id].mode: 'live'` promotes one and warns `SHADOW_PROMOTED_BY_HOST` once. `detectors[id].canary` runs a second copy of a live detector in shadow, at most four per engine, and that copy is not written into a baseline or a checkpoint. The engine does not read `mode` as a no-op anymore. `http.direction` is `out` or `in`; any other value is dropped. Indicator type `young-domain` matches a name and its subdomains, and expired rows are ignored. `src/data/http-probes.json` is the path and marker list for `exploit-probe-http`. `threat-intel-match` joins `dedupGroup` `indicator`, so an incident scores that group once when `young-domain` fires on the same device in the same window. `flow.ttl` is read by `ttl-anomaly`. No shipped adapter fills it. `class-violation` does not treat a LAN flow to a multicast, broadcast, or link-local address as an inbound session. A destination in `224.0.0.0/4`, `255.255.255.255`, or `ff00::/8` is a group send. `new-destination`, `new-port`, `lan-lateral`, `horizontal-scan`, `vertical-scan`, and `lan-sweep` skip it, and `fan-out`'s per-window host count does too. `posture-listening-risky` counts a listen port only when the device is the responder: direction `in`, or direction `lan` with `dstIp` equal to the device id. Sending to port 1900 is not listening on 1900. `reflection-participation`, `coap-amplification`, and `ttl-anomaly` are unchanged.

## 0.5.0

Local release, not published. `flush()` with no argument drains every open window whose start is at or before the watermark, then ticks at the watermark. `flush(now)` still closes only windows whose end is at or before `now`. `reorderMs` defaults to 0. A backward step inside the open window is accepted. A backward step outside that window and larger than `reorderMs` is `CLOCK_JUMP`. An event that would reopen a closed window is `LATE_EVENT` and is dropped. `went-silent` alerts from `tick()`, once, while the tick time is inside a learned active hour. `answer-drift` keeps every answer key seen while learning, up to 8. `smart-tv` is a loadable class: 120 families, 50 MB uploaded per hour, no inbound LAN, and `allowsBrowserJa4`. Learning warnings use `SUSPICIOUS_LEARNING` with a `reason`. `stats().learningQuality` reports whether a device is ready to lock. `minLearnWindows` defaults to 0. `tier-silent` arms a tier on its first event. It reports that tier when the tier's own silence limit has passed and another armed tier has produced an event within `tierSilentMs` (default 6 h). T4's own limit defaults to 26 h. Anomalies carry `schema`, a stable `fingerprint` of the detector, device, and dedup key (not the display text), and `evidence` unless `evidence` is false. Shared dedup groups are `private-answer`, `reflection`, `proxy-relay`, and `flood`. `identity-change` keeps the first DHCP fingerprint per MAC, at most 5,000 MACs. A different fingerprint during learning emits `SUSPICIOUS_LEARNING` reason `identity-change` and does not replace the stored value. A different fingerprint while watching alerts. `egress-flood` reports a one-way public upload of at least 50,000 packets or 200 MB in one window, and while watching also a burst of at least 5,000 packets and ten times the learned per-destination maximum. `proxy-sdk-traffic` matches a host-supplied `proxy-sdk` indicator and is medium on `smart-tv` and `tv-box`, high otherwise. `checkpoint()` and `restore()` snapshot the baseline, LAN scratch tables, watermark, and learning progress. `restore()` rejects a known scratch table whose shape is wrong. A tier listed in `tiers` with no events by the end of `learnMs` emits warning `TIER_NEVER_SEEN` once and does not raise an anomaly. `allow(device, 'fingerprint', value)` records a DHCP fingerprint that `identity-change` will not alert on after lock. `feed()` dispatches an event only to detectors whose `meta.consumes` lists that event type. An empty `consumes` array still runs on window close and on engine signals. `stream-to-new-destination` no longer uses a `bytesIn / bytesOut` guard. It stays quiet only when `egress-flood` has already fired for the same device and destination address in that window. The library still only reports. Not validated on real traffic.

## 0.4.0

Network-layer detection: TLS metadata, proxy backconnect, peer-to-peer shape, DNS answer drift and fast-flux, building-protocol writes, MQTT topics, ONVIF changes, and fleet comparison. Zeek and Suricata parsers, plus OCSF, syslog, and webhook exporters. A `discovery` event is accepted; an unknown discovery proto is dropped with `FIELD_DROPPED`. The library still only reports. Not validated on real traffic.

## 0.3.0

Device-class priors, incidents, and the 0.3 detectors: proxy relay, chain lookups, direct-to-IP, ASN and country, UPnP mappings, Tor indicators, sweeps, brute force, slow exfil, beacons, DGA, DNS tunnels, ARP/DHCP/RA, zones, tunnels, firmware downloads, and OT on the WAN. The library still only reports. Not validated on real traffic.

## 0.2.0

Flow and DNS detectors, threat indicators, policy rules, and the two log parsers. The library still only reports. Defaults that were not in the 0.1 tables are written in `docs/SPEC.md` under "Defaults shipped in 0.2". Not validated on real traffic.

## 0.1.0

Plugin engine. The original four detectors are plugins. Adds typed events, baseline v2 with optional HMAC-SHA256, and the public methods from the spec (`feedBatch`, `lock`, `relearn`, `allow`, `suppress`, `ack`, `forget`, `setPeerGroup`, `use`, `stats`, `loadIndicators`). Version 1 baselines still import. Not validated on real traffic.

## 0.0.1

Prototype engine, kept as the regression baseline. Four detectors: `new-destination`, `fan-out`, `volume-spike`, `wrong-time`. Not validated on real traffic.
