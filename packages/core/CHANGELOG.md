# Changelog

## 0.5.0

Local release, not published. `flush()` with no argument drains every open window whose start is at or before the watermark, then ticks at the watermark. `flush(now)` still closes only windows whose end is at or before `now`. `reorderMs` defaults to 0. A backward step inside the open window is accepted. A backward step outside that window and larger than `reorderMs` is `CLOCK_JUMP`. An event that would reopen a closed window is `LATE_EVENT` and is dropped. `went-silent` alerts from `tick()`, once, while the tick time is inside a learned active hour. `answer-drift` keeps every answer key seen while learning, up to 8. `smart-tv` is a loadable class: 120 families, 50 MB uploaded per hour, no inbound LAN, and `allowsBrowserJa4`. Learning warnings use `SUSPICIOUS_LEARNING` with a `reason`. `stats().learningQuality` reports whether a device is ready to lock. `minLearnWindows` defaults to 0. `tier-silent` arms a tier on its first event. It reports that tier when the tier's own silence limit has passed and another armed tier has produced an event within `tierSilentMs` (default 6 h). T4's own limit defaults to 26 h. Anomalies carry `schema`, a stable `fingerprint`, and `evidence` unless `evidence` is false. Shared dedup groups are `private-answer`, `reflection`, `proxy-relay`, and `flood`. `identity-change` learns one DHCP fingerprint per MAC, at most 5,000 MACs. `egress-flood` reports a one-way public upload of at least 50,000 packets or 200 MB in one window, and while watching also a burst of at least 5,000 packets and ten times the learned per-destination maximum. `proxy-sdk-traffic` matches a host-supplied `proxy-sdk` indicator and is medium on `smart-tv` and `tv-box`, high otherwise. `checkpoint()` and `restore()` snapshot the baseline, LAN scratch tables, watermark, and learning progress. The library still only reports. Not validated on real traffic.

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
