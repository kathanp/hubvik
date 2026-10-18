# Detector catalog (109 shipped live plus 3 early shadow, off by default)

Each detector is `packages/core/src/detectors/<id>.js` and is registered in `packages/core/src/detectors/index.js`. `requires` is the tier list. `hard` means `hardRule: true` (fires during learning). Severity is the default. Tunables are the other `defaults`. The full prose is `docs/SPEC.md`. The numeric defaults that were chosen so the benign gate still passes are under "Defaults shipped in 0.2", "0.3", and "0.4".

Changing any number in this table requires a SPEC edit and a CHANGELOG line.

## T0 — on by default

| id                     | hard | severity | tunables                                                                                                                                                                                                                                                                            |
| ---------------------- | ---- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `new-destination`      |      | medium   | `maxNewDstPerWindow=3`                                                                                                                                                                                                                                                              |
| `new-domain-family`    |      | medium   | `maxNewFamiliesPerWindow=3`                                                                                                                                                                                                                                                         |
| `fan-out`              |      | high     | `minFanout=10`, `fanoutFactor=3`                                                                                                                                                                                                                                                    |
| `volume-spike`         |      | high     | `sigma=4`, `minBytes=1000000`, `peakFactor=2`                                                                                                                                                                                                                                       |
| `volume-spike-hourly`  |      | high     | same shape as volume-spike, per hour of day                                                                                                                                                                                                                                         |
| `wrong-time`           |      | low      | dedup key is `day:hour`                                                                                                                                                                                                                                                             |
| `went-silent`          |      | medium   | `factor=3`, `sessionMs=21600000` (6 h). `tick()` only. Alerts once while `now` is inside a learned active hour and the gap since the last event exceeds `factor ×` the learned max gap. A device that is still sending does not alert. Print minutes when the limit is under 1 hour |
| `threat-intel-match`   | hard | critical | empty index means no alert                                                                                                                                                                                                                                                          |
| `new-device`           | hard | medium   | first event is during that device's learning; alert only if `ev.ts - startedAt > learnMs`                                                                                                                                                                                           |
| `policy-violation`     | hard | high     | empty policy means no alert                                                                                                                                                                                                                                                         |
| `input-gap`            | hard | high     | engine signal, flush only. See `02-ENGINE.md`                                                                                                                                                                                                                                       |
| `clock-jump`           | hard | medium   | `maxForwardMs=129600000` (36 h)                                                                                                                                                                                                                                                     |
| `state-cap`            | hard | medium   | engine signal                                                                                                                                                                                                                                                                       |
| `alert-storm`          | hard | medium   | `maxPerMinute=1000`                                                                                                                                                                                                                                                                 |
| `tier-silent`          | hard | high     | armed on a tier's first event. Default limit 6 h. T4 defaults to 26 h. A never-seen tier stays quiet. Another armed tier must have an event within 6 h                                                                                                                              |
| `class-violation`      | hard | high     | no class means no alert                                                                                                                                                                                                                                                             |
| `supply-chain-suspect` | hard | critical | engine signal only                                                                                                                                                                                                                                                                  |
| `post-update-drift`    | hard | high     | engine signal only                                                                                                                                                                                                                                                                  |
| `peer-divergence`      |      | high     | `minPeers=5`. No group, or fewer than 5 other seen peers, means no alert                                                                                                                                                                                                            |
| `fleet-wave`           |      | medium   | `minDevices=3`, `windowMs=600000`. `data.peersAffected`, `data.sameGroup`. One device never alerts                                                                                                                                                                                  |

`went-silent` runs from `tick()`, not from the next event. A tick at the watermark months later does not page, because the clock is the watermark.

`fan-out` `expected` uses the ASCII string `<= ${limit}`. `volume-spike` alerts when bytes are greater than the limit, `ts` is the window start, and an idle window with `bytes === 0` returns. Population standard deviation. Root options `sigma`, `minBytes`, `peakFactor`, `minFanout`, `fanoutFactor`, `maxNewDstPerWindow` override these four originals only when the caller passes them.

## T1 — flows

| id                          | hard | severity | tunables / behavior                                                                                                                                                                                      |
| --------------------------- | ---- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `new-port`                  |      | medium   | port set                                                                                                                                                                                                 |
| `new-protocol`              |      | high     | protocol set. `proto` may be `esp` or a number, including 41 and 50                                                                                                                                      |
| `horizontal-scan`           | hard | critical | `minHosts=20`, `minHardHosts=10` on ports 23, 2323, 5555, 7547 during learning, `factor=3`                                                                                                               |
| `vertical-scan`             |      | high     | `minPorts=15`, `factor=3`. `learn` records, `check` alerts                                                                                                                                               |
| `failed-connection-ratio`   |      | high     | `minAttempts=20`, `minRatio=0.8`                                                                                                                                                                         |
| `lan-lateral`               |      | high     | `direction: 'lan'`                                                                                                                                                                                       |
| `upload-ratio-shift`        |      | high     | `minBytes=10000`, `shift=0.35`                                                                                                                                                                           |
| `packet-flood`              | hard | critical | `minPackets=500`, `maxBytesPerPacket=100`. `dedupGroup` `flood`. `data.bytesPerPacket`                                                                                                                   |
| `egress-flood`              | hard | critical | public destination, upload ratio under 0.05, and at least 50,000 packets or 200 MB out. While watching, also at least 5,000 packets and ten times the learned per-destination maximum. Same `dedupGroup` |
| `reflection-participation`  | hard | critical | `minRatio=3`, `minBytes=300`. UDP source ports 123, 1900, 3702, 5353, 5683                                                                                                                               |
| `coap-amplification`        | hard | critical | same ratio. Source port 5683 is also in the reflection set, so both fire                                                                                                                                 |
| `bogon-destination`         |      | medium   | outbound flow to a bogon                                                                                                                                                                                 |
| `inbound-from-wan`          | hard | high     | risky ports during learning; other inbound ports are remembered and do not alert yet                                                                                                                     |
| `adb-exposure`              | hard | critical | TCP 5555                                                                                                                                                                                                 |
| `mqtt-new-broker`           |      | high     | ports 1883 and 8883                                                                                                                                                                                      |
| `spam-relay`                | hard | high     | `minConnections=10` per hour, or any SMTP from a device that never sent mail                                                                                                                             |
| `tftp-activity`             | hard | high     | UDP 69 to WAN                                                                                                                                                                                            |
| `posture-listening-risky`   |      | low      | listens on 23, 2323, 5555, 7547, 1900, 502, 47808                                                                                                                                                        |
| `posture-wan-exposed`       |      | low      |                                                                                                                                                                                                          |
| `upnp-port-open`            |      | high     | `mapping` event                                                                                                                                                                                          |
| `tor-or-proxy`              | hard | high     | indicator type `tor`, not type `ip`                                                                                                                                                                      |
| `lan-sweep`                 |      | high     | `minTargets=20`, so 21 unique targets fire. ARP request or ICMP to a bogon. Requires T1                                                                                                                  |
| `brute-force-out`           | hard | critical | `minHits=15`. Ports 22, 23, 3389, 554, 1883, 8080. `direction: 'out'`, tcp, `durationMs<=2000`, `bytes<=2000`                                                                                            |
| `brute-force-in`            |      | high     | same shape, `direction: 'in'`, reports `srcIp`                                                                                                                                                           |
| `slow-exfil`                |      | high     | CUSUM on hourly `bytesOut`. Samples only while learning. Need at least 6 completed hours. Limit `max(5 × mean, 1e6)`. Live check can alert on the open hour. Do not double-count                         |
| `protocol-mix-shift`        |      | high     | `minPackets=20`, non-TCP share jumps by `band=0.35` above the learned max. Uses `onWindowClose`                                                                                                          |
| `connection-churn`          |      | high     | `minCount=50` or `3 ×` learned max flows per window                                                                                                                                                      |
| `new-beacon`                |      | high     | `minCount=20`, MAD/median ≤ 0.25, size max/min ≤ 3. Only destinations absent from the baseline. Tracks are ephemeral; export the baseline only                                                           |
| `long-connection`           |      | high     | `minDurationMs=600000` or the learned p99, to a destination not in the baseline                                                                                                                          |
| `src-spoof`                 | hard | critical | DHCP ack `requestedIp` sets the lease first. A later flow whose `srcIp` differs alerts once                                                                                                              |
| `icmp-redirect`             | hard | high     | `proto: 'icmp'` and `icmpType === 5`, unless `srcIp` is `gatewayIp`                                                                                                                                      |
| `zone-violation`            |      | high     | `zones: [{id, cidr}]`. `direction: 'lan'` and src/dst in different zones. No zones means no alert                                                                                                        |
| `stream-to-new-destination` |      | critical | `dstPort === 554` or `bytesOut >= minMediaBytes` (1e6), destination not in the baseline                                                                                                                  |
| `cryptomining`              | hard | high     | app op matching `/mining\.(subscribe\|authorize)/` or a name in `src/data/pools.json`. Requires T1 so it also sees app and dns when T1 is on                                                             |
| `ot-wan-exposure`           | hard | critical | ports 502, 47808, 20000, 44818, 102, 1911, 4911. Out to a public dst, or in from a public src                                                                                                            |
| `vpn-protocol`              |      | high     | WireGuard is UDP 51820 and `bytesOut === 148`. OpenVPN UDP 1194. IPsec UDP 500/4500. ESP is `proto` `'esp'` or 50. SSH is TCP 22. New kind versus the baseline                                           |
| `icmp-tunnel`               |      | high     | ICMP, `icmpType !== 5`, bytes/packet ≥ 200                                                                                                                                                               |
| `ipv6-tunnel`               |      | high     | proto 41 (6in4) or UDP 3544 (Teredo)                                                                                                                                                                     |
| `ntp-rogue`                 |      | medium   | UDP destination port 123, new `dstIp`                                                                                                                                                                    |
| `update-from-new-source`    |      | high     | inbound `bytesIn > max(5e6, learned p99)` from a host not in the baseline. 2e6 does not fire                                                                                                             |
| `update-over-cleartext`     |      | medium   | inbound ≥ 1e6 on port 80, 21, or 69                                                                                                                                                                      |
| `posture-cleartext-auth`    |      | low      | TCP port 21 or 23. Not a hard rule, so a long `learnMs` stays quiet                                                                                                                                      |
| `cleartext-regression`      |      | high     | a destination seen on TLS (SNI, or port 443/8883) later seen in cleartext (HTTP host, or port 21/23/80/1883)                                                                                             |
| `proxy-backconnect`         |      | critical | `controlMs=60000`, then `minBursts=8` flows of ≤ 2 s within `burstMs=5000`                                                                                                                               |
| `lan-via-proxy`             |      | critical | `direction: 'lan'` within `followMs=1000` of an inbound flow with `bytesIn > 0`                                                                                                                          |
| `p2p-pattern`               |      | high     | `minPeers=30` on `dstPort > 1024` and inbound share ≥ 0.3 in one window                                                                                                                                  |
| `credential-stuffing-out`   |      | high     | `minSites=15` short (≤ 3 s) port-443 sessions to different names in one window                                                                                                                           |
| `quic-new`                  |      | medium   | UDP 443 to a destination not in the baseline                                                                                                                                                             |
| `beacon-change`             |      | medium   | `minGaps=8`, `factor=2`. Learn stores a median once there are 4 gaps. Watching compares the median of the last 8 gaps                                                                                    |
| `proxy-relay`               | hard | critical | `minDomains=6` and `minCategories=2` in one UTC hour. Categories from `src/data/consumer.json`: shopping, social, ticketing                                                                              |
| `direct-ip`                 |      | medium   | requires T1 and T2. A public outbound flow with no `dstName` that was never in a DNS A answer                                                                                                            |
| `new-asn`                   |      | medium   | `lookup(ip)` returns `{asn, country}` or null                                                                                                                                                            |
| `new-country`               |      | low      | same lookup                                                                                                                                                                                              |

## T2 — DNS

| id                               | hard | severity | tunables / behavior                                                                                                                                                     |
| -------------------------------- | ---- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nxdomain-burst`                 |      | high     | `minCount=10` or `3 ×` learned max per window                                                                                                                           |
| `resolver-bypass`                |      | high     | resolver set                                                                                                                                                            |
| `dns-rebinding`                  |      | high     | public name answers a bogon, including `0.0.0.0`                                                                                                                        |
| `private-answer-for-public-name` |      | high     | same address set. A test expects both detectors to fire on `0.0.0.0`                                                                                                    |
| `dga`                            |      | high     | `minBurst=5`. Label ≥ 12, letters ≥ 8, entropy ≥ 3.3, English bigram hit rate < 0.2, vowels < 0.25 or digit ratio > 0.15. Bigrams in `src/data/bigrams.json`            |
| `dns-tunnel`                     | hard | critical | `minScore=3`. Long label, entropy, many names under one parent, TXT/NULL/CNAME, or > 30 queries                                                                         |
| `blockchain-c2`                  | hard | high     | `qname` or `dstName` ends with a name in `src/data/rpc.json`. Classes `wallet` and `node` would skip, and those classes are not shipped, so an unset class still alerts |
| `tunnel-service`                 |      | high     | names in `src/data/tunnels.json` (ngrok, Cloudflare Tunnel, Tailscale, ZeroTier)                                                                                        |
| `answer-drift`                   |      | high     | per qname, the key is `lookup().asn` when present, otherwise the A value. A later new key alerts                                                                        |
| `fast-flux`                      |      | high     | `minAnswers=8` distinct A values in one window and some `ttl <= maxTtl` (60)                                                                                            |
| `ad-fraud`                       |      | medium   | `minDomains=5` names in one window that `exactHit` type `ad`. No ad indicators means no alert                                                                           |
| `proxy-sdk-traffic`              | hard | high     | host-supplied indicator type `proxy-sdk`. Medium on `smart-tv` and `tv-box`, high otherwise. Core ships no list                                                         |

## T3 — TLS metadata

JA4 is the host's string. Nothing here computes a fingerprint.

| id                       | hard | severity | behavior                                                                                                                                                                      |
| ------------------------ | ---- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `new-client-fingerprint` |      | high     | JA4 absent from the learned set                                                                                                                                               |
| `cert-change`            |      | high     | issuer for a known SNI changes. The first issuer is stored in `learn`, not in `check`, so a test must learn and then `lock`                                                   |
| `sni-missing`            |      | medium   | handshake with no SNI to an address that never presented one                                                                                                                  |
| `tls-on-odd-port`        |      | medium   | TLS to a destination port that was not learned                                                                                                                                |
| `browser-mimic`          |      | high     | JA4 is in `browserJa4`, a class is set, and `allowsBrowserJa4` is not true. The flag is true on `tv-box`, `nas`, `hub`, and `smart-tv`. No class or an empty list stays quiet |
| `posture-weak-tls`       |      | low      | version `TLSv1.0`, `TLSv1.1`, `SSLv3`, `SSLv2`, or `cert.selfSigned`, or `cert.notAfter < ev.ts`                                                                              |

## T4 — link layer

| id                     | hard | severity | behavior                                                                                                                                                                                                                                                                          |
| ---------------------- | ---- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `arp-spoof`            | hard | critical | one LAN table on `ctx.scratch`, not per device. Gateway IP change alerts during learning. Other binding changes only when watching. One MAC with more than `maxIpsPerMac` (8) alerts only when watching. A DHCP ack/offer with `requestedIp` updates the binding without an alert |
| `gratuitous-arp-flood` |      | high     | `minCount=30` per window                                                                                                                                                                                                                                                          |
| `rogue-dhcp`           | hard | critical | offer/ack. If `dhcpServers` is non-empty, any other server alerts. If empty, the first server is learned and a different one alerts                                                                                                                                               |
| `dhcp-starvation`      |      | high     | `minMacs=20` unique discover MACs per window, shared scratch                                                                                                                                                                                                                      |
| `rogue-ra`             | hard | critical | same first-router / `routers` pattern                                                                                                                                                                                                                                             |
| `identity-change`      |      | high     | host-supplied `dhcp.fingerprint`, at most 5,000 MACs. Learning keeps the first fingerprint and emits `SUSPICIOUS_LEARNING` reason `identity-change` when it changes. Watching alerts. Do not compute JA4T                                                                         |

## T5 — building protocols and MQTT / ONVIF

`app` events. Write ops are `WriteProperty`, `WritePropertyMultiple`, `fc5`, `fc6`, `fc15`, `fc16`. Dangerous ops (hard rule) are `ReinitializeDevice`, `DeviceCommunicationControl`, `AtomicWriteFile`, `fc8`, `STOP`, `download`. Recon ops are `Who-Is`, `Who-Has`, `fc43`.

| id                        | hard | severity | tunables / behavior                                                                                         |
| ------------------------- | ---- | -------- | ----------------------------------------------------------------------------------------------------------- |
| `ot-new-master`           |      | critical | new `peerIp`                                                                                                |
| `ot-write-new`            |      | high     | new `peerIp\|op\|target` for a write                                                                        |
| `ot-dangerous-op`         | hard | critical | one of the dangerous ops                                                                                    |
| `ot-value-out-of-range`   |      | critical | `minSamples=3`. Numeric `value` outside the learned min/max for that target                                 |
| `ot-write-rate`           |      | high     | `minWrites=10`, `factor=3`, on window close                                                                 |
| `ot-recon`                |      | high     | `minTargets=10`, so 11 fires. Also a flow to 47808, 502, 102, 44818, 20000, 1911, 4911                      |
| `ot-spoof`                |      | critical | second `peerIp` claiming an `I-Am` target. `learn` records the first owner                                  |
| `ot-error-burst`          |      | medium   | `minErrors=10` results `error` or `reject` per window                                                       |
| `mqtt-wildcard-subscribe` |      | high     | MQTT `SUBSCRIBE` of `#`, a topic containing `/+`, or a topic starting with `+`                              |
| `mqtt-topic-new`          |      | medium   | publish/subscribe prefix (first two path segments) not learned. `cmd`, `ota`, and `config` raise confidence |
| `mqtt-publish-rate`       |      | medium   | `minPublishes=30` per window                                                                                |
| `onvif-config-change`     | hard | critical | `SetUser`, `SetNetworkInterfaces`, `SetSystemFactoryDefault`, `UpgradeSystemFirmware`                       |

## Early shadow

These three are Rel 0.8. `defaults.enabled` is true and `meta.mode` is `shadow`. Drafts are `shadow-anomaly` events. Promote one with `detectors: { id: { mode: 'live' } }`.

| Detector             | Tier | Severity                                                                 | Behavior                                                                                                                                                        |
| -------------------- | ---- | ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `exploit-probe-http` | T3   | critical outbound, low inbound, high inbound with 2xx, medium if unknown | Substring match of `src/data/http-probes.json` after one percent-decode. Once per device, direction, path without query, and matched entry per 24 h. Cap 1,000. |
| `young-domain`       | T2   | medium                                                                   | Host indicator type `young-domain`. Once per registrable family per device per 24 h. Cap 1,000. `dedupGroup` `indicator`, shared with `threat-intel-match`.     |
| `ttl-anomaly`        | T1   | medium                                                                   | Outbound TTL bucket 64, 128, or 255 after 20 samples. Skips multicast, broadcast, and link-local. A TTL under 16 is ignored.                                    |

## Multicast and broadcast destinations

A flow to `224.0.0.0/4`, `255.255.255.255`, or `ff00::/8` is a group send. `isGroupDst` in `packages/core/src/detectors/lib.js` is the only check. `new-destination`, `new-port`, `lan-lateral`, `horizontal-scan`, `vertical-scan`, and `lan-sweep` skip those destinations. `fan-out` does not count them in the window's host set. `posture-listening-risky` reports a listen port only when the device is the responder (`direction` `in`, or `lan` with `dstIp` equal to the device id). `reflection-participation`, `coap-amplification`, and `ttl-anomaly` still treat discovery traffic the way they did before this rule.

## Not implemented

Marked 1.x or 1.0. Leave them until the human asks and until real-traffic evaluation exists. A 1.x row needs a numeric default in SPEC before code.

- `day-of-week-drift`
- `sni-ip-mismatch`
- `mac-randomization-churn`
- `discovery-spoof`
- `mud-violation`
- `fleet-baseline-poisoning`
- `ot-schedule-drift`
- `reverse-shell-shape`
- `llmnr-nbns-poison`
- `dns-answer-mismatch`

Also not built: host-declared physical limits on `ot-value-out-of-range`, and payload-size tracking on `mqtt-publish-rate` (rate only). `SUSPICIOUS_LEARNING` is implemented. Reasons: `family-churn`, `gre`, `telnet-out`, `nxdomain-burst`, `adb`, `proxy-shape`, `identity-change`.

## Tests that cover the catalog

There is not yet one test file per detector. The gate runs grouped suites. Do not delete them.

| File                                                | Covers                                                                                                                                          |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/core/test/engine.test.js`                 | the original six prototype cases                                                                                                                |
| `packages/core/test/engine-api.test.js`             | API, validation, caps, HMAC, v1 upgrade                                                                                                         |
| `packages/core/test/benign.test.js`                 | 14 days, zero anomalies of any severity                                                                                                         |
| `packages/core/test/benign-matrix.test.js`          | 14 days × 7 classes × 3 seeds, nothing ≥ medium                                                                                                 |
| `packages/core/test/phase2.test.js`                 | 0.2 detectors                                                                                                                                   |
| `packages/core/test/phase3.test.js`                 | 0.3 detectors                                                                                                                                   |
| `packages/core/test/phase4.test.js`                 | 0.4 detectors                                                                                                                                   |
| `packages/core/test/detectors/*.test.js`            | one file per newer detector, including `tier-silent`, `identity-change`, `went-silent`, `exploit-probe-http`, `young-domain`, and `ttl-anomaly` |
| `packages/core/test/fingerprint.test.js`            | same scan, different host counts, one fingerprint                                                                                               |
| `packages/core/test/checkpoint.test.js`             | restore, corrupt checkpoints, broken scratch                                                                                                    |
| `packages/core/test/replay/*.test.js`               | badbox-like, kimwolf-like, mirai-like, bms-hijack, mitm                                                                                         |
| `packages/adapter-*/test`, `packages/export-*/test` | parsers and formatters                                                                                                                          |

`dns-rebinding` and `private-answer-for-public-name` both match `0.0.0.0`. The phase 2 test expects length 2 and 2. Do not special-case that without a spec change.

A non-hard detector that should fire on the first watching event is tested with `learnMs: 0`. A hard-rule flag on the anomaly is tested with a long `learnMs` and no `lock()`.
