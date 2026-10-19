# Engine behavior that the code actually implements

`docs/SPEC.md` is the contract. This file is how `packages/core/src/engine/engine.js` fulfills it, including the decisions that are easy to break.

## Event types

`feed` validates before any detector runs. Unknown `type` throws `TypeError`. A missing `device` throws. Optional bad fields are dropped and counted as `warning` `FIELD_DROPPED`.

| type      | Tier tag | Required fields                           | Notes                                                                                                                                                                                                                         |
| --------- | -------- | ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| (none)    | T0       | `device`                                  | Summary. `dst`, `bytes`, `ts` optional                                                                                                                                                                                        |
| `flow`    | T1       | `device`                                  | Addresses, ports, `proto`, `direction` `out\|in\|lan`, byte and packet counters, `durationMs`, `tcpOutcome`, `dstName`, `icmpType`                                                                                            |
| `dns`     | T2       | `device`, `qname`                         | `qtype`, `rcode`, `resolver`, `answers[]` of `{type, value, ttl}`                                                                                                                                                             |
| `tls`     | T3       | `device`, `dstIp`, `dstPort`              | `sni`, `ja4` (string ≤ 255), `version` (≤ 32), `alpn` (≤ 8 strings), `cert.{issuer, subject, sha256, selfSigned, notAfter}`                                                                                                   |
| `http`    | T3       | `device`, `dstIp`, `dstPort`, `method`    | `host`, `path`, `status`, `direction` `out` or `in`. Any other `direction` is dropped with `FIELD_DROPPED`                                                                                                                    |
| `mapping` | T1       | `device`, `proto`, `port`                 | `proto` is `upnp`, `nat-pmp`, or `pcp`                                                                                                                                                                                        |
| `arp`     | T4       | `ip`, `mac`, `op`                         | `device` optional                                                                                                                                                                                                             |
| `dhcp`    | T4       | `mac`, `msg`                              | `serverIp`, `requestedIp`, `v6`, `duid`, `iaid`                                                                                                                                                                               |
| `ra`      | T4       | `srcMac`, `srcIp`                         |                                                                                                                                                                                                                               |
| `nd`      | T4       | `device`, `ip`, `mac`, `op`               | `op` is `na`, `ns`, `rs`, or `ra`. `ip` is IPv6. `router: true` marks a router address                                                                                                                                        |
| `wifi`    | T4       | `device`, `mac`, `op`                     | `op` is `assoc`, `disassoc`, `deauth`, or `auth-fail`. Optional `bssid`, `ssid` (≤ 32), `reason`                                                                                                                              |
| `app`     | T5       | `device`, `proto`, `role`, `peerIp`, `op` | `proto` must be in the app set: bacnet, modbus, dnp3, knx, s7, enip, mqtt, coap, rtsp, onvif, stratum, smtp, upnp, matter. `role` is `client` or `server`. `target`, `value` (number or string), `result` `ok\|error\|reject` |

Names are lowercased, a trailing dot is stripped, and IDN goes through `node:url` `domainToASCII`. An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is normalized to IPv4 **before** `domainToASCII`, because `domainToASCII('::ffff:192.0.2.1')` returns `''`.

A flow copies `dstName || dstIp` into `dst`, and `bytesOut + bytesIn` into `bytes`, so the T0 detectors see flows. Do not copy a DNS `qname` onto `dst`.

`feedBatch` sorts a copy by `ts`. It does not mutate the caller's array.

## Tiers

A detector runs only when every id in `requires` is in `tiers`. Otherwise it is inactive and `stats().detectors[id].reason` is like `requires T1`. `detectors[id].enabled: false` also disables it.

Default tiers are `['T0']`. Anything that `requires` T1 or higher stays off during the prototype tests and the 14-day benign runs. A new detector that `requires: ['T0']` must stay silent on those runs.

Where the spec says `T1/T2` or `T1/T5`, the code requires the **lowest** tier so the detector stays off by default. `direct-ip` is the exception that needs both: `requires: ['T1', 'T2']`.

The engine does not filter events by tier. If T1 is enabled, a T1 detector's `check` still receives `tls` and `app` events. Each detector returns immediately unless `ev.type` matches.

## Windows and learning

Window start is epoch-aligned: `ts - (ts % windowMs)`. Default 60 seconds.

While learning, a detector with `hardRule: false` gets `learn()` instead of `check()`. A `learn()` return with a string `reason` is `SUSPICIOUS_LEARNING`. A return with `severity` and no `reason` is emitted (shadow, for a shadow detector). That is how `nd-spoof` reports a router claim before lock (D-32).

Learning starts at the device's first accepted event. The device becomes watching when `ts >= learnStart + learnMs`. `learnMs: 0` flips to watching **before** detectors run, so the first event is a `check`, not a `learn`.

`lock(device)` freezes the device into watching. Close the current windows before flipping `frozen`. `relearn` clears the listed detector state and starts learning again. Import marks the device watching, frozen, and seen, with `learnStart` 0, and does not emit `learned`. A checkpoint also stores each detector's live state, including open-window counters and `LruSet` values that `exportBaseline()` does not keep, and `restore()` puts that state back.

While learning, a non-hard detector's `learn()` is called and `check()` is not. A `hardRule: true` detector skips `learn()` and always runs `check()`.

`anomaly.hardRule` means "this anomaly was emitted while the device was learning." It is `Boolean(learning)` at emit time. It is not a copy of the detector's `hardRule` flag. With `learnMs: 0` the flag on the anomaly is false even for a hard-rule detector. To assert `anomaly.hardRule === true`, use a long `learnMs` and do not `lock()` first.

`flush(now)` closes only windows whose `end <= now`. Idle windows during learning are stored as zero-byte, zero-destination samples so volume math does not treat silence as a missing sample. `planClose` caps idle materialization at `maxWindows` (10,080). A flush months later must not loop forever and must not page `input-gap`.

`_advanceTo` must keep the open window when the new event falls inside it. Replacing the window on every event makes fan-out count one host. That bug already shipped once and was fixed. Do not reintroduce it.

`noteLearning` also checks three poison shapes. `ramp` keeps two counters, first third and last third of `learnMs`. `late-family-burst` stores the first timestamp of each family in `familyFirst`, capped at `maxDestinations`. `beacon-born-in-learning` tracks at most 16 flows whose first contact is after half of `learnMs`, and skips a destination already in the `new-beacon` baseline. Each calls `mark`, so `ready` becomes false. They are warnings only.

`promote` defaults to false. When it is `{ afterDays, minHits }`, `_run` calls `noteWatch` only while the device is watching. `promote.js` tracks `new-domain-family`, `new-port`, `new-client-fingerprint`, and `resolver-bypass`. Promotion calls `allow()` and warns `BASELINE_PROMOTED`. `noteThreat` records a bad UTC day for a high, critical, or hard-rule anomaly, and records `actual` for `threat-intel-match`, `proxy-sdk-traffic`, and `tor-or-proxy`. A candidate whose days overlap that set is dropped. The cap is 500 per device per detector.

`feedback()` looks up `_anomalyById` or `_anomalyByFp` (last 10,000 live anomalies) and appends to `_feedback`. `exportLabels()` is JSONL without the note. `stats().precision` uses labels within 7 days of the watermark. `NOISY_DETECTOR` fires once per detector. The ring is `checkpoint().feedback`. More than 10,000 rows on restore throws `array feedback exceeds cap`.

`identity: 'auto'` re-keys `event.device` in `_apply` when that string is an IP in scratch table `identity`. The table is filled from DHCP ack/offer, ARP reply, and `nd`. `resolve(ip)` reads it. `stats().identity` is `{ rows, rekeyed, unresolved }`. Default `identity` is `'off'`, which still records bindings and does not re-key.

`explain(id)` reads `_explain`, an engine-wide LRU capped by `explainCap` (default 1,000). A detector puts `explain` on its draft. `lib.js` builds that object: `explainThreshold`, `explainNewMember`, `explainChanged`, `explainMatch`. If the draft has none, the engine stores `test: 'match'` and `observed` from `actual`. Hard rules drop any `allow` entry and clamp `untilTs` to `anomaly.ts + 24h`. Shadow anomalies are stored the same way, under their `sN` ids.

When `reorderMs > 0`, `feed` appends the validated event to `_reorder` ordered by `(ts, arrival seq)` and only calls `_apply` once `ts <= watermark - reorderMs`. `reorderMs: 0` leaves `_reorder` null and calls `_apply` immediately. `flush` and `tick` release up to their limit first; a bare `flush` releases the whole buffer. Overflow releases the oldest row and warns `REORDER_OVERFLOW` once per minute of event time. The buffer is the checkpoint's `reorder` array. A row that is not already in order is rejected. `lock()` releases the buffer first, so a device created by an event that is still held can be locked.

## Streaming statistics

`src/engine/stats/` is unused by detectors. `math.js` still owns the Welford summary that `volume-spike`, `fan-out`, and `volume-spike-hourly` export. The new `welford.js` adds min and Chan merge and must not be swapped in until a later WP, because a 7-day learn of the shorter rings would move the golden.

## Shadow mode

A detector with `meta.mode: 'shadow'` still learns, checks, and round-trips its own state. Each draft is a `shadow-anomaly` with `shadow: true` and no `incidentId`. It does not count toward `alert-storm` and is not passed to `post-update-drift` or `supply-chain-suspect`. Exporters that listen only to `anomaly` do not see it. `stats().shadow[id]` counts fires, devices, severity, and how many drafts would have joined an open incident. The host sets `detectors[id].mode` to `live` to promote one. The engine warns `SHADOW_PROMOTED_BY_HOST` once. `detectors[id].canary` runs a second copy of a live detector in shadow. `stats().canary[id]` is `{ liveOnly, canaryOnly, both }` by fingerprint per closed window. A fifth canary throws in `createEngine`. Canary state is not exported.

## Anomalies, caps, and incidents

Anomaly `id` is `String(++seq)` starting at `"1"`. Shape: `id`, `device`, `detector`, `category`, `severity`, `confidence`, `ts`, `actual`, `expected`, `data`, optional `attack` from `src/data/attack-map.json`, `hardRule`, optional `incidentId`.

Caps: 10,000 devices, 5,000 destinations per device, 5,000 alert keys, 10,080 history windows, 1,000,000 indicators, 5,000 destinations inside one window. Over the device cap: `warning` `STATE_CAP` plus one `state-cap` anomaly per device id. Use the event timestamp, never `Date.now()`.

`alert-storm` drops further anomalies from a device after 1,000 in one minute and emits one `alert-storm`. The storm detector itself is skipped so it cannot recurse.

Clock: a backward timestamp is `warning` `CLOCK_JUMP`, the event is not applied, and `clock-jump` fires. A forward jump fires only when one event is more than `maxForwardMs` after the previous event from the same device. The default is 36 hours (`129600000`). A 1 hour threshold fails the benign gate because overnight gaps are 12–19 hours. Documented in SPEC B11.

Incidents (`engine/incidents.js`): anomalies on one device inside `incidentWindowMs` (30 minutes) become one incident. Weights: info 5, low 10, medium 25, high 50, critical 80. Score is `min(100, raw * (stages <= 1 ? 1 : 1.5 ** (stages - 1)))` after decay `0.5 ** (elapsed / 6h)`. Severity is critical when stages ≥ 2 or score ≥ 70, else high when score ≥ 40, else medium. `ack(anomalyId)` halves the raw score. A score already capped at 100 may not drop when halved if new anomalies refill it. `anomaly.incidentId` is set before the anomaly event. Stages come from `src/data/stages.json`. Summary is up to 8 lines.

`post-update-drift` is not watching traffic. The engine calls it when an incident already contains an `update-*` detector and at least 3 other detector names. `supply-chain-suspect` fires once, during learning, when the detector that just fired is `proxy-relay`, `blockchain-c2`, or `class-violation`. `input-gap` runs on flush only: alert when `24h <= now - lastEventTs <= maxWindows * windowMs`. Its anomaly device id is `engine`. These five check functions no-op unless `ctx.extra.kind` matches. Do not make them scan ordinary events.

## Baseline v2

```json
{
  "version": 2,
  "createdAt": 0,
  "engine": { "windowMs": 60000, "pkg": "iotwarden@0.4.0" },
  "devices": {
    "cam-1": {
      "peerGroup": null,
      "detectors": { "new-destination": { "v": 1, "state": {} } }
    }
  }
}
```

`deviceClass` is omitted when unset. Export includes **every** registered detector. A new detector must `exportState` / `importState` an empty state or `engine.test.js` throws on the round trip.

`importBaseline` validates the whole document before it mutates. `merge: false` clears devices only after validation succeeds. Reject version other than 1 or 2, a v2 `windowMs` mismatch, an unknown detector, a state version mismatch, oversize arrays, strings longer than 255, forbidden keys, and an unknown `deviceClass`. Version 1 maps `dsts` → `new-destination`, `winFanout` → `fan-out`, `winBytes` → `volume-spike`, `hours` → `wrong-time`.

Optional HMAC-SHA256 via `node:crypto`: `exportBaseline({ sign: key })`, `importBaseline(data, { verify: key })`.

`JSON.parse('{"__proto__":1}')` on Node 24 keeps `__proto__` as an own key and does not pollute `Object.prototype`. Assignment `obj.__proto__ = x` does. Tests that want a rejected key must use `Object.defineProperty` or `JSON.parse`.

## Context object passed to detectors

`ctx` fields: `learning`, `ts`, `deviceId`, `hour(ts)`, `day(ts)`, `options`, `window`, `extra`, `learnMs`, `engineStarted`, `indicatorIndex`, `policy`, `deviceClass`, `gatewayIp`, `dhcpServers`, `routers`, `ownBssids`, `zones`, `browserJa4`, `peerGroup`, `scratch`, `peers()`, `peerState(other, id)`, `lookup(ip)`.

`lookup` is wrapped. A non-object return becomes null. A thrown lookup is not caught. `peers()` returns other **seen** devices with the same `peerGroup`. `scratch` is an engine-wide `Map`. ARP bindings, DHCP starvation, and fleet-wave rows live there because the events come from different device ids. Document that those tables are process memory, not the per-device baseline.

`browserJa4` is a string list capped at 32.

## Indicators

`loadIndicators([{ value, type, source, confidence?, expiresTs? }])`. Types: `ip`, `cidr`, `domain`, `ja4`, `tor`, `ad`, `proxy-sdk`, `young-domain`. Exact map for ip, domain, ja4, tor, ad, proxy-sdk, and young-domain. IPv4 CIDR is matched by prefix length. Domain and `young-domain` match walks parent labels. Expired when `expiresTs != null && ts >= expiresTs`. `type: 'tor'` is not treated as `ip`. `type: 'ad'` is only for `ad-fraud`. `type: 'young-domain'` is only for `young-domain`. The set is replaced only after every item validates.

`threat-intel-match` and `young-domain` share `dedupGroup` `indicator`. Two anomalies in that group on one device inside one incident window add once, at the higher weight.

## Classes, policy, and network helpers

`setDeviceClass(id, classId)` may be called before the first event. It creates a blank device so the tag is not lost. Classes in `src/data/classes/`: `camera`, `tv-box`, `thermostat`, `hvac-controller`, `plug`, `hub`, `printer`, `nas`. No class means `class-violation` returns immediately.

Policy: `createEngine({ policy: [{ id, severity?, match: { direction?, proto?, port?, hour?, dst? } }] })`. AND of the fields that are present. `dst: '*.example.com'` is a suffix match. Cap 256 rules. `policy-violation` is a hard rule.

`src/engine/net.js`: `isBogon`, `isPublic`, `domainFamily`, `ipv4`, `inBlock`. Bogons include RFC 1918, CGNAT `100.64/10`, loopback, link-local, the three documentation nets `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, multicast, `240/4`, and IPv6 ULA, link-local, unspecified, loopback, multicast, and `2001:db8`. `0.0.0.0` is inside `0.0.0.0/8`, so it is a bogon. `bogon-destination` requires `type === 'flow'` and `direction === 'out'`. `isPublic` means the string looks like an IP and is not a bogon. Tests that need a public address use `1.2.3.x`, `8.8.8.8`, or `9.9.9.9`. Do not use `198.51.100.0/24` or `203.0.113.0/24` as a "public" destination.

`domainFamily`: multi-label suffixes from `src/data/suffixes.json` (a curated snapshot, not the full Public Suffix List, because of the 500 KB pack cap). Unknown single-label TLDs use the last two labels. An IP has no family. A name matching `/^\d{1,3}(\.\d{1,3}){3}/` has no family, so scan labels like `203.0.113.4-12` are not families. `video.vendor.com` and `time.vendor.com` are both `vendor.com`. Refresh with `scripts/update-psl.mjs` only if the pack stays under 750 KB and `src/data/` stays at or under 200 KB.

## Prototype traffic the new T0 code must survive

`packages/core/test/engine.test.js` learns camera `cam-1` from day 0, hours 8–19, every 5 minutes, 2000 bytes, destination `time.vendor.com` when `minute % 10 === 0` and otherwise `video.vendor.com`. Watching starts day 7 at 08:00. The attack is a new host, hour 3, then a scan and a volume spike. `flush()` with no argument uses `Date.now()`, which is October 2026, so it closes January 2026 windows. A new T0 detector must not alert on that flush or on overnight gaps.

`benign.test.js` requires zero anomalies of any severity. `benign-matrix.test.js` runs 14 days × 7 classes × 3 seeds and requires no anomaly at medium or above. Profiles live in `packages/core/test/fixtures/`. Jitter is ±3% so any sample is less than twice any other sample. Clock origin is `Date.UTC(2026, 0, 5)`.

`peer-divergence` and `fleet-wave` are T0. They must return before emitting when there is no peer group, or when fewer than 3 devices newly share a destination. Benign runs are one device and set no peer group.

## Horizons

The ring exists only when T1 is enabled and `slow-scan` or `multi-horizon-exfil` is active, unless `horizons: false`. Flows update the open hour. A window close rolls a finished hour. A gap over 24 hours clears the ring and does not warn. `checkpoint().devices[id].progress.horizon` is the serialized ring.

## Graph and campaigns

`graph` is on when `graph-new-bridge` or `graph-role-change` is active. `graph: false` turns it off. LAN edges are 32 per device and WAN families are 64. Multicast is skipped. `engine.graph()` and `checkpoint().graph` expose the snapshot. `campaigns` defaults to false and only links live anomalies at medium or above when `identity` is `auto`. Shadow anomalies do not create campaign edges.
