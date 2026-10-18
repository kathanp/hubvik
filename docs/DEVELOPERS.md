# Building with iotwarden

iotwarden is a library for a gateway. You feed it observations. It emits events. Your product decides what to do with them. The library does not block, drop, or rewrite traffic.

Status of the code in this repo: prototype. It has not been validated on real traffic. Do not publish detection rates that this repository did not measure.

## Install

The publishable package is `packages/core` (`iotwarden`). It has no runtime dependencies and needs Node.js 22 or newer.

```js
const { createEngine, detectors, SEVERITY } = require('iotwarden');

const engine = createEngine({
  learnMs: 7 * 24 * 3600e3,
  tiers: ['T0', 'T1', 'T2'],
});

engine.on('anomaly', (anomaly) => {
  // anomaly.detector, severity, actual, expected, data, attack, hardRule
});

engine.on('warning', (warning) => {
  // FIELD_DROPPED, CLOCK_JUMP, STATE_CAP, SUSPICIOUS_LEARNING, LISTENER_ERROR
});
```

`tiers` defaults to `['T0']`. A detector stays off until every tier it requires is enabled. `engine.stats().detectors` lists each one with `active` and `reason`.

## What to send

T0 is enough for the original four detectors plus domain family, hourly volume, silence, and integrity:

```js
engine.feed({
  device: 'aa:bb:cc:dd:ee:ff',
  dst: 'video.vendor.com',
  bytes: 2048,
  ts: Date.now(),
});
```

T1 is a flow. On a flow the engine copies `dstName` or `dstIp` into `dst`, and `bytesOut + bytesIn` into `bytes`, so the T0 detectors see the same device.

```js
engine.feed({
  type: 'flow',
  device: 'aa:bb:cc:dd:ee:ff',
  ts: Date.now(),
  srcIp: '192.0.2.10',
  srcPort: 51515,
  dstIp: '203.0.113.5',
  dstPort: 443,
  proto: 'tcp',
  direction: 'out', // 'in' toward the device, 'lan' between local devices
  bytesOut: 1000,
  bytesIn: 8000,
  pktsOut: 8,
  pktsIn: 10,
  durationMs: 400,
  tcpOutcome: 'established', // or rejected, no-response, reset
  dstName: 'video.vendor.com',
});
```

T3 HTTP carries who sent the request. `direction` `out` means the device sent it. `in` means the device received it. Any other value is dropped.

```js
engine.feed({
  type: 'http',
  device: 'aa:bb:cc:dd:ee:ff',
  ts: Date.now(),
  dstIp: '203.0.113.5',
  dstPort: 80,
  method: 'GET',
  host: 'video.vendor.com',
  path: '/api/v1/status',
  status: 200,
  direction: 'out',
});
```

T2 is a DNS message:

```js
engine.feed({
  type: 'dns',
  device: 'aa:bb:cc:dd:ee:ff',
  ts: Date.now(),
  qname: 'video.vendor.com',
  qtype: 'A',
  rcode: 'NOERROR',
  resolver: '192.0.2.1',
  answers: [{ type: 'A', value: '203.0.113.5', ttl: 60 }],
});
```

Names are lowercased, a trailing dot is removed, and IDN is punycoded. IPv4-mapped IPv6 (`::ffff:192.0.2.1`) becomes `192.0.2.1`. A bad optional field is dropped and counted as `warning` `FIELD_DROPPED`. An unknown `type` throws.

Call `flush(now)` or `tick(now)` from a timer. Do not call a bare `flush()` while the gateway is still receiving traffic. A bare `flush()` is an end-of-input drain: it closes every open window whose start is ≤ the watermark, including the window that contains the watermark, then calls `tick(watermark)`. `flush(now)` closes only windows whose end is ≤ `now`. A backward step inside the current window is accepted even when `reorderMs` is 0. `reorderMs` extends that tolerance before the window and stays 0 through 0.5. Hosts that merge two adapters set `reorderMs: 5000`. `minLearnWindows` stays 0. 500 suits devices with a steady heartbeat; leave at 0 for devices that can be idle for days, such as printers.

## Learning

Learning starts at a device's first event and lasts `learnMs` (default 7 days), or until `lock(device)`. Hard-rule detectors still report during learning. Those shipped in this tree include threat-intel matches, telnet/ADB/TR-069 scans, packet floods, reflection, inbound telnet or ADB, policy violations, ADB on 5555, SMTP bursts, and TFTP to the WAN.

During learning the engine can emit `warning` `SUSPICIOUS_LEARNING` for a GRE flow, outbound telnet, TCP 5555, an NXDOMAIN burst (10 in one window), more than 20 new registrable domains in a day after day two, a proxy shape, or a DHCP fingerprint change on a MAC that already has one (`identity-change`). The first fingerprint is kept. Those warnings are not anomalies. Review them before `lock()`.

`importBaseline` marks the imported devices as already watching. They do not learn from the import itself.

## Indicators

The core ships no threat feed. You load indicators. Expired ones are ignored. A domain indicator matches that name and any name under it. CIDR matching is IPv4.

```js
engine.loadIndicators([
  { value: 'evil.example', type: 'domain', source: 'lab', confidence: 0.9 },
  { value: '203.0.113.0/24', type: 'cidr', source: 'lab' },
  { value: '198.51.100.20', type: 'ip', source: 'lab', expiresTs: Date.now() + 86400000 },
  { value: 't13d1516h2_8daaf6152771_b186095e22b6', type: 'ja4', source: 'lab' },
]);
```

`loadIndicators` replaces the whole set. If one item is invalid, the previous set stays.

## Policy

Policy rules are hard rules. Every field you set must match. `dst` entries are exact names, a registrable domain, or `*.example.com`.

```js
createEngine({
  tiers: ['T0', 'T1'],
  policy: [
    { id: 'no-telnet', severity: 'critical', match: { direction: 'out', proto: 'tcp', port: 23 } },
    { id: 'vendor-only', match: { direction: 'out', dst: ['*.vendor.com'] } },
  ],
});
```

An empty `policy` array disables `policy-violation`.

## Baselines

`exportBaseline()` writes version 2 JSON. Pass `{ sign: key }` to add an HMAC-SHA256 signature (`node:crypto`). `importBaseline(data, { verify: key, merge: true })` checks the whole document before it changes any device. Version 1 baselines from 0.1 still import.

Do not treat a baseline as a secret store. Anyone who can edit it chooses what "normal" means.

## Adapters

Parsers live in their own packages so core stays dependency-free.

- `packages/adapter-conntrack` reads `conntrack -L` / `conntrack -E` lines into T1 flows.
- `packages/adapter-dnsmasq` reads `log-queries=extra` lines into T2 DNS events.
- `packages/adapter-zeek` reads Zeek JSON `conn`, `dns`, `ssl`, `http`, Modbus, DNP3, MQTT, and ICSNPP `bacnet` / `s7comm` / `enip` lines.
- `packages/adapter-suricata-eve` reads EVE `flow`, `dns`, `tls`, and `http`. An `alert` line is returned for the host and is not an engine event.
- `packages/export-ocsf` maps an anomaly to an OCSF Detection Finding (`class_uid` 2004).
- `packages/export-syslog` formats RFC 5424 with a CEF message.
- `packages/export-webhook` POSTs JSON. You pass `fetch`. Optional `sign` sets `x-iotwarden-signature` to HMAC-SHA256 of the body. Failed attempts back off.

```js
const { createParser } = require('@iotwarden/adapter-conntrack');
const parser = createParser({ device: (ip) => ip });
for (const event of parser.write(line)) engine.feed(event);
```

## Caps

Defaults: 10 000 devices, 5 000 destinations per device, 5 000 alert keys, 10 080 windows of history, 5 000 destinations tracked inside one window. Passing a cap emits `warning` `STATE_CAP` and a `state-cap` anomaly once per device. The library keeps running with degraded memory for that device.

`alert-storm` starts at 1000 anomalies from one device in one minute. Later anomalies from that device are dropped until the next minute.

## Clock

Timestamps must not go backward. A backward step is `warning` `CLOCK_JUMP` and a `clock-jump` anomaly, and the event is not applied. A forward step longer than 36 hours is also `clock-jump`. Overnight silence is not a clock jump.

`input-gap` reports when `tick(now)` sees 24 hours with no accepted event, and that gap is still inside the history window (7 days by default). A tick at the watermark, including after a restart that has not seen a new event, does not page.

## Device class

```js
engine.setDeviceClass('aa:bb:cc:dd:ee:ff', 'plug');
```

Classes shipped: `camera`, `tv-box`, `thermostat`, `hvac-controller`, `plug`, `hub`, `printer`, `nas`. A class violation can fire during learning. That is how a device that shipped already infected is still reported. No class means those checks stay quiet.

## Incidents

Anomalies on one device inside 30 minutes become one `incident`: `{ id, device, stages, score, severity, anomalyIds, firstTs, lastTs, summary }`. Stages are recon, c2, spread, and impact. Two stages, or a score of at least 70, is critical. `ack(anomalyId)` halves the remaining score. The score decays with a 6 hour half-life.

## Lookup, zones, and mappings

```js
createEngine({
  tiers: ['T0', 'T1', 'T2'],
  lookup: (ip) => ({ asn: 'AS15169', country: 'US' }),
  gatewayIp: '192.0.2.1',
  dhcpServers: ['192.0.2.1'],
  routers: ['fe80::1'],
  zones: [
    { id: 'iot', cidr: '10.1.0.0/16' },
    { id: 'lan', cidr: '10.2.0.0/16' },
  ],
});

engine.feed({
  type: 'mapping',
  device: 'aa:bb:cc:dd:ee:ff',
  ts: Date.now(),
  proto: 'upnp',
  port: 5555,
  externalPort: 5555,
});
```

The core does not ship an IP-to-ASN database or a Tor relay list. Pass Tor relays as indicators with `type: 'tor'`. Ad domains use `type: 'ad'`. A newly registered name uses `type: 'young-domain'`.

## Early shadow detectors

`exploit-probe-http`, `young-domain`, and `ttl-anomaly` ship with `enabled: false`. They stay off until WP-12, which will turn them on in shadow mode. Enable one now with `createEngine({ detectors: { 'ttl-anomaly': { enabled: true } }, tiers: ['T0', 'T1'] })`.

`ttl-anomaly` reads `flow.ttl`. No shipped adapter fills that field, so the detector stays quiet until the host supplies it. `young-domain` does nothing until the host loads a `young-domain` list. Set `expiresTs` about 30 days after registration. Expired rows are ignored.

## TLS, building protocols, and fleets

```js
createEngine({
  tiers: ['T0', 'T1', 'T3', 'T5'],
  browserJa4: ['t13d1516h2_8daaf6152771_b186095e22b6'],
});

engine.feed({
  type: 'tls',
  device: 'aa:bb:cc:dd:ee:ff',
  ts: Date.now(),
  dstIp: '1.2.3.4',
  dstPort: 443,
  sni: 'video.vendor.com',
  ja4: 't13d1516h2_8daaf6152771_b186095e22b6',
  version: 'TLSv1.3',
  cert: { issuer: 'Vendor CA', selfSigned: false },
});

engine.feed({
  type: 'app',
  device: 'ahu-1',
  ts: Date.now(),
  proto: 'bacnet',
  role: 'server',
  peerIp: '10.0.0.2',
  op: 'WriteProperty',
  target: 'setpoint',
  value: 21,
  result: 'ok',
});

engine.setPeerGroup('aa:bb:cc:dd:ee:ff', 'cams');
```

JA4 is copied as a string. The library does not compute JA4 or JA4S. A peer comparison needs at least five other devices in the same group. A fleet wave needs three devices seeing one new destination inside ten minutes. `data.sameGroup` is true when those devices share one peer group.

## What this tree does not do yet

`checkpoint()` and `restore()` snapshot the baseline, the LAN scratch tables, the watermark, and learning progress. An anomaly `fingerprint` is a hash of the detector, the device, and a stable dedup key, not the display text.

Manufacturer Usage Description files, MAC randomization, discovery spoofing, TTL changes, and interactive-session shape are specified and not implemented. DHCP fingerprint identity is `identity-change`: the host supplies `dhcp.fingerprint`, and core does not derive it. `npm run bench` and `npm run fuzz` run. The watching-state bench meets the 10 µs budget after dispatch by `meta.consumes`; see `docs/BENCHMARKS.md`. Nothing in this tree has been measured on a public dataset. Do not treat the roadmap's dataset names as results.
