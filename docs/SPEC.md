# iotwarden — Package Specification (v2, full detection scope)

|              |                                                                                                                                               |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Package      | `iotwarden` (chosen 2026-10-16; npm exact-name check CLEAR)                                                                                   |
| Spec version | 2.1 draft. Adds B12–B19 (proxyware, OT/building automation, IoT protocols, abuse, tunnels, supply chain, spoofing, posture) and input tier T5 |
| Covers       | Core engine 0.1 → 1.0, plus the full detector catalog through 1.x                                                                             |
| Runtime      | Node.js ≥ 22 (18 and 20 are end-of-life), CommonJS + `.d.ts`, zero runtime dependencies in core                                               |
| License      | Apache-2.0                                                                                                                                    |
| Author       | Kathan Patel                                                                                                                                  |

**How to read this.** Part A is the engine. Part B is every detector worth building, each tagged with the release it belongs in and the input it needs. Part C covers scoring, operations, evaluation and the roadmap. Part D lists what is deliberately left out.

---

# PART A — ENGINE

## A1. Purpose

A library that runs on a network gateway, learns what each device behind it normally does on the network, and emits an event when a device's behavior changes or matches a known-bad pattern.

**It is a detector, not a firewall.** It never blocks, drops or modifies traffic. The host product decides the action.

**Target hosts:** IoT gateways, smart-home hubs, building-management servers, small network appliances, OpenWrt-class routers running Node.

**Core non-goals:** packet capture, payload/DPI signatures, blocking, cloud telemetry, deep-learning models in core. Rationale in Part D.

## A2. Input model — tiered

The 0.0.1 event `{ device, dst, bytes, ts }` can only drive 4 detectors. Most network-level detection needs more fields. Inputs are therefore defined in **tiers**. The host sends whatever it has; **each detector declares the tiers it needs and is disabled automatically if they are missing.** `engine.stats().detectors` reports which are active and why others are off.

| Tier   | Name                    | Typical source on a gateway                                                                                         | Adds                                                                                         |
| ------ | ----------------------- | ------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| **T0** | Summary                 | DNS log, simple conntrack                                                                                           | `device, dst, bytes, ts`                                                                     |
| **T1** | Flow                    | conntrack, NetFlow/IPFIX, nftables counters                                                                         | 5-tuple, direction, protocol, ports, bytes up/down, packets, duration, TCP outcome           |
| **T2** | DNS                     | dnsmasq / Unbound / CoreDNS logs                                                                                    | query name, qtype, rcode, answers, TTLs, resolver used                                       |
| **T3** | TLS/HTTP metadata       | Zeek, Suricata EVE, nDPI, eBPF                                                                                      | SNI, ALPN, JA4, cert subject/issuer/validity/fingerprint, HTTP host/UA                       |
| **T4** | Link layer              | ARP table, DHCP server log, mDNS/SSDP listener, IPv6 RA                                                             | MAC↔IP bindings, DHCP fingerprint (option 55 list, vendor class, hostname), RA sources       |
| **T5** | Application/OT protocol | Zeek built-in analyzers (Modbus, DNP3, MQTT), CISA's ICSNPP Zeek plugins (BACnet, S7comm, EtherNet/IP), broker logs | Protocol operation: BACnet service, Modbus function code, MQTT topic/QoS, RTSP/ONVIF actions |

```ts
// T5 — type: 'app'
{ type: 'app', device, ts, proto: 'bacnet'|'modbus'|'dnp3'|'knx'|'s7'|'enip'|'mqtt'|'coap'|'rtsp'|'onvif'|'stratum'|'smtp',
  role: 'client'|'server', peerIp, op: string,  // e.g. 'WriteProperty', 'fc16', 'SUBSCRIBE'
  target?: string,                              // object/register/topic/URI
  value?: string|number, result?: 'ok'|'error'|'reject' }
```

### A2.1 Event shapes

```ts
// T0 (unchanged, still valid)
{ device: string; dst?: string; bytes?: number; ts?: number }

// T1 flow — type: 'flow'
{ type: 'flow', device, ts,
  srcIp, srcPort, dstIp, dstPort,
  proto: 'tcp'|'udp'|'icmp'|'gre'|number,
  direction: 'out'|'in'|'lan',          // lan = device ↔ another local device
  bytesOut, bytesIn, pktsOut, pktsIn, durationMs,
  tcpOutcome?: 'established'|'rejected'|'no-response'|'reset',
  dstName?: string }                     // hostname if host already resolved it

// T2 DNS — type: 'dns'
{ type: 'dns', device, ts, qname, qtype, rcode,
  answers?: { type, value, ttl }[], resolver: string }

// T3 TLS — type: 'tls'
{ type: 'tls', device, ts, dstIp, dstPort, sni?, alpn?: string[], ja4?,
  cert?: { subject, issuer, notBefore, notAfter, sha256, selfSigned } }

// T3 HTTP — type: 'http'  (cleartext only)
{ type: 'http', device, ts, dstIp, dstPort, host?, method, path?, userAgent?, status? }

// T4 link layer — type: 'arp' | 'dhcp' | 'ra' | 'discovery'
{ type: 'arp',  ts, ip, mac, op: 'request'|'reply'|'gratuitous', iface? }
{ type: 'dhcp', ts, mac, msg: 'discover'|'request'|'ack'|'offer'|..., serverIp?,
  hostname?, vendorClass?, paramList?: number[], requestedIp? }
{ type: 'ra',   ts, srcMac, srcIp, prefixes: string[], routerLifetime }
{ type: 'discovery', device, ts, proto: 'mdns'|'ssdp'|'ws-discovery'|'coap', srcIp, direction }
```

- `dst`/`qname`/`sni` are lowercased, trailing dot removed, IDN converted to punycode.
- IPv4 and IPv6 are both first-class. IPv4-mapped IPv6 is normalized to IPv4.
- Validation: unknown `type` → `TypeError`. Malformed optional fields are dropped with a counted `warning`, not thrown, because gateway logs are messy.

### A2.2 Adapters (separate packages, not core)

Core stays zero-dependency. Parsers ship as optional packages that turn log lines into events:

`@iotwarden/adapter-conntrack`, `-dnsmasq`, `-unbound`, `-zeek`, `-suricata-eve`, `-ipfix`, `-openwrt`.

## A3. Concepts

| Term                    | Meaning                                                                                                           |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------- |
| **Device**              | Opaque stable ID chosen by host (MAC recommended).                                                                |
| **Window**              | Fixed epoch-aligned bucket, `windowMs` (default 60 s).                                                            |
| **Baseline**            | Per-device, per-detector learned state.                                                                           |
| **Learning / Watching** | Per device. Learning starts at first event and lasts `learnMs`.                                                   |
| **Hard rules**          | Detectors that fire **even during learning** (§B10). Prevents a compromised device from teaching itself "normal". |
| **Peer group**          | Devices the host marks as the same model/role. Enables cross-device comparison (§B9).                             |
| **Incident**            | A correlated group of anomalies on one device (§C1).                                                              |

Lifecycle:

```
first event ─► LEARNING ─(learnMs | lock())─► WATCHING ─(relearn())─► LEARNING
                     importBaseline() ──────────┘
Hard-rule detectors run in both states.
```

## A4. Public API

```js
const { createEngine, Engine, detectors, SEVERITY } = require('iotwarden');
```

| Method                                                          | Behavior                                                                                                   |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `createEngine(opts)`                                            | Factory.                                                                                                   |
| `feed(event)`                                                   | Synchronous. Validates, routes to detectors by tier, emits synchronously.                                  |
| `feedBatch(events)`                                             | Same, sorted by `ts` first.                                                                                |
| `flush(now = Date.now())`                                       | Closes only windows whose end ≤ `now`. Never closes an open window early.                                  |
| `lock(device?)`                                                 | End learning for one or all devices.                                                                       |
| `relearn(device, { detectors? })`                               | Reset baseline (all or listed detectors) and re-enter learning.                                            |
| `allow(device, kind, value)`                                    | Add to frozen baseline: `kind` ∈ `dst`, `port`, `asn`, `country`, `ja4`, `certIssuer`, `resolver`, `peer`. |
| `suppress(device, detector, { untilTs, match? })`               | Mute a detector for a device, optionally only for matching `actual`.                                       |
| `ack(anomalyId)`                                                | Mark handled; used by incident scoring decay.                                                              |
| `forget(device)`                                                | Delete all state.                                                                                          |
| `setPeerGroup(device, groupId)`                                 | Assign peer group.                                                                                         |
| `exportBaseline({ devices? })` / `importBaseline(b, { merge })` | §A6. Import validates fully before mutating.                                                               |
| `use(detector)`                                                 | Register a custom detector (§A5).                                                                          |
| `stats()`                                                       | Counters, active/disabled detectors with reasons, memory estimate.                                         |

Events:

| Event        | Payload                               |
| ------------ | ------------------------------------- |
| `anomaly`    | `Anomaly` (§A7)                       |
| `incident`   | `Incident` (§C1), opened or escalated |
| `learned`    | `{ device, ts }`                      |
| `device-new` | `{ device, ts, firstEvent }`          |
| `warning`    | `{ code, message, device? }`          |

A throwing listener is caught and re-emitted as `warning` `LISTENER_ERROR`; engine state stays consistent.

## A5. Detector plugin interface

Every built-in detector uses the same interface, so third parties can add their own.

```ts
interface Detector {
  id: string; // 'beaconing'
  version: number; // bump when state format changes
  requires: Tier[]; // ['T1']
  defaults: Record<string, unknown>; // tunables
  hardRule?: boolean; // runs during learning
  learn?(dev, ev, ctx): void;
  check?(dev, ev, ctx): AnomalyDraft | AnomalyDraft[] | void;
  onWindowClose?(dev, window, ctx): AnomalyDraft[] | void;
  exportState?(dev): unknown; // JSON-safe, size-bounded
  importState?(dev, state): void;
  memoryEstimate?(dev): number; // bytes
}
```

Per-detector options: `createEngine({ detectors: { beaconing: { enabled: true, severity: 'high', minConnections: 20 } } })`.

## A6. Baseline format (version 2)

```json
{
  "version": 2,
  "createdAt": 0,
  "engine": { "windowMs": 60000, "pkg": "iotwarden@0.3.0" },
  "devices": {
    "<id>": {
      "peerGroup": "cam-model-x",
      "detectors": { "<detectorId>": { "v": 1, "state": {} } }
    }
  }
}
```

- Version 1 baselines (0.1) are read and upgraded.
- Import rejects mismatched `windowMs`, unknown detector state versions (per detector, not whole file), keys `__proto__`/`constructor`/`prototype`, arrays over cap, strings over 255 chars.
- **Optional signing**: `exportBaseline({ sign: key })` adds an HMAC-SHA256 (`node:crypto`, still zero-dep). `importBaseline(b, { verify: key })` rejects tampered files. A baseline shipped to a fleet is an attack surface: whoever edits it decides what is "normal".

## A7. Anomaly shape

```ts
{
  id: string;                  // unique, monotonic per engine
  device: string;
  detector: string;
  category: 'destination'|'scan'|'volume'|'timing'|'dns'|'tls'|'link'|'policy'|'fleet'|'integrity'
          | 'proxy'|'ot'|'app'|'abuse'|'tunnel'|'update'|'spoof'|'posture';
  severity: 'info'|'low'|'medium'|'high'|'critical';
  confidence: number;          // 0..1, how sure the detector is
  ts: number;
  actual: string;              // display only
  expected: string;            // display only
  data: object;                // machine-readable; schema per detector
  attack?: string[];           // MITRE ATT&CK technique IDs, e.g. ['T1046']
  hardRule: boolean;           // fired during learning?
  incidentId?: string;
}
```

---

# PART B — DETECTOR CATALOG

Columns: **Needs** = input tier. **Rel** = release (0.1, 0.2, 0.3, 0.4, 1.0, 1.x). **FP risk** = false-positive risk on real IoT traffic, which decides default severity.

## B1. Destination and identity

| ID                        | Catches                                                                           | Needs   | Method                                                                                     | Sev          | FP risk                                                                 | Rel |
| ------------------------- | --------------------------------------------------------------------------------- | ------- | ------------------------------------------------------------------------------------------ | ------------ | ----------------------------------------------------------------------- | --- |
| `new-destination`         | Host never contacted during learning                                              | T0      | Set membership; capped per window                                                          | medium       | Medium: CDNs rotate hostnames                                           | 0.1 |
| `new-domain-family`       | New **registered domain** (eTLD+1), not just new hostname                         | T0/T2   | Bundled Public Suffix List snapshot; replaces raw hostname match as default                | medium       | Low: removes CDN-subdomain noise                                        | 0.2 |
| `new-port`                | Device uses a destination port it never used                                      | T1      | Per-device port set, direction-aware                                                       | medium       | Low for IoT                                                             | 0.2 |
| `new-protocol`            | New IP protocol (GRE, raw ICMP bursts, IPv6-in-IPv4)                              | T1      | Protocol set                                                                               | high         | Very low; GRE from a camera is Mirai GREIP/GREETH territory             | 0.2 |
| `direct-ip`               | Connection to an IP the device never resolved via DNS                             | T1+T2   | Join flow dstIp with device's recent DNS answers (TTL-bounded)                             | medium       | Low on IoT; hard-coded C2 IPs are classic                               | 0.3 |
| `new-asn` / `new-country` | Traffic to a network or country never used                                        | T1      | Offline IP→ASN/country DB loaded by host (core ships none)                                 | medium / low | Medium                                                                  | 0.3 |
| `inbound-from-wan`        | Unsolicited inbound connections reaching the device                               | T1      | `direction: 'in'` from public IP without prior outbound                                    | high         | Low; means port forward/UPnP exposure                                   | 0.2 |
| `upnp-port-open`          | Device opens a WAN port mapping via UPnP-IGD / NAT-PMP / PCP                      | T1/host | Host reports mapping event; flag any new mapping                                           | high         | Low                                                                     | 0.3 |
| `threat-intel-match`      | Destination on a known-bad list                                                   | T0+     | Host-supplied indicator sets (IP, CIDR, domain, JA4); loaded via `engine.loadIndicators()` | critical     | Depends on feed quality                                                 | 0.2 |
| `bogon-destination`       | Traffic to reserved/unallocated/martian space on WAN side                         | T1      | Static RFC table + host-provided bogon list                                                | medium       | Low                                                                     | 0.2 |
| `tor-or-proxy`            | Connections to Tor relays / known anonymizers                                     | T1      | Indicator set (Tor Project publishes relay lists)                                          | high         | Very low for IoT                                                        | 0.3 |
| `p2p-pattern`             | Device acting as a P2P node (many residential peers, high ports, both directions) | T1      | Ratio of unique peers on ephemeral ports + inbound share                                   | high         | Medium (some cameras use P2P relay legitimately; baseline catches that) | 0.4 |

**Note on threat intel.** The core ships **no feed**. Feed licensing changes: abuse.ch, for example, made authentication mandatory for its APIs from 30 June 2025. The host product chooses feeds, handles keys and terms, and passes indicators in. Each indicator carries `{ value, type, source, confidence, expiresTs }`. Expired indicators are ignored.

## B2. Scanning and propagation

| ID                        | Catches                                                     | Needs   | Method                                                                                                                | Sev      | FP risk                                                        | Rel |
| ------------------------- | ----------------------------------------------------------- | ------- | --------------------------------------------------------------------------------------------------------------------- | -------- | -------------------------------------------------------------- | --- |
| `fan-out`                 | Many unique hosts per window                                | T0      | Exists. Threshold `max(minFanout, k × learned max)`                                                                   | high     | Low                                                            | 0.1 |
| `horizontal-scan`         | Same port, many hosts (worm propagation)                    | T1      | Unique dstIps per (dstPort, window); extra weight for 23, 2323, 22, 5555 (ADB), 7547 (TR-069), 37215, 52869, 80, 8080 | critical | Very low                                                       | 0.2 |
| `vertical-scan`           | Many ports on one host (recon)                              | T1      | Unique dstPorts per (dstIp, window)                                                                                   | high     | Low                                                            | 0.2 |
| `failed-connection-ratio` | High share of SYNs with no answer or RST                    | T1      | `tcpOutcome` ratio vs baseline, min 20 attempts                                                                       | high     | Low; the most robust scan signal                               | 0.2 |
| `lan-lateral`             | Device starts talking to LAN peers it never contacted       | T1      | `direction: 'lan'` peer set                                                                                           | high     | Low on IoT (devices rarely talk east-west except hub ↔ device) | 0.2 |
| `lan-sweep`               | ARP or ICMP sweep of the local subnet                       | T1/T4   | Unique local targets per window in ARP requests or ICMP echo                                                          | high     | Low                                                            | 0.3 |
| `brute-force-out`         | Device hammering auth ports on other hosts                  | T1      | Many short connections to 22/23/3389/554/1883/8080 with similar small sizes                                           | critical | Very low                                                       | 0.3 |
| `brute-force-in`          | Something hammering the device                              | T1      | Same, reversed; reports source                                                                                        | high     | Low                                                            | 0.3 |
| `exploit-probe-http`      | Known IoT exploit paths in cleartext HTTP from or to device | T3 http | Small built-in path list (e.g. GPON `/GponForm/`, shell-injection patterns in query strings)                          | critical | Low                                                            | 1.x |

## B3. Volume and flooding

| ID                         | Catches                                                                                                 | Needs | Method                                                                               | Sev      | FP risk                  | Rel |
| -------------------------- | ------------------------------------------------------------------------------------------------------- | ----- | ------------------------------------------------------------------------------------ | -------- | ------------------------ | --- |
| `volume-spike`             | Far more bytes in a window                                                                              | T0    | Exists. Fix: count idle windows                                                      | high     | Medium for cameras       | 0.1 |
| `volume-spike-hourly`      | Spike vs the **same hour of day** baseline                                                              | T0    | Per-hour-of-day mean/std                                                             | high     | Lower than flat baseline | 0.2 |
| `upload-ratio-shift`       | Up/down ratio flips (thermostat suddenly uploading)                                                     | T1    | EWMA of bytesOut/(bytesIn+bytesOut) vs learned band                                  | high     | Low                      | 0.2 |
| `slow-exfil`               | Small but sustained upload increase over hours                                                          | T1    | CUSUM on hourly bytesOut vs learned mean                                             | high     | Medium                   | 0.3 |
| `packet-flood`             | High packet rate with tiny packets (SYN/UDP/ICMP flood)                                                 | T1    | pps vs baseline and avg bytes/pkt < 100                                              | critical | Very low                 | 0.2 |
| `protocol-mix-shift`       | UDP/ICMP/GRE share jumps                                                                                | T1    | Per-window proportion vs learned band (chi-square or simple band)                    | high     | Low                      | 0.3 |
| `reflection-participation` | Device answering SSDP/mDNS/CoAP/WS-Discovery/NTP to WAN addresses: it is being used as a DDoS reflector | T1/T4 | Outbound UDP from those service ports to public IPs, response/request byte ratio > 3 | critical | Very low                 | 0.2 |
| `connection-churn`         | Huge number of short connections (HTTP flood, Slowloris inverse)                                        | T1    | New connections/window vs baseline                                                   | high     | Low                      | 0.3 |

## B4. Timing and rhythm

| ID                  | Catches                                                                   | Needs | Method                                                                                                                      | Sev    | FP risk                                                                                                                | Rel |
| ------------------- | ------------------------------------------------------------------------- | ----- | --------------------------------------------------------------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------- | --- |
| `wrong-time`        | Active in an hour never seen                                              | T0    | Exists. Fix day/hour clock mismatch                                                                                         | low    | Medium                                                                                                                 | 0.1 |
| `new-beacon`        | **New** periodic communication to a non-baseline destination              | T1    | Per (device, dst) inter-arrival times: low dispersion (MAD/median), low skew, ≥ 20 connections, consistent sizes. Score 0–1 | high   | **High if applied to everything**: IoT devices beacon to vendors all day. Only score destinations outside the baseline | 0.3 |
| `beacon-change`     | A known vendor beacon changes period or size sharply                      | T1    | Compare learned period/size to current                                                                                      | medium | Medium (firmware updates)                                                                                              | 0.4 |
| `long-connection`   | New long-lived session (reverse shell, tunnel)                            | T1    | durationMs above learned p99 to a non-baseline dst                                                                          | high   | Low                                                                                                                    | 0.3 |
| `went-silent`       | Device stops all traffic (bricked, unplugged, wiped, blocked by attacker) | T0    | No events for `k ×` learned max gap during its active hours                                                                 | medium | Medium                                                                                                                 | 0.2 |
| `day-of-week-drift` | Weekend/weekday pattern change                                            | T0    | Per-weekday activity profile                                                                                                | low    | Medium; needs ≥ 2 weeks learning                                                                                       | 1.x |

## B5. DNS

| ID                | Catches                                                                                                         | Needs        | Method                                                                                                                              | Sev      | FP risk                                                                       | Rel |
| ----------------- | --------------------------------------------------------------------------------------------------------------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------------- | -------- | ----------------------------------------------------------------------------- | --- |
| `dga`             | Algorithmically generated domains                                                                               | T2           | Per-label entropy + bigram score against bundled English/brand n-gram table + vowel/digit ratio; fire on a burst, not a single name | high     | Medium per name, low per burst                                                | 0.3 |
| `nxdomain-burst`  | Many NXDOMAIN answers (DGA trying names, misconfig)                                                             | T2           | NXDOMAIN rate vs baseline, min count                                                                                                | high     | Low                                                                           | 0.2 |
| `dns-tunnel`      | Data hidden in DNS queries                                                                                      | T2           | Long labels (> 40 chars), high entropy, many unique subdomains under one parent, TXT/NULL/CNAME share, query volume vs baseline     | critical | Low with the combined score                                                   | 0.3 |
| `resolver-bypass` | Device stops using the gateway resolver: direct UDP/TCP 53 to outside, DoT (853), or DoH to known DoH endpoints | T1/T2        | Resolver set in baseline; DoH endpoint list as indicators                                                                           | high     | Low on IoT, though some devices hard-code 8.8.8.8, which the baseline absorbs | 0.2 |
| `answer-drift`    | A known vendor name suddenly resolves into a different ASN/country                                              | T2 (+ASN DB) | Learned answer ASNs per qname                                                                                                       | high     | Medium (CDN changes); could indicate DNS hijack or spoofing                   | 0.4 |
| `dns-rebinding`   | Public domain resolving to a private/loopback address                                                           | T2           | RFC1918/loopback/link-local in answers for a public name                                                                            | high     | Low                                                                           | 0.2 |
| `fast-flux`       | Many A records, very low TTL, many ASNs                                                                         | T2           | Answer diversity × TTL score                                                                                                        | high     | Medium                                                                        | 0.4 |
| `young-domain`    | Domain registered recently                                                                                      | T2           | Host-supplied newly-registered-domain indicator set                                                                                 | medium   | Medium                                                                        | 1.x |

## B6. Encrypted-traffic metadata (TLS/QUIC)

These read handshake metadata only. Nothing is decrypted.

| ID                       | Catches                                                                                    | Needs | Method                             | Sev    | FP risk                                                  | Rel |
| ------------------------ | ------------------------------------------------------------------------------------------ | ----- | ---------------------------------- | ------ | -------------------------------------------------------- | --- |
| `new-client-fingerprint` | Device starts using a TLS client stack it never used (new malware process, firmware swap)  | T3    | Per-device JA4 set                 | high   | Low on single-purpose IoT, medium after firmware updates | 0.4 |
| `cert-change`            | Known SNI now presents a cert from a different issuer, self-signed, or expired             | T3    | Learned issuer/fingerprint per SNI | high   | Low; strong MITM signal                                  | 0.4 |
| `sni-missing`            | TLS without SNI to a non-baseline destination                                              | T3    | Flag                               | medium | Medium                                                   | 0.4 |
| `sni-ip-mismatch`        | SNI claims a vendor name but the IP never resolved for it (domain fronting, hard-coded C2) | T2+T3 | Join                               | high   | Medium (CDNs)                                            | 1.x |
| `tls-on-odd-port`        | TLS to a port the device never used for TLS                                                | T1+T3 | Port set per protocol              | medium | Low                                                      | 0.4 |
| `cleartext-regression`   | Device that always used TLS starts sending HTTP/MQTT/Telnet in clear                       | T1/T3 | Learned per-dst TLS share          | high   | Low; downgrade attack or tampered firmware               | 0.4 |

**Fingerprint licensing.** JA4 (TLS client) is BSD-3-Clause. JA4S, JA4H, JA4X, JA4SSH, JA4T and JA4D carry the FoxIO License 1.1, which is aimed at academic, internal business and research use. Core accepts any JA4 string the host supplies and never computes the other JA4+ variants itself. **Before shipping a commercial product that computes JA4+ beyond JA4, get legal review.**

**ECH caveat.** Encrypted Client Hello hides SNI. As ECH spreads, `sni-*` detectors lose coverage; `cert-change` and `new-client-fingerprint` remain.

## B7. Link layer and local network

Needs T4. These protect the network, not just one device's traffic, so many report the **attacker MAC**, not the victim.

| ID                        | Catches                                                                                    | Method                                                              | Sev      | FP risk                                           | Rel |
| ------------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | -------- | ------------------------------------------------- | --- |
| `new-device`              | Unknown MAC joins                                                                          | First event for unseen ID after engine has been running `> learnMs` | medium   | Low                                               | 0.2 |
| `arp-spoof`               | IP ↔ MAC binding changes, or one MAC claims many IPs, or gateway IP claimed by another MAC | Binding table with history                                          | critical | Low (DHCP reassignments handled via lease events) | 0.3 |
| `gratuitous-arp-flood`    | Gratuitous ARP storm                                                                       | Rate                                                                | high     | Low                                               | 0.3 |
| `rogue-dhcp`              | DHCP OFFER/ACK from a server that is not the configured one                                | Allowed server set                                                  | critical | Very low                                          | 0.3 |
| `dhcp-starvation`         | Many DISCOVERs from random MACs                                                            | Unique MAC rate                                                     | high     | Low                                               | 0.3 |
| `rogue-ra`                | IPv6 Router Advertisement from an unexpected router                                        | Allowed RA sources                                                  | critical | Very low                                          | 0.3 |
| `identity-change`         | Same MAC, different DHCP fingerprint (option 55 list, vendor class, hostname) or JA4T      | Learned fingerprint per MAC                                         | high     | Low; signals MAC cloning or firmware swap         | 0.4 |
| `mac-randomization-churn` | Many short-lived MACs with the same DHCP fingerprint                                       | Fingerprint → MAC set                                               | info     | Phones do this legitimately; report, don't alarm  | 1.x |
| `discovery-spoof`         | mDNS/SSDP announcements claiming another device's name                                     | Name ↔ MAC table                                                    | high     | Low                                               | 1.x |

## B8. Policy and allowlists

| ID                 | Catches                                                                    | Needs | Method                                                                                           | Sev      | Rel |
| ------------------ | -------------------------------------------------------------------------- | ----- | ------------------------------------------------------------------------------------------------ | -------- | --- |
| `policy-violation` | Host-declared rules broken, e.g. "camera: WAN only to *.vendor.com:443"    | any   | Declarative rule set: allow/deny by dst, domain family, port, proto, direction, hours            | per rule | 0.2 |
| `mud-violation`    | Traffic outside the device's **Manufacturer Usage Description** (RFC 8520) | T1+T2 | Host fetches and verifies the MUD file and passes the parsed ACL; engine checks flows against it | high     | 1.0 |
| `zone-violation`   | Device crosses a network zone boundary (IoT VLAN → main LAN)               | T1    | Host tags IP ranges as zones                                                                     | high     | 0.3 |

**MUD reality check.** MUD is a published IETF standard, but deployments are still early: a survey of real implementations found mostly proof-of-concept systems, with gaps such as no rules for lateral movement within a network, and MUD URLs that a compromised device could forge over DHCP or LLDP. Treat MUD as an extra input when available, never as the main detection method.

## B9. Fleet and peer comparison

These need the host to aggregate events from many devices (one big gateway, or a central service fed by many gateways).

| ID                         | Catches                                                                       | Method                                                                                        | Sev                                                                                                                                                                   | Rel |
| -------------------------- | ----------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- |
| `peer-divergence`          | One device behaves unlike others of the same model                            | Compare device's destination families, ports, volume band to peer-group consensus (≥ 5 peers) | high                                                                                                                                                                  | 0.4 |
| `fleet-wave`               | Many devices hit the same new destination within minutes                      | Count devices per new dst per 10 min                                                          | **Ambiguous by design.** Vendor update (suppress) or worm (escalate). Output `fleet-wave` with `data.peersAffected`, `data.sameGroup`; host decides. Default `medium` | 0.4 |
| `fleet-baseline-poisoning` | An imported fleet baseline contains destinations no peer ever learned locally | Compare import vs local peers                                                                 | high                                                                                                                                                                  | 1.x |

## B10. Hard rules — fire during learning too

The biggest weakness of learn-then-watch is that a device compromised before or during learning teaches the engine that the compromise is normal. These detectors ignore learning state:

`threat-intel-match`, `horizontal-scan` on telnet/ADB/TR-069 ports, `packet-flood`, `reflection-participation`, `brute-force-out`, `dns-tunnel`, `rogue-dhcp`, `rogue-ra`, `arp-spoof` on the gateway IP, `inbound-from-wan` on telnet/ADB, `policy-violation`, `adb-exposure`, `proxy-relay`, `blockchain-c2`, `supply-chain-suspect`, `ot-dangerous-op`, `ot-wan-exposure`, `onvif-config-change`, `cryptomining`, `spam-relay`, `tftp-activity`, `src-spoof`, `class-violation`.

In addition, during learning the engine records **learning quality warnings** (`warning` code `SUSPICIOUS_LEARNING`) when it sees: > 20 new destination families per day after day 2, any GRE, any outbound telnet, any NXDOMAIN burst. These do not alert; they tell the operator to review before `lock()`.

## B11. Engine integrity

| ID            | Catches                                                                                                                                          | Sev    | Rel |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------ | --- |
| `input-gap`   | Whole input pipeline goes quiet (log rotation broke, adapter died). A silent detector is worse than none because everyone assumes it is watching | high   | 0.2 |
| `clock-jump`  | Event timestamps jump backward or > 1 h forward                                                                                                  | medium | 0.2 |
| `state-cap`   | A device hit memory caps; detection degraded for it                                                                                              | medium | 0.2 |
| `alert-storm` | > N anomalies/minute engine-wide; per-device rate limiting engaged                                                                               | medium | 0.2 |

## B12. Residential proxy and "proxyware" — the main IoT threat of 2025–26

The threat has moved past Mirai-style DDoS. Today, compromised IoT devices are mostly rented out as **residential proxies**:

- In June 2025, the FBI warned that BADBOX 2.0 had put millions of TV boxes, projectors, car infotainment units and picture frames into a botnet. Infection happened **before purchase** or during setup, and the devices are sold as proxy endpoints.
- In 2026, Kimwolf spread through proxy networks **back into the victims' own LANs**, reaching Android boxes that leave ADB open on port 5555. To get around proxy providers' private-address blocks, it pointed DNS names at private or 0.0.0.0 addresses.

| ID                               | Catches                                                                                                                                                 | Needs | Method                                                                                                                     | Sev      | Rel |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- | -------------------------------------------------------------------------------------------------------------------------- | -------- | --- |
| `proxy-relay`                    | Device relays third-party traffic: destination diversity explodes into popular consumer sites (shopping, social, ticketing) unrelated to its function   | T1/T2 | Unique registered domains per hour vs baseline × category entropy; inbound control session + outbound fan-out to web ports | critical | 0.3 |
| `browser-mimic`                  | A non-browser device (camera, thermostat, TV box backend) emits browser-class TLS fingerprints                                                          | T3    | JA4 matched against a host-supplied set of browser fingerprints; flag when device class ≠ browser-capable                  | high     | 0.4 |
| `proxy-backconnect`              | Long-lived control connection to a proxy-provider endpoint, followed by many short outbound flows that track its activity                               | T1    | Correlate: 1 persistent session + bursts of new flows within seconds of control traffic                                    | critical | 0.4 |
| `lan-via-proxy`                  | Traffic **from WAN-originated sessions** reaching LAN devices (proxy tunneling into the home)                                                           | T1    | Flows to `direction: 'lan'` targets that start within ms of inbound bytes on a proxy session                               | critical | 0.4 |
| `adb-exposure`                   | Any connection to TCP 5555 on a LAN device, from LAN or WAN                                                                                             | T1    | Hard rule. Plus `posture` report if device listens on 5555                                                                 | critical | 0.2 |
| `private-answer-for-public-name` | Public domain resolves to RFC 1918 / 0.0.0.0 (Kimwolf's blocklist bypass)                                                                               | T2    | Same as `dns-rebinding`, includes 0.0.0.0 and `::`                                                                         | high     | 0.2 |
| `blockchain-c2`                  | IoT device queries Ethereum/other chain RPC endpoints or ENS resolution services (C2 address lookup that survives domain takedowns, used by Kimwolf v7) | T2/T3 | Indicator set of public RPC endpoints; any hit from a device whose class is not wallet/node                                | high     | 0.3 |
| `supply-chain-suspect`           | Device begins proxy/ad/C2 behavior **from its very first hour** (preinstalled malware)                                                                  | T1–T3 | Hard-rule evaluation of B12 detectors during learning + `device-class` priors (§B19)                                       | critical | 0.3 |

## B13. Building automation and OT protocols

Building-management servers are a stated target market, so this group is not optional. BACnet and Modbus have **no authentication** in common deployments: anyone who can send packets can write setpoints, stop equipment or reflash controllers.

| ID                      | Catches                                                                                                                                                                       | Needs | Method                                                             | Sev      | Rel |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- | ------------------------------------------------------------------ | -------- | --- |
| `ot-new-master`         | A host that never talked to a controller now does (new Modbus master, new BACnet client)                                                                                      | T1/T5 | Per-controller client set                                          | critical | 0.4 |
| `ot-write-new`          | Write operation from a client that only ever read, or to an object/register never written: Modbus FC 5/6/15/16, BACnet `WriteProperty` / `WritePropertyMultiple`              | T5    | Learned (client, op, target) set                                   | high     | 0.4 |
| `ot-dangerous-op`       | `ReinitializeDevice`, `DeviceCommunicationControl` (silences a controller), `AtomicWriteFile` (program/firmware write), Modbus FC 8 diagnostics, S7 STOP/PLC program download | T5    | Hard rule, always alert; host can allow during maintenance windows | critical | 0.4 |
| `ot-value-out-of-range` | Setpoint written outside learned min/max (e.g. chiller setpoint to 40 °C)                                                                                                     | T5    | Per (target) learned range + host-declared physical limits         | critical | 0.4 |
| `ot-write-rate`         | Sudden burst of writes (rapid on/off cycling can damage motors and compressors)                                                                                               | T5    | Writes/window vs baseline                                          | high     | 0.4 |
| `ot-recon`              | BACnet `Who-Is` / `Who-Has` sweeps, Modbus FC 43 (read device identification), scans of 47808/502/102/44818/20000/1911/4911                                                   | T1/T5 | Unique targets per window                                          | high     | 0.4 |
| `ot-spoof`              | BACnet `I-Am` for a device instance ID already owned by another MAC/IP                                                                                                        | T5    | Instance ID ↔ address table                                        | critical | 0.4 |
| `ot-wan-exposure`       | OT protocol traffic crossing to/from WAN, BACnet BBMD foreign-device registration from a public IP                                                                            | T1    | Direction + port                                                   | critical | 0.3 |
| `ot-error-burst`        | Spike in protocol exceptions/rejects (fuzzing, wrong-register probing)                                                                                                        | T5    | Error rate vs baseline                                             | medium   | 0.4 |
| `ot-schedule-drift`     | Writes outside the learned operating schedule                                                                                                                                 | T5    | Hour-of-week profile per (client, op)                              | medium   | 1.x |

## B14. IoT application protocols (MQTT, CoAP, RTSP/ONVIF)

| ID                          | Catches                                                                                                                               | Needs | Method                                                | Sev      | Rel |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ----- | ----------------------------------------------------- | -------- | --- |
| `mqtt-new-broker`           | Device connects to an MQTT broker it never used (1883/8883)                                                                           | T1    | Destination set by port                               | high     | 0.2 |
| `mqtt-wildcard-subscribe`   | `SUBSCRIBE` to `#` or broad `+/…` wildcards (harvesting every device's messages)                                                      | T5    | Topic pattern check                                   | high     | 0.4 |
| `mqtt-topic-new`            | Publish/subscribe to topics outside the learned set, especially `cmd`/`ota`/`config` paths                                            | T5    | Topic-prefix set                                      | medium   | 0.4 |
| `mqtt-publish-rate`         | Publish flood or sudden payload-size jump                                                                                             | T5    | Rate/size bands                                       | medium   | 0.4 |
| `coap-amplification`        | Device answering CoAP (5683/udp) from WAN with large responses                                                                        | T1    | Reflection logic of `reflection-participation`        | critical | 0.2 |
| `stream-to-new-destination` | Camera media stream (RTSP 554, RTP, or sustained high-rate upload) starts going to a non-baseline host — someone is watching the feed | T1/T5 | Upload rate > learned media rate threshold to new dst | critical | 0.3 |
| `onvif-config-change`       | ONVIF `SetUser`, `SetNetworkInterfaces`, `SetSystemFactoryDefault`, firmware upgrade from non-baseline client                         | T5    | Hard rule                                             | critical | 0.4 |

## B15. Device monetization abuse

| ID                        | Catches                                                                                                                  | Needs    | Method                                                                                                                                                                        | Sev    | Rel |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | --- |
| `cryptomining`            | Device joins a mining pool                                                                                               | T1/T2/T5 | Stratum JSON-RPC (`mining.subscribe` / `mining.authorize`) when cleartext; pool-domain indicators; long-lived low-volume session with steady small periodic upstream messages | high   | 0.3 |
| `spam-relay`              | Outbound SMTP (25) from a device that never sent mail                                                                    | T1       | Port set; hard rule above 10 connections/hour                                                                                                                                 | high   | 0.2 |
| `ad-fraud`                | Hidden ad traffic: many ad-network / tracker domains from a device with no screen, or at night from a TV box that is off | T2       | Host-supplied ad-domain indicator set × activity hours                                                                                                                        | medium | 0.4 |
| `credential-stuffing-out` | Many login POSTs to many different sites (device used as a stuffing proxy)                                               | T1/T3    | Short TLS sessions with similar sizes to many unrelated domains                                                                                                               | high   | 0.4 |

## B16. Remote access, tunnels and covert channels

| ID                    | Catches                                                                                                                                                   | Needs | Method                                 | Sev    | Rel |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- | -------------------------------------- | ------ | --- |
| `tunnel-service`      | Device connects to tunnel/remote-access services (ngrok, Cloudflare Tunnel, Tailscale/ZeroTier coordinators, remote-desktop relays) never in its baseline | T2    | Indicator domain families              | high   | 0.3 |
| `vpn-protocol`        | New WireGuard (UDP, fixed 148-byte handshake initiation), OpenVPN, IPsec (500/4500, ESP), or SSH session from a device that never used one                | T1    | Port/proto + handshake-size heuristics | high   | 0.3 |
| `icmp-tunnel`         | ICMP echo with large or highly variable payloads, or ICMP volume far over ping norms                                                                      | T1    | Bytes/packet and variance on ICMP      | high   | 0.3 |
| `ipv6-tunnel`         | 6in4 (IP proto 41), Teredo (UDP 3544), 6to4 appearing on an IPv4-only device                                                                              | T1    | Protocol set                           | high   | 0.3 |
| `quic-new`            | QUIC (UDP 443) from a device that never used it, to a non-baseline host                                                                                   | T1    | Port+proto set                         | medium | 0.4 |
| `ntp-rogue`           | Device syncs time from a non-baseline NTP server (time manipulation breaks cert checks and logs)                                                          | T1    | UDP 123 destination set                | medium | 0.3 |
| `reverse-shell-shape` | Interactive-looking session: small packets both directions, human-paced timing, to a non-baseline host                                                    | T1    | Packet size / inter-arrival profile    | high   | 1.x |

## B17. Firmware updates and supply chain

| ID                       | Catches                                                                                                                                    | Needs       | Method                                                                                           | Sev    | Rel |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ | ----------- | ------------------------------------------------------------------------------------------------ | ------ | --- |
| `update-from-new-source` | Large inbound download (> learned p99) from a host outside the baseline                                                                    | T1          | Size × destination                                                                               | high   | 0.3 |
| `update-over-cleartext`  | Large binary-sized download over plain HTTP/FTP/TFTP (tamperable in transit)                                                               | T1/T3       | Port + size                                                                                      | medium | 0.3 |
| `post-update-drift`      | Many detectors fire within 24 h after a large download: either a legitimate firmware update (offer one-click `relearn`) or a malicious one | correlation | Incident rule: `update-*` anomaly + ≥ 3 new-behavior anomalies → incident with both explanations | high   | 0.3 |
| `tftp-activity`          | Any TFTP (69/udp) to WAN — common malware download path on routers/cameras                                                                 | T1          | Hard rule                                                                                        | high   | 0.2 |

## B18. IP-layer spoofing and integrity

| ID                    | Catches                                                                                             | Needs                | Method                                 | Sev      | Rel |
| --------------------- | --------------------------------------------------------------------------------------------------- | -------------------- | -------------------------------------- | -------- | --- |
| `src-spoof`           | Packets from a device with a source IP that is not its lease (spoofed floods)                       | T1+T4                | Flow srcIp vs DHCP lease / ARP binding | critical | 0.3 |
| `ttl-anomaly`         | Device's outbound TTL/hop-limit changes (different OS stack or packets crafted by raw-socket tools) | T1 (needs TTL field) | Learned TTL set                        | medium   | 1.x |
| `llmnr-nbns-poison`   | Device answering LLMNR (5355) / NBNS (137) / mDNS queries for names it does not own                 | T4                   | Name ownership table                   | high     | 1.x |
| `icmp-redirect`       | ICMP redirects on the LAN from a non-router host                                                    | T1                   | Hard rule                              | high     | 0.3 |
| `dns-answer-mismatch` | Device receives DNS answers from an IP other than the resolver it queried (off-path spoofing)       | T2                   | Query/answer source join               | high     | 1.x |

## B19. Posture and device-class priors

Posture findings are **not attacks**. They report weaknesses that make attacks likely. Severity `info`/`low`. They are cheap and very useful to a product selling to homeowners or building managers.

| ID                        | Reports                                                                                  | Needs | Rel |
| ------------------------- | ---------------------------------------------------------------------------------------- | ----- | --- |
| `posture-listening-risky` | Device accepts connections on 23, 2323, 5555, 7547, 1900 (UPnP), 502, 47808 from the LAN | T1    | 0.2 |
| `posture-cleartext-auth`  | Logins over Telnet/FTP/HTTP Basic to or from device                                      | T1/T3 | 0.3 |
| `posture-weak-tls`        | TLS 1.0/1.1, expired or self-signed certs on the device's own services                   | T3    | 0.4 |
| `posture-wan-exposed`     | Device reachable from WAN (port forward / UPnP)                                          | T1    | 0.2 |

**Device-class priors** fix the poisoned-learning problem that BADBOX-style supply-chain malware creates. A device that ships infected has no clean baseline to learn from. The host can tag each device with a class (`camera`, `tv-box`, `thermostat`, `hvac-controller`, `plug`, `hub`, `printer`, `nas`). The engine then applies **class expectations** from day one, independent of what the device learned:

- A plug never needs more than a handful of destination families.
- A thermostat never uploads more than ~1 MB/hour.
- Nothing except `tv-box`/`nas`/`hub` has a reason to emit browser-class JA4.
- No class except `hub`/`nas` needs inbound LAN connections.

Class files are plain JSON shipped in `src/data/classes/` and editable by the host. A violation of a class expectation is reported as `class-violation` (high) even during learning.

---

### Catalog total

| Group                         | Detectors |
| ----------------------------- | --------- |
| B1–B11 (spec v2.0)            | 68        |
| B12 Residential proxy         | 8         |
| B13 Building automation / OT  | 10        |
| B14 IoT app protocols         | 7         |
| B15 Monetization abuse        | 4         |
| B16 Tunnels / covert channels | 7         |
| B17 Firmware / supply chain   | 4         |
| B18 IP-layer spoofing         | 5         |
| B19 Posture + class priors    | 5         |
| **Total**                     | **118**   |

---

# PART C — SCORING, OPERATIONS, EVALUATION

## C1. Correlation into incidents

Single anomalies are noisy. Operators act on incidents.

- An **incident** groups anomalies on one device within `incidentWindowMs` (default 30 min, sliding).
- Each anomaly maps to a stage: **recon** (scans, sweeps) → **c2** (new-beacon, dga, direct-ip, threat-intel, tor) → **spread** (horizontal-scan, lan-lateral, brute-force-out) → **impact** (floods, reflection, slow-exfil, dns-tunnel).
- **Risk score** 0–100 = sum of `severityWeight × confidence`, ×1.5 for each additional distinct stage, with exponential decay (half-life 6 h). `ack()` halves the remaining score.
- Incident severity: ≥ 2 stages or score ≥ 70 → `critical`.
- Emitted `incident` payload: `{ id, device, stages, score, severity, anomalyIds, firstTs, lastTs, summary }` where `summary` is a one-line plain-English story, e.g. _"cam-1 contacted a never-seen domain at 03:00, then scanned 400 hosts on port 23, then sent 80 MB to that domain."_

The 0.0.1 demo is exactly a 3-stage incident. Today it prints 6 separate lines.

## C2. MITRE ATT&CK mapping

Every anomaly carries `attack` IDs where a clear mapping exists. Examples: `T1046` network service discovery (scans), `T1110` brute force, `T1071.004` DNS application protocol, `T1568.002` DGA, `T1572` protocol tunneling, `T1041` exfiltration over C2, `T1498` network DoS, `T1557.002` ARP cache poisoning, `T1090.003` multi-hop proxy (Tor). Mappings live in one table so they can be corrected without touching detectors.

## C3. Output formats

Core emits native objects. Optional packages convert:

`@iotwarden/export-ocsf` (OCSF Detection Finding), `-ecs` (Elastic), `-syslog` (RFC 5424 / CEF), `-webhook`, `-mqtt` (for home-automation hubs).

## C4. Resource limits

| Limit                          | Default                                                     |
| ------------------------------ | ----------------------------------------------------------- |
| Devices                        | 10 000                                                      |
| Destinations per device        | 5 000                                                       |
| Alert-dedup entries per device | 5 000 (LRU)                                                 |
| History windows                | 10 080                                                      |
| Indicators                     | 1 000 000, stored as sorted arrays / CIDR tree, not objects |
| Per-window dst set             | Stops growing after fan-out fires; count only               |

Budgets: **< 100 KB per watching device with all 0.x detectors on; < 30 µs median `feed()` on a Raspberry Pi 4.** Measured by `bench/` in the repo every release.

## C5. Feedback loop

- `ack` / `suppress` / `allow` calls are recorded with operator ID if supplied.
- `stats().precision` estimates per-detector false-positive rate from suppress/allow vs ack. A detector whose estimated FP rate passes 50 % over 7 days emits `warning` `NOISY_DETECTOR`.

## C6. Evaluation (required before 1.0)

0.0.1 has only been tested on simulated traffic. That proves the code runs, not that detection works.

- **Datasets:**
  - **CICIoT2023**, from the University of New Brunswick: 33 attacks in 7 categories (DDoS, DoS, Recon, Web-based, Brute Force, Spoofing, Mirai) run against 105 IoT devices.
  - **IoT-23**, real IoT malware captures (Stratosphere Lab).
  - **N-BaIoT**, real devices infected with Mirai and BASHLITE.
- **Adapter:** `eval/` converts their PCAP/flows to T1/T2 events.
- **Metrics per detector and per attack class:** detection rate, time-to-detect, **false positives per device-day on the benign portion**.
- **Release gates:**

| Severity | Max false positives     |
| -------- | ----------------------- |
| ≥ high   | < 1 per device per week |
| medium   | < 1 per device per day  |

- **Publish the numbers in the README**, including the misses. Claims without them will not be trusted by anyone buying security software.

## C7. Security of the package itself

- Zero runtime dependencies in core. Adapters and exporters pin exact versions.
- `npm publish --provenance` from CI; 2FA on the npm account.
- `SECURITY.md` with a disclosure address and response time.
- Fuzz `feed()` and `importBaseline()` with random input (built-in `node:test` + a seeded generator).
- First npm publish is manual with 2FA; later releases use npm trusted publishing (OIDC) from GitHub Actions. No long-lived npm tokens anywhere.
- **Regulation.** If you sell iotwarden, or a gateway containing it, into the EU, it is a product with digital elements under the Cyber Resilience Act. Since **11 September 2026**, manufacturers must report actively exploited vulnerabilities and severe incidents: an early warning within 24 h, a notification within 72 h, and a final report later. Most other CRA obligations apply from **11 December 2027**. Plan the disclosure process now.

## C8. Package layout

```
iotwarden/                 (core, npm tarball)
  src/index.js  src/index.d.ts
  src/engine/   src/detectors/<id>.js   src/data/psl.json  src/data/attack-map.json
  README.md LICENSE CHANGELOG.md SECURITY.md
repo only (not published): test/ eval/ bench/ examples/ fuzz/
separate packages: @iotwarden/adapter-*, @iotwarden/export-*
```

`package.json`: `exports` with `types` + `require`; `files` whitelist; `repository`, `bugs`, `homepage`; `engines.node >= 22`; `sideEffects: false`. Check with `npm pack --dry-run` before each publish.

## C9. Versioning

Semver. While 0.x, minor may break API. Changing any threshold formula or default is a minor bump because it changes which alerts fire. Baseline format change bumps baseline `version`.

## C10. Roadmap

| Release  | Scope                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Gate                                                           |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| **0.1**  | Fix the 10 spec-v1 gaps (flush, idle windows, memory caps, validation…). Detectors: the original 4. Plugin interface.                                                                                                                                                                                                                                                                                                                                                     | All v1 acceptance tests                                        |
| **0.2**  | T1 flows + T2 DNS input. Hard rules. `new-domain-family`, `new-port`, `new-protocol`, `inbound-from-wan`, `threat-intel-match`, `bogon`, `horizontal-scan`, `vertical-scan`, `failed-connection-ratio`, `lan-lateral`, `volume-spike-hourly`, `upload-ratio-shift`, `packet-flood`, `reflection-participation`, `went-silent`, `nxdomain-burst`, `resolver-bypass`, `dns-rebinding`, `new-device`, `policy-violation`, integrity detectors. conntrack + dnsmasq adapters. | CICIoT2023 Recon/DDoS/Mirai detection ≥ 90 %, FP gates met     |
| **0.3**  | `direct-ip`, ASN/country, UPnP, Tor, `lan-sweep`, brute-force, `slow-exfil`, `protocol-mix-shift`, `connection-churn`, `new-beacon`, `long-connection`, `dga`, `dns-tunnel`, T4 link layer (ARP, DHCP, RA), zones. Incidents.                                                                                                                                                                                                                                             | IoT-23 + N-BaIoT results published                             |
| **0.3+** | **Proxyware first** (B12 `proxy-relay`, `blockchain-c2`, `supply-chain-suspect`) and device-class priors: this is the dominant IoT threat today and the strongest selling point. Plus `stream-to-new-destination`, `cryptomining`, tunnels (B16), update detectors (B17), `src-spoof`, `ot-wan-exposure`.                                                                                                                                                                 | Detects BADBOX/Kimwolf-style behavior in a replay test         |
| **0.4**  | T3 TLS detectors, `browser-mimic`, `proxy-backconnect`, `lan-via-proxy`, `p2p-pattern`, `beacon-change`, `answer-drift`, `fast-flux`, fleet/peer detectors. **T5 input + all OT detectors (B13)**, MQTT/ONVIF detectors. Zeek + Suricata + ICSNPP adapters.                                                                                                                                                                                                               | Pilot on ≥ 1 real home deployment and ≥ 1 building for 30 days |
| **1.0**  | MUD input, signed baselines, OCSF export, API freeze.                                                                                                                                                                                                                                                                                                                                                                                                                     | Stable for one minor release; security review                  |
| **1.x**  | `exploit-probe-http`, `day-of-week-drift`, `sni-ip-mismatch`, `young-domain`, `discovery-spoof`, `fleet-baseline-poisoning`, `mac-randomization-churn`, `ot-schedule-drift`, `reverse-shell-shape`, `ttl-anomaly`, `llmnr-nbns-poison`, `dns-answer-mismatch`.                                                                                                                                                                                                            | —                                                              |

---

# PART D — DELIBERATELY NOT INCLUDED

| Idea                                 | Why not                                                                                                                                                                                                                                                                                                                 |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Payload signatures / DPI             | Suricata and Snort already do this with thousands of maintained rules. Use their output as T3 input instead of competing.                                                                                                                                                                                               |
| Deep-learning anomaly models in core | Need training data per device type, are hard to explain to an operator, and would break the zero-dependency and small-memory goals. If wanted later: a separate `@iotwarden/ml` package that consumes the same events and emits `anomaly` with `confidence`. Must beat the statistical detectors on C6 metrics to ship. |
| Packet capture                       | Needs native bindings and root. The gateway already has better tools (conntrack, eBPF, Zeek).                                                                                                                                                                                                                           |
| Automatic blocking                   | A false positive on a lock, alarm or medical device can cause real harm. Hosts may block; the library never does.                                                                                                                                                                                                       |
| TLS interception                     | Breaks device certificate pinning, creates a huge liability, and is unnecessary for metadata detection.                                                                                                                                                                                                                 |
| Bundled threat feeds                 | License terms and API key rules change. A stale feed baked into an npm package is worse than none.                                                                                                                                                                                                                      |

---

# Appendix — v1 acceptance tests (still required for 0.1)

1. `flush()` offset 30 s from window boundaries yields the same alerts as boundary-aligned flushes.
2. Idle-heavy learning period: volume threshold counts silent windows.
3. 1 M distinct `dst` values keep heap growth bounded.
4. `importBaseline` with `__proto__`, oversize arrays or mismatched `windowMs` throws and leaves state unchanged.
5. `allow()` suppresses further `new-destination` for that host.
6. `relearn()` emits nothing until `learnMs` passes, then emits `learned`.
7. A throwing listener does not stop processing.
8. Non-UTC `hourOf`: `wrong-time` fires once per local day.
9. Realistic camera volume (~15 MB/window) produces no `volume-spike` in a normal week.

Added for 0.2+: one test per detector for "fires on attack", "silent on benign", "respects caps", and "survives export/import". Hard-rule detectors also get a "fires during learning" test.
