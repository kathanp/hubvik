# hubvik — what it does and what it is not

hubvik is a **detector library**, not a protection appliance. It watches per-device network behavior on a gateway, emits reports when that behavior looks wrong, and **never** changes the traffic itself.

That boundary is normal for a serious npm package. Respected security packages on npm are narrow libraries (hashing, JWT, headers, rate limits, dep scanning). They harden one layer; they do not turn `npm install` into a firewall, IPS, EDR, or “you’re safe now” product. Real IoT/OT network security is sold as platforms, not as one blocking npm module.

Status: **2.3.0 prototype — not validated on real traffic.** Package: `hubvik` (`packages/core`). Full machine-generated catalog: [`docs/DETECTORS.md`](docs/DETECTORS.md) (170 rows). Also: [`README.md`](README.md), [`docs/DEVELOPERS.md`](docs/DEVELOPERS.md).

---

## What detectors can do (IoT gateway)

All of these **only report**. They do not block. Many need event tiers above T0 (flow, DNS, TLS, link, OT/app). Default `tiers: ['T0']` runs a smaller live set. B21–B25 rows are **shadow** (`shadow-anomaly`) until evidence promotes them — they do not page by default.

### Capability map — full detector id lists (nothing left out)

Third column is **every** id in that group (from [`docs/DETECTORS.md`](docs/DETECTORS.md)), not examples.

| Area                                      | What the detectors look for                                                                                                               | All detector ids                                                                                                                                                                                                          |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **B1 Destination & identity** (13)        | New hosts/ports/protocols, direct IP C2, ASN/country, bogons, Tor/proxy, P2P, threat-intel, WAN exposure / UPnP                           | `new-destination`, `new-domain-family`, `new-port`, `new-protocol`, `direct-ip`, `new-asn`, `new-country`, `inbound-from-wan`, `upnp-port-open`, `threat-intel-match`, `bogon-destination`, `tor-or-proxy`, `p2p-pattern` |
| **B2 Scanning & spread** (9)              | Fan-out, horizontal/vertical scans, failed connects, LAN lateral/sweep, brute force in/out, HTTP exploit probes                           | `fan-out`, `horizontal-scan`, `vertical-scan`, `failed-connection-ratio`, `lan-lateral`, `lan-sweep`, `brute-force-out`, `brute-force-in`, `exploit-probe-http`                                                           |
| **B3 Volume & flooding** (8)              | Spikes (flat + hourly), upload-ratio shift, slow exfil, packet floods, protocol mix, reflection, connection churn                         | `volume-spike`, `volume-spike-hourly`, `upload-ratio-shift`, `slow-exfil`, `packet-flood`, `protocol-mix-shift`, `reflection-participation`, `connection-churn`                                                           |
| **B4 Timing & rhythm** (6)                | Wrong hour, new/changed beacons, long connections, device went silent, day-of-week drift                                                  | `wrong-time`, `new-beacon`, `beacon-change`, `long-connection`, `went-silent`, `day-of-week-drift`                                                                                                                        |
| **B5 DNS abuse** (8)                      | DGA, NXDOMAIN bursts, DNS tunnel, resolver bypass, answer drift, rebinding, fast flux, young domains                                      | `dga`, `nxdomain-burst`, `dns-tunnel`, `resolver-bypass`, `answer-drift`, `dns-rebinding`, `fast-flux`, `young-domain`                                                                                                    |
| **B6 TLS / encrypted metadata** (6)       | New client fingerprint, cert change, missing/mismatched SNI, TLS on odd port, cleartext regression                                        | `new-client-fingerprint`, `cert-change`, `sni-missing`, `sni-ip-mismatch`, `tls-on-odd-port`, `cleartext-regression`                                                                                                      |
| **B7 Link layer / LAN** (9)               | New device, ARP spoof/flood, rogue DHCP/RA, DHCP starvation, identity change, MAC churn, discovery spoof                                  | `new-device`, `arp-spoof`, `gratuitous-arp-flood`, `rogue-dhcp`, `dhcp-starvation`, `rogue-ra`, `identity-change`, `mac-randomization-churn`, `discovery-spoof`                                                           |
| **B8 Policy** (3)                         | Host policy rules, MUD, zone violations                                                                                                   | `policy-violation`, `mud-violation`, `zone-violation`                                                                                                                                                                     |
| **B9 Fleet / peers** (3)                  | One device diverges from peers; many devices flip together; baseline poisoning                                                            | `peer-divergence`, `fleet-wave`, `fleet-baseline-poisoning`                                                                                                                                                               |
| **B11 Engine integrity** (5)              | Input gaps, clock jumps, state caps, alert storms, silent tiers                                                                           | `input-gap`, `clock-jump`, `state-cap`, `alert-storm`, `tier-silent`                                                                                                                                                      |
| **B12 Proxyware / residential proxy** (8) | Proxy relay, browser mimic, backconnect, LAN-via-proxy, ADB exposure, private answer for public name, blockchain C2, supply-chain suspect | `proxy-relay`, `browser-mimic`, `proxy-backconnect`, `lan-via-proxy`, `adb-exposure`, `private-answer-for-public-name`, `blockchain-c2`, `supply-chain-suspect`                                                           |
| **B13 Building / OT** (10)                | New master, writes, dangerous ops, value range, write rate, recon, spoof, WAN exposure, error burst, schedule drift                       | `ot-new-master`, `ot-write-new`, `ot-dangerous-op`, `ot-value-out-of-range`, `ot-write-rate`, `ot-recon`, `ot-spoof`, `ot-wan-exposure`, `ot-error-burst`, `ot-schedule-drift`                                            |
| **B14 IoT apps (MQTT / CoAP / RTSP)** (7) | New MQTT broker/topics/wildcards/rate, CoAP amp, camera stream to new dest, ONVIF config change                                           | `mqtt-new-broker`, `mqtt-wildcard-subscribe`, `mqtt-topic-new`, `mqtt-publish-rate`, `coap-amplification`, `stream-to-new-destination`, `onvif-config-change`                                                             |
| **B15 Monetization abuse** (4)            | Cryptomining, spam relay, ad fraud, outbound credential stuffing                                                                          | `cryptomining`, `spam-relay`, `ad-fraud`, `credential-stuffing-out`                                                                                                                                                       |
| **B16 Tunnels / remote access** (7)       | Tunnel/VPN protocols, ICMP/IPv6 tunnels, new QUIC, rogue NTP, reverse-shell shape                                                         | `tunnel-service`, `vpn-protocol`, `icmp-tunnel`, `ipv6-tunnel`, `quic-new`, `ntp-rogue`, `reverse-shell-shape`                                                                                                            |
| **B17 Firmware / supply chain** (4)       | Update from new source, cleartext update, post-update drift, TFTP                                                                         | `update-from-new-source`, `update-over-cleartext`, `post-update-drift`, `tftp-activity`                                                                                                                                   |
| **B18 Spoofing / integrity** (5)          | Source spoof, TTL anomaly, LLMNR/NBNS poison, ICMP redirect, DNS answer mismatch                                                          | `src-spoof`, `ttl-anomaly`, `llmnr-nbns-poison`, `icmp-redirect`, `dns-answer-mismatch`                                                                                                                                   |
| **B19 Posture / device class** (5)        | Risky listeners, cleartext auth, weak TLS, WAN exposed, class violation                                                                   | `posture-listening-risky`, `posture-cleartext-auth`, `posture-weak-tls`, `posture-wan-exposed`, `class-violation`                                                                                                         |
| **B20 2026 threat update** (2)            | High egress flood shape; proxy-SDK style traffic                                                                                          | `egress-flood`, `proxy-sdk-traffic`                                                                                                                                                                                       |

### Shadow-only groups — full id lists (opt-in; do not page by default)

| Group           | Count | All detector ids                                                                                                                                                                                                                                                                                                                                                                                              |
| --------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **B21** Rel 0.8 | 15    | `slow-scan`, `jitter-beacon`, `multi-horizon-exfil`, `exploit-then-download`, `ssh-brute-then-session`, `cloud-storage-exfil`, `graph-new-bridge`, `graph-role-change`, `nd-spoof`, `dhcpv6-rogue`, `wifi-deauth-flood`, `evil-twin`, `upnp-callstranger`, `matter-new-controller`, `peer-divergence-federated`                                                                                               |
| **B22** Rel 1.1 | 20    | `dhcp-route-injection`, `wpad-hijack`, `ra-flood`, `karma-responder`, `dictionary-dga`, `cname-cloak`, `ja4-churn`, `lan-first-seen-domain`, `dormant-reactivation`, `firmware-size-divergence`, `stun-turn-relay`, `port-knock`, `bacnet-bbmd-write`, `modbus-unit-sweep`, `mqtt-retained-command`, `rtsp-new-viewer`, `suppression-abuse`, `multivariate-outlier`, `sequence-surprise`, `flow-shape-change` |
| **B23** Rel 1.2 | 5     | `graph-contagion`, `doh-bypass`, `spectral-beacon`, `modbus-address-sweep`, `mqtt-will-takeover`                                                                                                                                                                                                                                                                                                              |
| **B24** Rel 1.6 | 4     | `dispersed-flood`, `txt-channel`, `inbound-lateral`, `short-lived-cert`                                                                                                                                                                                                                                                                                                                                       |
| **B25** Rel 2.0 | 4     | `h2-fanout`, `onion-name`, `proxy-fanin`, `scatter-udp`                                                                                                                                                                                                                                                                                                                                                       |

**Catalog total: 170 detector rows** (122 in B1–B20 + 48 shadow in B21–B25). [x] Each id has a file under `packages/core/src/detectors/`. Source of truth: [`docs/DETECTORS.md`](docs/DETECTORS.md). Shadow rows are implemented and stay off the default `anomaly` stream.

---

## What it does

Runs on IoT gateways, smart-home hubs, building-management servers, and OpenWrt-class Node (≥ 22) appliances. It:

1. [x] Learns each device’s normal network behavior (destinations, volume, timing; richer signals when you feed higher tiers).
2. [x] Compares live traffic to that baseline and to hard rules / known-bad patterns when configured.
3. [x] Emits structured events (`anomaly`, and related signals such as incidents when enabled) so the **host product** can log, page, quarantine, or ignore them.

**Report-only (binding):** hubvik does not block, drop, or rewrite traffic. Your host product decides what to do with reports.

| hubvik does                                        | hubvik does not                         |
| -------------------------------------------------- | --------------------------------------- |
| Accept events (`feed`, `flush`, `tick`)            | Capture packets itself                  |
| Maintain per-device baselines                      | Sit in the forwarding path              |
| Emit anomalies to listeners                        | Drop, rate-limit, NAT, or rewrite flows |
| Export/import baselines                            | Apply nftables / firewall rules for you |
| Optional text response _hints_ (separate packages) | Execute those hints                     |

Adapters (conntrack, dnsmasq, Zeek, Suricata EVE, …) only translate logs into events. Exporters only format reports.

```js
const { createEngine } = require('hubvik');
const engine = createEngine({ learnMs: 7 * 24 * 3600e3 });

engine.feed({ device: 'aa:bb:cc:dd:ee:ff', dst: 'video.vendor.com', bytes: 2048, ts: Date.now() });

engine.on('anomaly', (a) => {
  // Host product decides: log, page, or ignore.
});

setInterval(() => engine.flush(Date.now()), 60e3);
```

### Input tiers (you must supply events)

| Tier | Typical source      | Roughly adds                       |
| ---- | ------------------- | ---------------------------------- |
| T0   | DNS / summary       | device, destination, bytes, time   |
| T1   | conntrack / flow    | 5-tuple, direction, ports, volumes |
| T2   | dnsmasq / Unbound   | DNS query, answers, TTLs           |
| T3   | Zeek / Suricata EVE | TLS/HTTP metadata                  |
| T4   | ARP / DHCP          | Link-layer identity                |
| T5   | OT / app logs       | BACnet, Modbus, MQTT, …            |

Default `tiers` is `['T0']`. Detectors that need a missing tier stay off.

### Learning

- [x] `learnMs` default 7 days per device from first event.
- [x] Export / import / `lock()` after review / `relearn()` as needed.
- [x] Compromise during learning can become “normal” — review before `lock()`.

---

## What it is not

`npm install hubvik` gives a **library API**. Nothing watches the LAN until your process creates an engine and feeds events.

Worth stating (because people confuse detectors with enforcers):

- **Not a firewall, IPS, or auto-blocker.** No allow/deny path, no packet refuse/reset. Hosts may block; the library never does (false positives on locks/alarms/medical devices can cause real harm).
- **Not an EDR / antivirus on the device.** No file scan, process hook, or endpoint remediation.
- **Not Suricata/Snort/Zeek.** No packet capture, DPI signatures, or TLS interception in core — use those tools and optionally feed metadata in.
- **Not a bundled threat-feed + auto-block service.** No stale IoCs baked into the package; host may pass indicators in.
- **Not app/lockfile security.** Not Express middleware, not `npm audit` / Snyk, not password/JWT/secrets tooling.
- **Not a turnkey SOC or “install and you’re protected” product.** Offline core; no required cloud telemetry; no warranty that attacks are stopped.

Deliberately out of core (see Part D of the spec): heavy ML in core, auto-executing playbooks, auto-retuning thresholds from live labels, auto device-class or peer-group assignment, and promoting shadow detectors without evidence.

### Not production-validated yet

`[x]` means the repo already contains it. `[ ]` means it is still open.

- [x] README status line: **prototype — not validated on real traffic.**
- [ ] 0.6 gate (C6.3 false positives under 1 per benign device-day for every default-on detector).
- [ ] Raspberry Pi 4 bench numbers in `docs/BENCHMARKS.md`.
- [ ] API freeze.
- [ ] Security review.
- [ ] 30-day pilot on one home and one building.
- [x] IoT-23 malware and honeypot result files exist (`eval/results/iot23-malware/iot23.md`, `eval/results/iot23-honeypot/iot23.md`). Strict detection on the malware capture is 9/17 ≈ 52.9%. That sample is too small to market.
- [ ] CICIoT2023 run on real captures. The joiner is in `eval/ciciot2023.js` and is marked UNVERIFIED. It has not been run on real data.
- [ ] False-positive gate. The malware capture is about 4.32 false positives per benign device-day.
- [x] Shadow mode. B21–B25 emit `shadow-anomaly` until evidence promotes them.
- [x] `npm run gate` exists. It proves engineering consistency, not efficacy on a network.

---

## Limits

1. Sees only traffic that crosses the gateway.
2. Encrypted content is opaque; who / how much / when can still help.
3. Attacks inside the learned baseline are not flagged.
4. Poisoned learning teaches the wrong normal — review + `lock()`.
5. A compromised gateway defeats detection.
6. No feed / wrong `tiers` → blind detectors.
7. Reports without a host workflow are noise, not protection.

---

## How to say it

| Prefer                                                    | Avoid                                    |
| --------------------------------------------------------- | ---------------------------------------- |
| Per-device network anomaly **detection** for IoT gateways | “Blocks cyber attacks” / “npm antivirus” |
| Reports; host decides action                              | “Firewall / IPS / EDR in npm”            |
| Prototype; evidence gates open                            | “Production-validated protection”        |
| Complements Suricata/Zeek/conntrack                       | “Replaces your security stack”           |

**Bottom line:** hubvik **sees and reports** unusual device network behavior across **170 detector rows** (destination, scan, DNS, TLS, LAN, OT, MQTT, proxyware, and more). It does not stop attacks by itself and is not production-validated yet.

---

## What we can take from the tools operators already run

Checked 28 Oct 2026 against Part D of [`docs/SPEC.md`](docs/SPEC.md) and the tree. Part D wins over this file. `[x]` means the behavior is in the repo. `[ ]` means it is not. A check here is not a new work package.

`npm install hubvik` can absorb the **detection and reporting** slice of those tools. It cannot absorb the **enforcement, capture, or cloud-crowd** slice. Putting that slice in core would make a false positive on a lock, alarm, or building controller into an outage, and it would duplicate Suricata, Zeek, and CrowdSec instead of reading their logs.

| Tool                         | What they own                                     | Can it go in the hubvik package?                                                                                                                                                                                                                                                           |
| ---------------------------- | ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Fail2ban                     | Log-driven bans                                   | [x] Brute-force detectors report it. [x] `@hubvik/respond-nftables` renders rule text. The host applies it. The package does not ban.                                                                                                                                                      |
| CrowdSec                     | Behavior on logs, a community blocklist, bouncers | [x] Behavior on events the host feeds. [x] A blocklist the host loads through `loadIndicators()`. A list baked into the tarball is out. A bouncer that drops traffic is out. Silent upload is out.                                                                                         |
| Maltrail                     | Trail matches against malicious destinations      | [x] The host supplies `{ value, type, source, confidence, expiresTs }`. Core ships no feed.                                                                                                                                                                                                |
| Zeek                         | Protocol metadata from packets                    | [x] `@hubvik/adapter-zeek` turns Zeek JSON into events. Core does not capture packets and does not parse payloads.                                                                                                                                                                         |
| Suricata                     | Signatures, optional inline blocking              | [x] `@hubvik/adapter-suricata-eve` reads EVE JSON. [x] `loadRules()` loads site rules that are data (no regular expressions). Inline drop stays in Suricata.                                                                                                                               |
| Firewalla                    | Consumer gateway, hardware, app, blocking         | [x] Per-device alarms. A box, a phone app, and a block path are out.                                                                                                                                                                                                                       |
| Leetha                       | Passive fingerprinting, a baseline, a dashboard   | [x] Identity (`identity: 'auto'`), a baseline, and `explain()`. [x] Class suggestion (`classSuggest`, default off) warns `CLASS_SUGGESTED` and never calls `setDeviceClass` (`packages/core/test/class-suggest.test.js`). [x] `@hubvik/cli` HTML report. Active probing of devices is out. |
| NIST MUD / Cisco MUD-Manager | Manufacturer allowlists turned into switch ACLs   | [x] `mud-violation` reports a break from a profile the host installed. [x] `@hubvik/mud` parses a local MUD file into `loadMud` allows. Installing ACLs on a switch is out.                                                                                                                |

### Already in the tree (do not rebuild these)

These are the advanced pieces of those products that already fit the contract. Several sibling packages are still marked UNVERIFIED in the spec.

- [x] Per-device baseline, export/import, `lock()`, incidents, campaigns, shadow mode.
- [x] `loadIndicators()` for IP, CIDR, domain, JA4, and the typed lists (`tor`, `ad`, `young-domain`, `proxy-sdk`, `tracker`). Expired rows are ignored. No feed ships inside the package.
- [x] `loadRules()` for site detections: prefix, suffix, contains, counts, sequences. Cap 256 rules. No `eval`, no regular expressions.
- [x] `explain()`, `feedback()`, `exportLabels()`, `stats().precision`.
- [x] Identity re-key from IPv6 and DHCP onto a MAC when `identity: 'auto'`.
- [x] Response hints, off unless `responseHints: true`. Actions are words (`review`, `relearn`, `isolate-device`, `block-destination`, `rate-limit`). `ot-*` and `safety` devices stay at `review`. The nftables package returns text and does not spawn a process.
- [x] Adapters for conntrack, dnsmasq, Zeek, and Suricata EVE, plus OCSF, syslog, webhook, and Prometheus export. Several sibling packages are still marked UNVERIFIED in the spec.
- [x] `@hubvik/cli` replay and a self-contained HTML report (inline CSS, no CDN): per-device timeline, incidents, top detectors, explain text. Snapshot test: `packages/cli/test/cli.test.js`.

### Proposed

These five shipped in `hubvik@2.2.0` and the two sibling packages. Each one reports or formats. None of them captures, blocks, phones home, or assigns a device class by itself.

1. [x] **`engine.digest(sinceTs)` in `hubvik`.** One plain-language summary per device since a timestamp. Built from live anomalies the engine already emitted. `packages/core/test/report.test.js`.
2. [x] **`engine.inventory()` in `hubvik`.** Devices already seen, identity addresses, learned ports and protocols, and `suggestions` only when `classSuggest` is on. The host still calls `setDeviceClass`.
3. [x] **F9 class suggestion, still only a suggestion.** `classSuggest` (default off) fills `stats().classSuggestions` and warns `CLASS_SUGGESTED` when the top score leads. The engine never calls `setDeviceClass`. Tests: `packages/core/test/class-suggest.test.js`.
4. [x] **`@hubvik/indicators-file`.** Reads a file the host already downloaded and returns the array `loadIndicators()` accepts. No network call and no indicator rows in the package. Cap 100,000.
5. [x] **`@hubvik/mud`.** Parses a MUD file the host fetched into `{ allows }` for `loadMud`. It does not write nftables, RADIUS, or switch ACLs. Cap 64 allows.
6. [x] **`engine.exportDecisions()` in `hubvik`.** JSON of destinations the engine already flagged. The host may POST it. The function opens no socket. The ring is capped by `explainCap`.
7. [x] **`@hubvik/cli` `report`.** One HTML file, inline CSS, no CDN. Per-device timeline, incidents, top detectors, explain text. This is the on-box screen. Use it before any hosted console.

The false-positive gate and the 30-day pilot are still open. These helpers do not change a detector threshold.

### 2.3.0

Eight more report-only pieces. No new detector row. No threshold change. A ban in a decisions file is not applied.

8. [x] **`engine.counts(sinceTs)`.** How often each detector fired since a timestamp. This is the count the measurement section asked for. `packages/core/test/report.test.js`.
9. [x] **`engine.hints(sinceTs)`.** The F16 hint words already stored on live anomalies. Empty unless `responseHints` is on. The call does not isolate, rate-limit, or block.
10. [x] **`engine.noisy()`.** Detectors whose existing `feedback` labels are already over the noisy bar. It does not change a threshold.
11. [x] **`engine.quiet(now, quietMs)`.** Seen devices with no event for that long. It does not emit `went-silent` and it does not power anything off.
12. [x] **`@hubvik/trail`.** A local one-host-per-line trail file into `loadIndicators` rows. No download and no bundled hosts. Cap 100,000.
13. [x] **`@hubvik/decisions-file`.** A local decisions file into `loadIndicators` rows. `Ip`, `Range`, and `Domain` become indicator types. A ban type is dropped. Cap 100,000.
14. [x] **`@hubvik/rules-file`.** A local JSON rules file for `loadRules`. Keys named `regex`, `regexp`, or `pcre` are rejected. Cap 256.
15. [x] **`@hubvik/cli` 0.1.2 sentences.** The HTML report lists one sentence per anomaly and hint lines when the JSONL already has them. Inline CSS. No script.

### Stays outside the hubvik package

Part D. Do not add these as future npm work, and do not implement them in `packages/core`.

| Idea                                                                  | Why it stays out                                                                                                                                                     |
| --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Executing a ban, drop, reject, or rate limit                          | Fail2ban, CrowdSec bouncers, Suricata IPS, and Firewalla do this. A false positive on a lock or a chiller is harm. Hints stay text.                                  |
| Packet capture, payload signatures, DPI, TLS interception             | Zeek and Suricata already do this. Native capture needs root. Interception breaks pinned device certificates. Feed their logs in.                                    |
| A threat feed, trail file, or ASN/country database inside the tarball | Licenses and keys change. Indicators expire in days. The host loads them.                                                                                            |
| Regular expressions in rules                                          | ReDoS on one gateway thread.                                                                                                                                         |
| Deep learning, isolation forests, autoencoders in core                | A separate `@hubvik/ml` may exist only if it beats the statistical detectors on the C6 metrics. Half-space trees are the multivariate model core is allowed to keep. |
| Auto-applying a device class or a peer group                          | The device could be compromised during learning and would choose the class that hides it.                                                                            |
| Auto-changing a threshold from labels                                 | An attacker who can cause labels or wealth can train the gateway. A person approves each number.                                                                     |
| Default phone-home, crowd upload, or a required cloud account         | The package stays offline. Sharing is a host call to `exportLabels()` or, later, `exportDecisions()`.                                                                |
| Hardware, a mobile app, or a claim that install equals protection     | That is a product around the library, after a pilot, not another export of `hubvik`.                                                                                 |

**Bottom line (other tools):** hubvik’s npm package can be the per-device brain those tools do not ship: baselines, site rules, host-supplied indicators, identity, a suggestion of class, a text hint, and a static report. Fail2ban’s ban, CrowdSec’s bouncer, Suricata’s drop, Zeek’s capture, Firewalla’s box, and a baked-in blocklist stay outside it.

---

## How to measure what fails (pilots + feedback)

You don’t learn failures by guessing inside the npm package. You get them from **labeled live use** — and hubvik already has hooks for that (`feedback`, shadow mode, pilots). Core stays **offline** (no secret phone-home). Longer playbook: [`workout.md`](workout.md).

### 1. Measure first (before random users)

- [x] IoT-23 result files are in `eval/results/`. The false-positive gate still fails.
- [ ] CICIoT2023 on real captures. The joiner exists and is UNVERIFIED.
- [ ] A **30-day pilot** on one home + one building (open gate in the spec). You own the gateways; you see which detectors fire on real quiet traffic.

### 2. Design partners / early npm users (voluntary)

Ask integrators to:

1. [x] The API for this exists: normal `anomaly` listeners, and `shadow: true` for shadow rows.
2. [x] When an operator says “noise” or “real,” call the built-in API:

```js
engine.feedback(anomalyId, 'fp'); // or 'tp', 'benign-true', 'unknown'
```

3. [x] The export API exists. Periodically send **aggregated** exports (not raw PCAP unless they agree):
   - `engine.exportLabels()` — JSONL of verdicts
   - `engine.stats().precision` — per-detector FP rates; warns `NOISY_DETECTOR` when `fpRate > 0.5` and `n >= 10`
   - counts: detector id → how often it fired / was marked FP

That’s how you learn **which** detectors fail in the wild without turning npm into spyware.

### 3. What “failed” means in practice

| Signal                                            | Meaning                            |
| ------------------------------------------------- | ---------------------------------- |
| High `fp` labels on one id                        | Too noisy → tighten or keep shadow |
| Almost never fires on known attacks in eval/pilot | Blind → improve that one detector  |
| Shadow fires a lot, live stays quiet              | Candidate to study before promote  |

### 4. What not to do

- Don’t auto-upload user traffic from the package (against offline design + trust).
- Don’t wait for “all npm users” — start with **1–2 pilots** who agree to label for 30 days.

**Bottom line (measurement):** failed measures come from **pilots + `feedback()` labels + eval**, not from the library magically knowing. Recruit a few gateway developers, give them a short “label FP/TP weekly, send `exportLabels`” playbook, and fix the noisiest ids first.
