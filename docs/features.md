# hubvik — what it does and what it is not

hubvik is a **detector library**, not a protection appliance. It watches per-device network behavior on a gateway, emits reports when that behavior looks wrong, and **never** changes the traffic itself.

That boundary is normal for a serious npm package. Respected security packages on npm are narrow libraries (hashing, JWT, headers, rate limits, dep scanning). They harden one layer; they do not turn `npm install` into a firewall, IPS, EDR, or “you’re safe now” product. Real IoT/OT network security is sold as platforms, not as one blocking npm module.

Status: **3.2.0 prototype — not validated on real traffic.** Package: `hubvik` (`packages/core`). The detector catalog is at the end of this file. Also: [`README.md`](../README.md), [`DEVELOPERS.md`](DEVELOPERS.md).

---

## What detectors can do (IoT gateway)

All of these **only report**. They do not block. Many need event tiers above T0 (flow, DNS, TLS, link, OT/app). Default `tiers: ['T0']` runs a smaller live set. B21–B25 rows are **shadow** (`shadow-anomaly`) until evidence promotes them — they do not page by default.

Every detector id is in the catalog at the end of this file. Each id has one file under `packages/core/src/detectors/`. Shadow rows are implemented and stay off the default `anomaly` stream.

| Area                      | What the detectors look for                                                                                                                |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Destination and identity  | New hosts, ports, protocols, direct-IP command and control, ASN or country, bogons, Tor or proxy, peer-to-peer, threat intel, WAN exposure |
| Scanning and spread       | Fan-out, horizontal and vertical scans, failed connects, LAN lateral movement, brute force, HTTP exploit probes                            |
| Volume and flooding       | Spikes, upload-ratio shift, slow exfil, packet floods, protocol mix, reflection, connection churn                                          |
| Timing and rhythm         | Wrong hour, beacons, long connections, a device that went silent, day-of-week drift                                                        |
| DNS                       | DGA, NXDOMAIN bursts, tunnels, resolver bypass, answer drift, rebinding, fast flux, young domains                                          |
| TLS metadata              | New client fingerprint, certificate change, missing or mismatched SNI, TLS on an odd port, cleartext regression                            |
| Link layer                | New device, ARP spoof, rogue DHCP or router advertisement, identity change, MAC churn, discovery spoof                                     |
| Policy                    | Host rules, MUD, zone violations                                                                                                           |
| Fleet                     | One device diverges from its peers, many devices flip together, baseline poisoning                                                         |
| Engine integrity          | Input gaps, clock jumps, state caps, alert storms, a silent tier                                                                           |
| Proxyware                 | Relay, browser mimic, backconnect, LAN through a proxy, ADB, blockchain command and control                                                |
| Building and OT           | New master, writes, dangerous operations, value range, recon, schedule drift                                                               |
| IoT apps                  | MQTT broker, topics, rate, CoAP amplification, a camera stream to a new destination, ONVIF                                                 |
| Monetization              | Cryptomining, spam relay, ad fraud, outbound credential stuffing                                                                           |
| Tunnels and remote access | VPN and tunnel protocols, ICMP and IPv6 tunnels, new QUIC, rogue NTP, reverse-shell shape                                                  |
| Firmware                  | Update from a new source, cleartext update, post-update drift, TFTP                                                                        |
| Spoofing                  | Source spoof, TTL, LLMNR or NBNS poison, ICMP redirect, DNS answer mismatch                                                                |
| Posture                   | Risky listeners, cleartext auth, weak TLS, WAN exposed, class violation                                                                    |

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

**Bottom line:** hubvik **sees and reports** unusual device network behavior. The catalog at the end of this file is the full detector list. It does not stop attacks by itself and is not production-validated yet.

---

## What we can take from the tools operators already run

Checked 28 Oct 2026 against Part D of [`SPEC.md`](SPEC.md) and the tree. Part D wins over this file. `[x]` means the behavior is in the repo. `[ ]` means it is not. A check here is not a new work package.

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

### 3.0.1

Readers over anomalies the detectors already emit. No new detector row. No threshold change.

16. [x] **`engine.attacks(sinceTs)`.** Per device: stages (`recon`, `c2`, `spread`, `impact`) and technique ids already mapped to those detectors. `progressing` is true when two stages have been seen. That is the device moving through an attack, not one noisy detector.
17. [x] **`engine.waves(sinceTs)`.** A detector that already fired on three or more devices. That is the same bar a campaign uses. It is how a spread across the LAN shows up.
18. [x] **`engine.openIncidents(now)`.** Incidents the engine already opened and has not closed. The score is the one already stored. The call does not emit.

### 3.1.0

Readers over destinations, campaigns, and shadow hits the engine already has. No new detector row. No threshold change.

19. [x] **Destinations on `engine.attacks(sinceTs)`.** Up to 8 hosts already stored on those anomalies, first-seen order. That is where the device went.
20. [x] **`engine.campaigns(now)`.** Campaigns the engine already opened and has not closed. The devices, edges, and stages are the ones already stored. The call does not emit.
21. [x] **`engine.shadow(sinceTs)`.** A second ring of shadow anomalies, capped by `explainCap`. Same shape as `attacks`. It does not promote a detector.
22. [x] **`@hubvik/cli` 0.1.3 sections.** The HTML report lists Destinations, Campaigns, and Shadow when the JSONL already has them. Inline CSS. No script.

### 3.2.0

One read for a developer. No new detector row. No threshold change.

23. [x] **`engine.overview(now, sinceTs)`.** Attacks, waves, open incidents, campaigns, shadow hits, and counts in one object. Leave `sinceTs` out and it is 0. The call does not emit.

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

You don’t learn failures by guessing inside the npm package. You get them from **labeled live use** — and hubvik already has hooks for that (`feedback`, shadow mode, pilots). Core stays **offline** (no secret phone-home). Longer playbook: [`workout.md`](../workout.md).

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

<!-- detectors:start -->

## Detector catalog

Generated by `scripts/spec-coverage.mjs` from the detector rows and the detector files. Core 3.2.0. Do not edit this section by hand.

The last column is yes when the row Rel is at or below this package version. A later Rel is no even when its file is already in the tree. Those files are absent from "Not yet implemented".

## B1. Destination and identity

| ID                   | Rel | Severity | FP risk                                                                 | In this release |
| -------------------- | --- | -------- | ----------------------------------------------------------------------- | --------------- |
| `new-destination`    | 0.1 | medium   | Medium: CDNs rotate hostnames                                           | yes             |
| `new-domain-family`  | 0.2 | medium   | Low: removes CDN-subdomain noise                                        | yes             |
| `new-port`           | 0.2 | medium   | Low for IoT                                                             | yes             |
| `new-protocol`       | 0.2 | high     | Very low; GRE from a camera is Mirai GREIP/GREETH territory             | yes             |
| `direct-ip`          | 0.3 | medium   | Low on IoT; hard-coded C2 IPs are classic                               | yes             |
| `new-asn`            | 0.3 | medium   | Medium                                                                  | yes             |
| `new-country`        | 0.3 | low      | Medium                                                                  | yes             |
| `inbound-from-wan`   | 0.2 | high     | Low; means port forward/UPnP exposure                                   | yes             |
| `upnp-port-open`     | 0.3 | high     | Low                                                                     | yes             |
| `threat-intel-match` | 0.2 | critical | Depends on feed quality                                                 | yes             |
| `bogon-destination`  | 0.2 | info     | Low                                                                     | yes             |
| `tor-or-proxy`       | 0.3 | high     | Very low for IoT                                                        | yes             |
| `p2p-pattern`        | 0.4 | high     | Medium (some cameras use P2P relay legitimately; baseline catches that) | yes             |

## B2. Scanning and propagation

| ID                        | Rel | Severity                                                              | FP risk                                                        | In this release |
| ------------------------- | --- | --------------------------------------------------------------------- | -------------------------------------------------------------- | --------------- |
| `fan-out`                 | 0.1 | high                                                                  | Low                                                            | yes             |
| `horizontal-scan`         | 0.2 | critical                                                              | Very low                                                       | yes             |
| `vertical-scan`           | 0.2 | high                                                                  | Low                                                            | yes             |
| `failed-connection-ratio` | 0.2 | high                                                                  | Low; the most robust scan signal                               | yes             |
| `lan-lateral`             | 0.2 | high                                                                  | Low on IoT (devices rarely talk east-west except hub ↔ device) | yes             |
| `lan-sweep`               | 0.3 | high                                                                  | Low                                                            | yes             |
| `brute-force-out`         | 0.3 | critical                                                              | Very low                                                       | yes             |
| `brute-force-in`          | 0.3 | high                                                                  | Low                                                            | yes             |
| `exploit-probe-http`      | 0.8 | critical outbound, low inbound, high inbound with 2xx, medium unknown | Low outbound. High inbound: internet scanners                  | yes             |

## B3. Volume and flooding

| ID                         | Rel | Severity | FP risk                  | In this release |
| -------------------------- | --- | -------- | ------------------------ | --------------- |
| `volume-spike`             | 0.1 | high     | Medium for cameras       | yes             |
| `volume-spike-hourly`      | 0.2 | high     | Lower than flat baseline | yes             |
| `upload-ratio-shift`       | 0.2 | high     | Low                      | yes             |
| `slow-exfil`               | 0.3 | high     | Medium                   | yes             |
| `packet-flood`             | 0.2 | critical | Very low                 | yes             |
| `protocol-mix-shift`       | 0.3 | high     | Low                      | yes             |
| `reflection-participation` | 0.2 | critical | Very low                 | yes             |
| `connection-churn`         | 0.3 | high     | Low                      | yes             |

## B4. Timing and rhythm

| ID                  | Rel | Severity | FP risk                                                                                                                | In this release |
| ------------------- | --- | -------- | ---------------------------------------------------------------------------------------------------------------------- | --------------- |
| `wrong-time`        | 0.1 | low      | Medium                                                                                                                 | yes             |
| `new-beacon`        | 0.3 | high     | **High if applied to everything**: IoT devices beacon to vendors all day. Only score destinations outside the baseline | yes             |
| `beacon-change`     | 0.4 | medium   | Medium (firmware updates)                                                                                              | yes             |
| `long-connection`   | 0.3 | high     | Low                                                                                                                    | yes             |
| `went-silent`       | 0.2 | medium   | Medium                                                                                                                 | yes             |
| `day-of-week-drift` | 0.9 | low      | Medium; needs ≥ 2 weeks learning                                                                                       | yes             |

## B5. DNS

| ID                | Rel | Severity | FP risk                                                                       | In this release |
| ----------------- | --- | -------- | ----------------------------------------------------------------------------- | --------------- |
| `dga`             | 0.3 | high     | Medium per name, low per burst                                                | yes             |
| `nxdomain-burst`  | 0.2 | high     | Low                                                                           | yes             |
| `dns-tunnel`      | 0.3 | critical | Low with the combined score                                                   | yes             |
| `resolver-bypass` | 0.2 | high     | Low on IoT, though some devices hard-code 8.8.8.8, which the baseline absorbs | yes             |
| `answer-drift`    | 0.4 | high     | Medium (CDN changes); could indicate DNS hijack or spoofing                   | yes             |
| `dns-rebinding`   | 0.2 | high     | Low                                                                           | yes             |
| `fast-flux`       | 0.4 | high     | Medium                                                                        | yes             |
| `young-domain`    | 0.8 | medium   | Medium. The host chooses the list                                             | yes             |

## B6. Encrypted-traffic metadata (TLS/QUIC)

| ID                       | Rel | Severity | FP risk                                                  | In this release |
| ------------------------ | --- | -------- | -------------------------------------------------------- | --------------- |
| `new-client-fingerprint` | 0.4 | high     | Low on single-purpose IoT, medium after firmware updates | yes             |
| `cert-change`            | 0.4 | high     | Low; strong MITM signal                                  | yes             |
| `sni-missing`            | 0.4 | medium   | Medium                                                   | yes             |
| `sni-ip-mismatch`        | 0.9 | high     | Medium (CDNs)                                            | yes             |
| `tls-on-odd-port`        | 0.4 | medium   | Low                                                      | yes             |
| `cleartext-regression`   | 0.4 | high     | Low; downgrade attack or tampered firmware               | yes             |

## B7. Link layer and local network

| ID                        | Rel | Severity | FP risk                                           | In this release |
| ------------------------- | --- | -------- | ------------------------------------------------- | --------------- |
| `new-device`              | 0.2 | medium   | Low                                               | yes             |
| `arp-spoof`               | 0.3 | critical | Low (DHCP reassignments handled via lease events) | yes             |
| `gratuitous-arp-flood`    | 0.3 | high     | Low                                               | yes             |
| `rogue-dhcp`              | 0.3 | critical | Very low                                          | yes             |
| `dhcp-starvation`         | 0.3 | high     | Low                                               | yes             |
| `rogue-ra`                | 0.3 | critical | Very low                                          | yes             |
| `identity-change`         | 0.5 | high     | Low; signals MAC cloning or firmware swap         | yes             |
| `mac-randomization-churn` | 0.9 | info     | Phones do this legitimately; report, don't alarm  | yes             |
| `discovery-spoof`         | 0.9 | high     | Low                                               | yes             |

## B8. Policy and allowlists

| ID                 | Rel | Severity | FP risk | In this release |
| ------------------ | --- | -------- | ------- | --------------- |
| `policy-violation` | 0.2 | per rule |         | yes             |
| `mud-violation`    | 0.9 | high     |         | yes             |
| `zone-violation`   | 0.3 | high     |         | yes             |

## B9. Fleet and peer comparison

| ID                         | Rel | Severity | FP risk | In this release |
| -------------------------- | --- | -------- | ------- | --------------- |
| `peer-divergence`          | 0.4 | high     |         | yes             |
| `fleet-wave`               | 0.4 | medium   |         | yes             |
| `fleet-baseline-poisoning` | 0.9 | high     |         | yes             |

## B11. Engine integrity

| ID            | Rel | Severity | FP risk | In this release |
| ------------- | --- | -------- | ------- | --------------- |
| `input-gap`   | 0.2 | high     |         | yes             |
| `clock-jump`  | 0.2 | medium   |         | yes             |
| `state-cap`   | 0.2 | medium   |         | yes             |
| `alert-storm` | 0.2 | medium   |         | yes             |
| `tier-silent` | 0.5 | high     |         | yes             |

## B12. Residential proxy and "proxyware" — the main IoT threat of 2025–26

| ID                               | Rel | Severity | FP risk | In this release |
| -------------------------------- | --- | -------- | ------- | --------------- |
| `proxy-relay`                    | 0.3 | critical |         | yes             |
| `browser-mimic`                  | 0.4 | high     |         | yes             |
| `proxy-backconnect`              | 0.4 | critical |         | yes             |
| `lan-via-proxy`                  | 0.4 | critical |         | yes             |
| `adb-exposure`                   | 0.2 | critical |         | yes             |
| `private-answer-for-public-name` | 0.2 | high     |         | yes             |
| `blockchain-c2`                  | 0.3 | high     |         | yes             |
| `supply-chain-suspect`           | 0.3 | critical |         | yes             |

## B13. Building automation and OT protocols

| ID                      | Rel | Severity | FP risk | In this release |
| ----------------------- | --- | -------- | ------- | --------------- |
| `ot-new-master`         | 0.4 | critical |         | yes             |
| `ot-write-new`          | 0.4 | high     |         | yes             |
| `ot-dangerous-op`       | 0.4 | critical |         | yes             |
| `ot-value-out-of-range` | 0.4 | critical |         | yes             |
| `ot-write-rate`         | 0.4 | high     |         | yes             |
| `ot-recon`              | 0.4 | high     |         | yes             |
| `ot-spoof`              | 0.4 | critical |         | yes             |
| `ot-wan-exposure`       | 0.3 | critical |         | yes             |
| `ot-error-burst`        | 0.4 | medium   |         | yes             |
| `ot-schedule-drift`     | 0.9 | medium   |         | yes             |

## B14. IoT application protocols (MQTT, CoAP, RTSP/ONVIF)

| ID                          | Rel | Severity | FP risk | In this release |
| --------------------------- | --- | -------- | ------- | --------------- |
| `mqtt-new-broker`           | 0.2 | high     |         | yes             |
| `mqtt-wildcard-subscribe`   | 0.4 | high     |         | yes             |
| `mqtt-topic-new`            | 0.4 | medium   |         | yes             |
| `mqtt-publish-rate`         | 0.4 | medium   |         | yes             |
| `coap-amplification`        | 0.2 | critical |         | yes             |
| `stream-to-new-destination` | 0.3 | critical |         | yes             |
| `onvif-config-change`       | 0.4 | critical |         | yes             |

## B15. Device monetization abuse

| ID                        | Rel | Severity | FP risk | In this release |
| ------------------------- | --- | -------- | ------- | --------------- |
| `cryptomining`            | 0.3 | high     |         | yes             |
| `spam-relay`              | 0.2 | high     |         | yes             |
| `ad-fraud`                | 0.4 | medium   |         | yes             |
| `credential-stuffing-out` | 0.4 | high     |         | yes             |

## B16. Remote access, tunnels and covert channels

| ID                    | Rel | Severity | FP risk | In this release |
| --------------------- | --- | -------- | ------- | --------------- |
| `tunnel-service`      | 0.3 | high     |         | yes             |
| `vpn-protocol`        | 0.3 | high     |         | yes             |
| `icmp-tunnel`         | 0.3 | high     |         | yes             |
| `ipv6-tunnel`         | 0.3 | high     |         | yes             |
| `quic-new`            | 0.4 | medium   |         | yes             |
| `ntp-rogue`           | 0.3 | medium   |         | yes             |
| `reverse-shell-shape` | 0.9 | high     |         | yes             |

## B17. Firmware updates and supply chain

| ID                       | Rel | Severity | FP risk | In this release |
| ------------------------ | --- | -------- | ------- | --------------- |
| `update-from-new-source` | 0.3 | high     |         | yes             |
| `update-over-cleartext`  | 0.3 | medium   |         | yes             |
| `post-update-drift`      | 0.3 | high     |         | yes             |
| `tftp-activity`          | 0.2 | high     |         | yes             |

## B18. IP-layer spoofing and integrity

| ID                    | Rel | Severity | FP risk | In this release |
| --------------------- | --- | -------- | ------- | --------------- |
| `src-spoof`           | 0.3 | critical |         | yes             |
| `ttl-anomaly`         | 0.8 | medium   |         | yes             |
| `llmnr-nbns-poison`   | 0.9 | high     |         | yes             |
| `icmp-redirect`       | 0.3 | high     |         | yes             |
| `dns-answer-mismatch` | 0.9 | high     |         | yes             |

## B19. Posture and device-class priors

| ID                        | Rel | Severity | FP risk                                      | In this release |
| ------------------------- | --- | -------- | -------------------------------------------- | --------------- |
| `posture-listening-risky` | 0.2 | per rule |                                              | yes             |
| `posture-cleartext-auth`  | 0.3 | per rule |                                              | yes             |
| `posture-weak-tls`        | 0.4 | per rule |                                              | yes             |
| `posture-wan-exposed`     | 0.2 | per rule |                                              | yes             |
| `class-violation`         | 0.3 | high     | Low. No class is set until `setDeviceClass`. | yes             |

## B20. 2026 threat update (new rows for 0.5)

| ID                  | Rel | Severity                                  | FP risk                                             | In this release |
| ------------------- | --- | ----------------------------------------- | --------------------------------------------------- | --------------- |
| `egress-flood`      | 0.5 | critical                                  | Low. Camera upload is ~15 MB/window and two-way TCP | yes             |
| `proxy-sdk-traffic` | 0.5 | medium on smart-tv/tv-box, high otherwise | Depends on the host's list                          | yes             |

## B21. Shadow detectors (new rows for 0.8)

| ID                          | Rel | Severity | FP risk                                                                         | In this release |
| --------------------------- | --- | -------- | ------------------------------------------------------------------------------- | --------------- |
| `slow-scan`                 | 0.8 | high     | Low. IoT devices rarely add 40 new host/port pairs a day                        | yes             |
| `jitter-beacon`             | 0.8 | high     | Medium: NTP, push-notification keepalives. Baseline destinations are excluded   | yes             |
| `multi-horizon-exfil`       | 0.8 | high     | Medium: camera event clips, cloud backups on NAS. Class prior can raise the bar | yes             |
| `exploit-then-download`     | 0.8 | critical | Low on devices with no WAN exposure                                             | yes             |
| `ssh-brute-then-session`    | 0.8 | critical | Very low                                                                        | yes             |
| `cloud-storage-exfil`       | 0.8 | high     | Medium on `nas` and `camera` classes with cloud backup; baseline absorbs it     | yes             |
| `graph-new-bridge`          | 0.8 | high     | Low, provided zones are configured. No zones means no alert                     | yes             |
| `graph-role-change`         | 0.8 | high     | Low                                                                             | yes             |
| `nd-spoof`                  | 0.8 | critical | Low once F8 is on; high without it (privacy addresses rotate)                   | yes             |
| `dhcpv6-rogue`              | 0.8 | critical | Very low                                                                        | yes             |
| `wifi-deauth-flood`         | 0.8 | high     | Low. Note that 802.11w (PMF) networks reduce the real attack surface            | yes             |
| `evil-twin`                 | 0.8 | critical | Medium on mesh networks without `ownBssids`                                     | yes             |
| `upnp-callstranger`         | 0.8 | critical | Very low                                                                        | yes             |
| `matter-new-controller`     | 0.8 | high     | Low. Commissioning a new controller is rare and user-initiated                  | yes             |
| `peer-divergence-federated` | 0.9 | high     | Depends on summary freshness; stale summaries (> 7 days) are ignored            | yes             |

## B22. Shadow detectors (new rows for 1.1, spec 3.3)

| ID                         | Rel | Severity | FP risk                                                                                                          | In this release |
| -------------------------- | --- | -------- | ---------------------------------------------------------------------------------------------------------------- | --------------- |
| `dhcp-route-injection`     | 1.1 | high     | Low. Enterprise networks that push 121 legitimately are absorbed by the learned set                              | yes             |
| `wpad-hijack`              | 1.1 | high     | Low. Most home and building networks never answer WPAD                                                           | yes             |
| `ra-flood`                 | 1.1 | high     | Low                                                                                                              | yes             |
| `karma-responder`          | 1.1 | high     | Low. Real APs answer for the SSIDs they host, usually 1–4                                                        | yes             |
| `dictionary-dga`           | 1.1 | medium   | Medium per name (brand and marketing domains), low per burst because NXDOMAIN or low TTL is required             | yes             |
| `cname-cloak`              | 1.1 | medium   | Depends on the host's lists                                                                                      | yes             |
| `ja4-churn`                | 1.1 | high     | Low on single-stack IoT                                                                                          | yes             |
| `lan-first-seen-domain`    | 1.1 | low      | High alone; that is why it is `low` and capped                                                                   | yes             |
| `dormant-reactivation`     | 1.1 | high     | Medium: seasonal devices that update firmware on wake. A G3 `firmware-update` annotation removes it from scoring | yes             |
| `firmware-size-divergence` | 1.1 | high     | Low once peer groups are right (G10 helps)                                                                       | yes             |
| `stun-turn-relay`          | 1.1 | medium   | Medium: video doorbells use WebRTC. The baseline absorbs their relays                                            | yes             |
| `port-knock`               | 1.1 | high     | Low                                                                                                              | yes             |
| `bacnet-bbmd-write`        | 1.1 | critical | Very low                                                                                                         | yes             |
| `modbus-unit-sweep`        | 1.1 | high     | Low                                                                                                              | yes             |
| `mqtt-retained-command`    | 1.1 | high     | Low. Legitimate retained command topics are learned                                                              | yes             |
| `rtsp-new-viewer`          | 1.1 | high     | Low. NVRs and hubs are learned                                                                                   | yes             |
| `suppression-abuse`        | 1.1 | medium   | Medium after a large initial tuning session; that is why it is `medium`                                          | yes             |
| `multivariate-outlier`     | 1.1 | medium   | Medium. Shadow until evidence says otherwise                                                                     | yes             |
| `sequence-surprise`        | 1.1 | medium   | Medium                                                                                                           | yes             |
| `flow-shape-change`        | 1.1 | high     | Medium after firmware updates. Inactive until a host supplies `splt`                                             | yes             |

## B23. Shadow detectors (new rows for 1.2, spec 3.4)

| ID                     | Rel | Severity | FP risk                                                             | In this release |
| ---------------------- | --- | -------- | ------------------------------------------------------------------- | --------------- |
| `graph-contagion`      | 1.2 | high     | Medium when the graph is dense. No graph means no alert             | yes             |
| `doh-bypass`           | 1.2 | high     | Low once the device's own DoH resolver is in the baseline           | yes             |
| `spectral-beacon`      | 1.2 | high     | Medium: NTP and push keepalives. Baseline destinations are excluded | yes             |
| `modbus-address-sweep` | 1.2 | high     | Low                                                                 | yes             |
| `mqtt-will-takeover`   | 1.2 | high     | Low. Legitimate will topics are learned                             | yes             |

## B24. Shadow detectors (new rows for 1.6, spec 3.7)

| ID                 | Rel | Severity | FP risk                                                                                      | In this release |
| ------------------ | --- | -------- | -------------------------------------------------------------------------------------------- | --------------- |
| `dispersed-flood`  | 1.6 | high     | Low. Two-way camera uploads do not count. A single hot destination stays with `egress-flood` | yes             |
| `txt-channel`      | 1.6 | high     | Low. One TXT lookup does not fire                                                            | yes             |
| `inbound-lateral`  | 1.6 | high     | Low. Hubs that already talk on the LAN are learned                                           | yes             |
| `short-lived-cert` | 1.6 | medium   | Medium. A device that renews a one-day certificate is learned                                | yes             |

## B25. Shadow detectors (new rows for 2.0, spec 3.8)

| ID            | Rel | Severity | FP risk                                                                     | In this release |
| ------------- | --- | -------- | --------------------------------------------------------------------------- | --------------- |
| `h2-fanout`   | 2.0 | high     | Medium. A device that opens many new HTTP/2 destinations in one window      | yes             |
| `onion-name`  | 2.0 | high     | Low. An IoT device does not look up a Tor hidden service                    | yes             |
| `proxy-fanin` | 2.0 | high     | Low. A learned inbound peer does not count, and a scan has no two-way bytes | yes             |
| `scatter-udp` | 2.0 | high     | Low. DNS, NTP, and a destination at 200 packets stay with the other rows    | yes             |

## Not yet implemented

## Counts

| Group                                                                   | Rows |
| ----------------------------------------------------------------------- | ---- |
| B1. Destination and identity                                            | 13   |
| B2. Scanning and propagation                                            | 9    |
| B3. Volume and flooding                                                 | 8    |
| B4. Timing and rhythm                                                   | 6    |
| B5. DNS                                                                 | 8    |
| B6. Encrypted-traffic metadata (TLS/QUIC)                               | 6    |
| B7. Link layer and local network                                        | 9    |
| B8. Policy and allowlists                                               | 3    |
| B9. Fleet and peer comparison                                           | 3    |
| B11. Engine integrity                                                   | 5    |
| B12. Residential proxy and "proxyware" — the main IoT threat of 2025–26 | 8    |
| B13. Building automation and OT protocols                               | 10   |
| B14. IoT application protocols (MQTT, CoAP, RTSP/ONVIF)                 | 7    |
| B15. Device monetization abuse                                          | 4    |
| B16. Remote access, tunnels and covert channels                         | 7    |
| B17. Firmware updates and supply chain                                  | 4    |
| B18. IP-layer spoofing and integrity                                    | 5    |
| B19. Posture and device-class priors                                    | 5    |
| B20. 2026 threat update (new rows for 0.5)                              | 2    |
| B21. Shadow detectors (new rows for 0.8)                                | 15   |
| B22. Shadow detectors (new rows for 1.1, spec 3.3)                      | 20   |
| B23. Shadow detectors (new rows for 1.2, spec 3.4)                      | 5    |
| B24. Shadow detectors (new rows for 1.6, spec 3.7)                      | 4    |
| B25. Shadow detectors (new rows for 2.0, spec 3.8)                      | 4    |
| Total                                                                   | 170  |

<!-- detectors:end -->
