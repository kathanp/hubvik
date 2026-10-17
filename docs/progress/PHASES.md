# Phases 0–4

One note for the 0.0.1 through 0.4.0 build. Not validated on real traffic.

## Phase 0

Date: 2026-10-16. Package name: `iotwarden`.

`scripts/check-name.mjs` checks the npm exact name, punctuation variants, similar packages, `@name/core`, and an optional GitHub repo. npm workspaces. The publishable package is `packages/core` (`iotwarden@0.0.1`) with empty `dependencies`. Root tooling: ESLint flat config, Prettier, `tsc --noEmit` with `checkJs`, `npm run check`, and `npm run gate`. `scripts/pack-check.mjs` rejects a tarball that leaves the allowlist, a core dependency, a size over 500 KB, `TODO` / `FIXME` / `console.log`, or a token-shaped string. CI on Node 22, 24, and 26, on `ubuntu-latest` and `ubuntu-24.04-arm`. Actions are pinned to commit SHAs (`actions/checkout` v7.0.1, `actions/setup-node` v7.1.0). The 0.0.1 prototype lives at `packages/core/src/index.js`, with its six tests and the camera demo. `cursor-kit/` is the original instruction drop. Canonical spec is `docs/SPEC.md`.

Skipped: no git remote, no `npm publish`, no npm login. `repository`, `bugs`, and `homepage` stay omitted until a GitHub remote exists. Adapters, the engine refactor, and every detector past the original four belong to later phases. Real benchmarks and fuzzing belonged to Phase 5. `lock()` in the prototype was the only uncovered code. The six original tests never call it.

Gate: `node scripts/check-name.mjs iotwarden` was CLEAR (exact npm free, HTTP 404; punctuation variants none; `@iotwarden/core` free; similar names none). `npm ci && npm run check` passed 6/6 tests. `npm run gate` passed at 99.08% lines and 86.36% branches. Pack-check: 7 files, 24906 bytes unpacked. Bench and fuzz were no-ops. GitHub `kathanp/iotwarden` was free the same day when `--github-user=kathanp` was passed. The gate command does not pass that flag. Trademark search is manual: https://tmsearch.uspto.gov/ and https://euipo.europa.eu/eSearch/

## Phase 1

Date: 2026-10-16. Package: `iotwarden@0.1.0`.

The prototype rules are plugins: `new-destination`, `fan-out`, `volume-spike`, `wrong-time`. `createEngine` feeds T0–T5 events, closes epoch-aligned windows, and emits `anomaly`, `learned`, `device-new`, and `warning`. Baseline v2, optional HMAC-SHA256, and import of the v1 prototype shape. Import validates the whole document before it changes engine state. Caps on devices, destinations, alert keys, window history, and per-window destinations. Seeded fixtures for seven device classes. Fourteen benign days of each class produce no anomalies.

Skipped: detectors past the original four. The spec lists 118; this release ships 4. Bench and fuzz stayed no-ops. No git remote and no `npm publish`.

Gate: `npm run check` passed 52/52 tests. `npm run gate` passed at 98.93% lines and 88.99% branches. Pack-check: 21 files, 83907 bytes unpacked. The demo still prints the camera hijack: new destination, wrong hour, fan-out, then the volume spike.

## Phase 2

Date: 2026-10-16. Package: `iotwarden@0.2.0`.

Thirty-two detectors on top of the original four. Flow events also feed the T0 detectors. DNS events stay on T2. Hard rules still report during learning: threat indicators, telnet/ADB/TR-069 scans, packet floods, reflection, inbound telnet or ADB, policy, ADB on 5555, SMTP bursts, TFTP to the WAN. `loadIndicators` matches IP, IPv4 CIDR, domain suffix, and JA4. The core ships no feed. Policy rules are a JSON match list. Empty means the policy detector stays quiet. Learning warnings for GRE, outbound telnet, an NXDOMAIN burst, and a burst of new registrable domains after day two. Bundled port list, ATT&CK map, and a multi-label public-suffix snapshot. `scripts/update-psl.mjs` refreshes the snapshot. `@iotwarden/adapter-conntrack` and `@iotwarden/adapter-dnsmasq` parse log lines. No runtime dependencies. Developer guide: `docs/DEVELOPERS.md`.

Skipped: the spec lists 118 detectors. This release ships 36. Proxyware, link layer, incidents, and class priors stayed for later phases. JA4 is an opaque string. The library does not compute JA4S or the other JA4+ variants. The full Public Suffix List is not vendored. Bench and fuzz stayed no-ops. No git remote and no `npm publish`.

Gate: 66/66 tests, 95.77% lines, 84.72% branches. Pack-check: core 60 files, 161236 bytes; conntrack 5 files, 13914 bytes; dnsmasq 5 files, 14111 bytes. The demo prints the camera hijack through the volume spike. Fourteen benign days of each of the seven device classes, three seeds, produce no anomaly at medium or above. The original six prototype tests still pass.

## Phase 3

Date: 2026-10-16. Package: `iotwarden@0.3.0`.

Device-class priors for `camera`, `tv-box`, `thermostat`, `hvac-controller`, `plug`, `hub`, `printer`, and `nas`. `setDeviceClass` applies them before the first event. `class-violation` can fire during learning. Incidents group anomalies on one device for 30 minutes. The score uses severity weights, a 1.5× step per extra stage, and a 6 hour half-life. `ack` halves it. Two stages, or a score of at least 70, is critical. Proxyware: `proxy-relay`, `blockchain-c2`, `supply-chain-suspect`. The rest of the 0.3 catalog: direct-to-IP, ASN and country (host lookup, no database in core), UPnP mappings, Tor indicators, LAN sweeps, brute force, slow exfil, protocol mix, connection churn, beacons, long sessions, DGA, DNS tunnels, ARP/DHCP/RA, source spoof, ICMP redirect, zones, camera streams, mining, OT on the WAN, tunnels, VPN, NTP, firmware downloads, cleartext auth posture, and post-update drift. Replay tests: a tv box relaying consumer sites from hour 0, a proxy-plus-ADB-plus-RPC incident, and a telnet scan plus a GRE flood.

Skipped: TLS, fleet comparison, OT writes, and MQTT topic checks stayed in 0.4. No ASN database, no Tor relay list, and no threat feed ship in the package. Bench and fuzz stayed no-ops. No git remote and no `npm publish`. The roadmap's IoT-23 and N-BaIoT numbers are not results from this repo.

Gate: 76/76 tests, 96.61% lines, 85.39% branches. Pack-check: core 116 files, 246065 bytes unpacked. The demo prints the camera hijack and one critical incident whose stages are c2, recon, and impact. Fourteen benign days of each of the seven device classes, three seeds, produce no anomaly at medium or above. The original six prototype tests still pass.

## Phase 4

Date: 2026-10-16. Package: `iotwarden@0.4.0`.

TLS metadata events (`tls`, `http`) and detectors for a new JA4 string, a certificate issuer change, a missing SNI, TLS on a new port, a return to cleartext, a browser fingerprint on a non-browser class, and weak TLS posture. JA4 is copied as a string. Core does not compute it. Proxy backconnect, LAN traffic that follows inbound bytes, peer-to-peer shape, outbound credential stuffing, ad-network indicators, and QUIC to a new host. Beacon interval change, DNS answer drift, and fast-flux. Building-protocol events (`app`) for a new master, a new write, a dangerous operation, a setpoint outside the learned range, write rate, recon, a second BACnet owner, and protocol errors. MQTT wildcard subscribe, a new topic prefix, publish rate, and ONVIF configuration changes. Fleet comparison: `peer-divergence` (at least five peers) and `fleet-wave` (three devices, ten minutes, `data.sameGroup`). Parsers: `@iotwarden/adapter-zeek@0.1.0` and `@iotwarden/adapter-suricata-eve@0.1.0`. Exporters: `@iotwarden/export-ocsf@0.1.0`, `@iotwarden/export-syslog@0.1.0`, `@iotwarden/export-webhook@0.1.0`. The webhook takes an injected `fetch`. Replay: a BMS hijack and a certificate-issuer change.

Skipped: detectors listed for 1.x (MUD, MAC randomization, reverse-shell shape, TTL, and others). No ASN database, no Tor list, no ad-domain list, and no threat feed. Bench and fuzz stayed no-ops. No git remote and no `npm publish`. No detection-rate number is published from this repo.

Gate: 91/91 tests, 97.06% lines, 84.99% branches. Pack-check: core 146 files, 297212 bytes unpacked. The new adapter and exporter tarballs are each 5 files and under 20 KB unpacked. The demo prints the camera hijack and one critical incident whose stages are c2, recon, and impact. Fourteen benign days of each of the seven device classes, three seeds, produce no anomaly at medium or above. The original six prototype tests still pass.
