# Phase 3

Date: 2026-10-16. Package: `iotwarden@0.3.0`.

## What was built

- Device-class priors for `camera`, `tv-box`, `thermostat`, `hvac-controller`, `plug`, `hub`, `printer`, and `nas`. `setDeviceClass` applies them before the first event. `class-violation` can fire during learning.
- Incidents group anomalies on one device for 30 minutes. The score uses severity weights, a 1.5× step per extra stage, and a 6 hour half-life. `ack` halves it. Two stages, or a score of at least 70, is critical.
- Proxyware: `proxy-relay`, `blockchain-c2`, `supply-chain-suspect`.
- The rest of the 0.3 catalog: direct-to-IP, ASN and country (host lookup, no database in core), UPnP mappings, Tor indicators, LAN sweeps, brute force, slow exfil, protocol mix, connection churn, beacons, long sessions, DGA, DNS tunnels, ARP/DHCP/RA, source spoof, ICMP redirect, zones, camera streams, mining, OT on the WAN, tunnels, VPN, NTP, firmware downloads, cleartext auth posture, and post-update drift.
- Replay tests: a tv box relaying consumer sites from hour 0, a proxy-plus-ADB-plus-RPC incident, and a telnet scan plus a GRE flood.

## What was skipped, and why

- The spec lists 118 detectors. This release adds the 0.3 set on top of the 36 from 0.2. TLS, fleet comparison, OT writes, and MQTT topic checks stay in 0.4.
- No ASN database, no Tor relay list, and no threat feed ship in the package. The host passes `lookup` and indicators.
- `bench` and `fuzz` stay no-ops until Phase 5.
- No git remote and no `npm publish`. Not validated on real traffic. The roadmap's IoT-23 and N-BaIoT numbers are not results from this repo.

## Gate

`npm run gate` passed: 76/76 tests, 96.61% lines, 85.39% branches. Thresholds are 90% lines and 80% branches.

`npm run pack:check`: `packages/core` is 116 files, 246065 bytes unpacked.

`npm run demo` prints the camera hijack and one critical incident whose stages are c2, recon, and impact.

Fourteen benign days of each of the seven device classes, three seeds, produce no anomaly at medium or above. The original six prototype tests still pass.
