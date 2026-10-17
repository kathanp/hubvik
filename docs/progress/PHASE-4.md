# Phase 4

Date: 2026-10-16. Package: `iotwarden@0.4.0`.

## What was built

- TLS metadata events (`tls`, `http`) and detectors for a new JA4 string, a certificate issuer change, a missing SNI, TLS on a new port, a return to cleartext, a browser fingerprint on a non-browser class, and weak TLS posture. JA4 is copied as a string. Core does not compute it.
- Proxy backconnect, LAN traffic that follows inbound bytes, peer-to-peer shape, outbound credential stuffing, ad-network indicators, and QUIC to a new host.
- Beacon interval change, DNS answer drift, and fast-flux.
- Building-protocol events (`app`) for a new master, a new write, a dangerous operation, a setpoint outside the learned range, write rate, recon, a second BACnet owner, and protocol errors.
- MQTT wildcard subscribe, a new topic prefix, publish rate, and ONVIF configuration changes.
- Fleet comparison: `peer-divergence` (at least five peers) and `fleet-wave` (three devices, ten minutes, `data.sameGroup`).
- Parsers: `@iotwarden/adapter-zeek@0.1.0` and `@iotwarden/adapter-suricata-eve@0.1.0`.
- Exporters: `@iotwarden/export-ocsf@0.1.0`, `@iotwarden/export-syslog@0.1.0`, `@iotwarden/export-webhook@0.1.0`. The webhook takes an injected `fetch`.
- Replay: a BMS hijack and a certificate-issuer change.

## What was skipped, and why

- The spec still lists detectors for 1.x (MUD, DHCP identity, MAC randomization, reverse-shell shape, TTL, and others). Those stay out until there is a real-traffic evaluation.
- No ASN database, no Tor list, no ad-domain list, and no threat feed ship in the package.
- `bench` and `fuzz` stay no-ops until Phase 5.
- No git remote and no `npm publish`. Not validated on real traffic. No detection-rate number is published from this repo.

## Gate

`npm run gate` passed: 91/91 tests, 97.06% lines, 84.99% branches. Thresholds are 90% lines and 80% branches.

`npm run pack:check`: `packages/core` is 146 files, 297212 bytes unpacked. The new adapter and exporter tarballs are each 5 files and under 20 KB unpacked.

`npm run demo` prints the camera hijack and one critical incident whose stages are c2, recon, and impact.

Fourteen benign days of each of the seven device classes, three seeds, produce no anomaly at medium or above. The original six prototype tests still pass.
