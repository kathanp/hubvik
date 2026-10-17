# Phase 2

Date: 2026-10-16. Package: `iotwarden@0.2.0`.

## What was built

- Thirty-two detectors on top of the original four. Flow events also feed the T0 detectors. DNS events stay on T2.
- Hard rules still report during learning: threat indicators, telnet/ADB/TR-069 scans, packet floods, reflection, inbound telnet or ADB, policy, ADB on 5555, SMTP bursts, TFTP to the WAN.
- `loadIndicators` matches IP, IPv4 CIDR, domain suffix, and JA4. The core ships no feed.
- Policy rules are a JSON match list. Empty means the policy detector stays quiet.
- Learning warnings for GRE, outbound telnet, an NXDOMAIN burst, and a burst of new registrable domains after day two.
- Bundled port list, ATT&CK map, and a multi-label public-suffix snapshot. `scripts/update-psl.mjs` refreshes the snapshot.
- `@iotwarden/adapter-conntrack` and `@iotwarden/adapter-dnsmasq` parse log lines. No runtime dependencies.
- Developer guide: `docs/DEVELOPERS.md`. Shipped tunables: `docs/SPEC.md`, "Defaults shipped in 0.2".

## What was skipped, and why

- The spec lists 118 detectors. This release ships 36. Proxyware, link layer, incidents, and class priors stay in later phases.
- JA4 is an opaque string. The library does not compute JA4S or the other JA4+ variants.
- The full Public Suffix List is not vendored. The snapshot is multi-label suffixes only, so the tarball stays under 500 KB.
- `bench` and `fuzz` stay no-ops until Phase 5.
- No git remote and no `npm publish`.

## Gate

`npm run gate` passed: 66/66 tests, 95.77% lines, 84.72% branches. Thresholds are 90% lines and 80% branches.

`npm run pack:check`:

- `packages/core`: 60 files, 161236 bytes unpacked
- `packages/adapter-conntrack`: 5 files, 13914 bytes unpacked
- `packages/adapter-dnsmasq`: 5 files, 14111 bytes unpacked

`npm run demo` still prints the camera hijack: new host, new registrable domain, 3 a.m. activity, a missed active day, the scan, then the volume spike (window and hour).

Fourteen benign days of each of the seven device classes, three seeds, produce no anomaly at medium or above. The original six prototype tests still pass.

Not validated on real traffic.
