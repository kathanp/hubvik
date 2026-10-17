# WP-1

Date: 2026-10-17. Package: `iotwarden@0.4.0`. Spec 3.0.

## What was built

- `packages/core/test/benign-matrix-tiers.test.js`: tiers T0–T5, every profile including `smart-tv`, 14 days × seeds 1, 2, and 3, `setDeviceClass` set to the profile id. Assertion: no anomaly at medium or above. The test prints `low/info anomalies: none`.
- `simulate({ rich: true })` emits the same schedule as the T0 summaries, as flow, DNS, TLS, DHCP, and ARP events. Thermostat profiles also emit MQTT publishes. HVAC profiles also emit BACnet reads and scheduled writes. The default `simulate()` path is unchanged.
- Ordinary noise in the rich stream: DHCP moves the lease from `192.0.2.10` to `192.0.2.11` on day 2, DNS A answers alternate `1.2.3.10` and `1.2.3.11`, NTP goes to `1.1.1.1` and `9.9.9.9` every day, and one 30 MB firmware download arrives on day 1.
- `smart-tv` profile and `src/data/classes/smart-tv.json` so `setDeviceClass` accepts the class. Upload cap is 50000000 bytes/hour, copied from `tv-box`, because B20 does not state one (Q-5). `browser-mimic` was not changed.

## Logic change

`answer-drift` used to replace a name's learned keys with the latest lookup. CDN rotation then looked like a new answer after learning. Learning now keeps the union, up to 8 keys. A key that was never seen while learning still alerts. No numeric default moved.

## Thresholds

No detector threshold, default, or severity changed. No detector was disabled.

| Item                               | Before                         | After                                    | Reason                                                                                                   |
| ---------------------------------- | ------------------------------ | ---------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `answer-drift` learned keys        | latest lookup replaces the set | union of keys seen while learning, cap 8 | WP-1 requires CDN rotation inside one name to stay quiet. This is the learned-set rule, not a threshold. |
| `smart-tv` `maxFamilies`           | class did not exist            | 120                                      | B20.                                                                                                     |
| `smart-tv` `maxUploadBytesPerHour` | class did not exist            | 50000000                                 | Same number as `tv-box`. B20 does not give an upload cap. Open as Q-5.                                   |
| `smart-tv` `allowsInboundLan`      | class did not exist            | false                                    | B20.                                                                                                     |

## Gate

`npm run gate` passed: 93/93 tests, 97.39% lines, 85.78% branches.

`npm run pack:check`: `packages/core` is 147 files, 306113 bytes unpacked.

`spec-coverage`: 122 rows, 105 detector files, core 0.4.0. Pending Rel 0.5 rows: `identity-change`, `tier-silent`, `egress-flood`, `proxy-sdk-traffic`.

The all-tier test printed `low/info anomalies: none`.

`npm run demo` prints the camera hijack and one critical incident whose stages are c2, recon, and impact.
