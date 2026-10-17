# iot23

Attack intervals: contiguous Malicious runs per (device, detailed-label), merged when the gap is under 5 minutes.

T1 only (conn.log). DNS, TLS, link-layer and app detectors not exercised.

Tiers: T1.

Learning: Every device learned at least 24 h.

Detection: 20/25 = 80.0% (95% Wilson 60.9%–91.1%)

False positives: 0 anomalies at medium or above, 3 benign device-days, 0 per benign device-day.

Benign intervals with a false positive: n too small (0 detected, 5 benign intervals)

## By type

- HorizontalScan: n too small (7 detected, 7 attack instances)
- SlowVerticalScan: n too small (1 detected, 6 attack instances)
- C2Beacon: n too small (6 detected, 6 attack instances)
- UdpFlood: n too small (6 detected, 6 attack instances)

## Hits

- 10.0.0.1 HorizontalScan at 172800000–172800000, time to detect 0 ms, detectors horizontal-scan
- 10.0.0.1 HorizontalScan at 173400000–173400000, time to detect 0 ms, detectors horizontal-scan
- 10.0.0.1 HorizontalScan at 174000000–174000000, time to detect 0 ms, detectors horizontal-scan
- 10.0.0.1 HorizontalScan at 174600000–174600000, time to detect 0 ms, detectors horizontal-scan
- 10.0.0.1 HorizontalScan at 175200000–175200000, time to detect 0 ms, detectors horizontal-scan
- 10.0.0.1 HorizontalScan at 175800000–175800000, time to detect 0 ms, detectors horizontal-scan
- 10.0.0.2 SlowVerticalScan at 174600000–174600000, time to detect 0 ms, detectors beacon-change
- 10.0.0.3 C2Beacon at 172800000–173940000, time to detect 1140000 ms, detectors new-beacon
- 10.0.0.3 C2Beacon at 174540000–175680000, time to detect 1140000 ms, detectors new-beacon
- 10.0.0.3 C2Beacon at 176280000–177420000, time to detect 1140000 ms, detectors new-beacon
- 10.0.0.3 C2Beacon at 178020000–179160000, time to detect 1140000 ms, detectors new-beacon
- 10.0.0.3 C2Beacon at 179760000–180900000, time to detect 1140000 ms, detectors new-beacon
- 10.0.0.3 C2Beacon at 181500000–182640000, time to detect 1140000 ms, detectors new-beacon
- 10.0.0.4 UdpFlood at 172800000–172800000, time to detect 0 ms, detectors new-protocol, packet-flood, protocol-mix-shift
- 10.0.0.4 UdpFlood at 173400000–173400000, time to detect 0 ms, detectors packet-flood, protocol-mix-shift
- 10.0.0.4 UdpFlood at 174000000–174000000, time to detect 0 ms, detectors packet-flood, protocol-mix-shift
- 10.0.0.4 UdpFlood at 174600000–174600000, time to detect 0 ms, detectors packet-flood, protocol-mix-shift
- 10.0.0.4 UdpFlood at 175200000–175200000, time to detect 0 ms, detectors packet-flood, protocol-mix-shift
- 10.0.0.4 UdpFlood at 175800000–175800000, time to detect 0 ms, detectors packet-flood, protocol-mix-shift
- 10.0.0.5 HorizontalScan at 172800000–172800000, time to detect 0 ms, detectors horizontal-scan

## Misses

- 10.0.0.2 SlowVerticalScan at 172800000–172800000 (1 flows)
- 10.0.0.2 SlowVerticalScan at 173400000–173400000 (1 flows)
- 10.0.0.2 SlowVerticalScan at 174000000–174000000 (1 flows)
- 10.0.0.2 SlowVerticalScan at 175200000–175200000 (1 flows)
- 10.0.0.2 SlowVerticalScan at 175800000–175800000 (1 flows)

## Ablation

- new-port: 0 unique detections, 0 false positives, zero unique
- new-protocol: 0 unique detections, 0 false positives, zero unique
- horizontal-scan: 7 unique detections, 0 false positives
- vertical-scan: 0 unique detections, 0 false positives, zero unique
- failed-connection-ratio: 0 unique detections, 0 false positives, zero unique
- lan-lateral: 0 unique detections, 0 false positives, zero unique
- upload-ratio-shift: 0 unique detections, 0 false positives, zero unique
- packet-flood: 0 unique detections, 0 false positives, zero unique
- egress-flood: 0 unique detections, 0 false positives, zero unique
- reflection-participation: 0 unique detections, 0 false positives, zero unique
- coap-amplification: 0 unique detections, 0 false positives, zero unique
- bogon-destination: 0 unique detections, 0 false positives, zero unique
- inbound-from-wan: 0 unique detections, 0 false positives, zero unique
- adb-exposure: 0 unique detections, 0 false positives, zero unique
- mqtt-new-broker: 0 unique detections, 0 false positives, zero unique
- spam-relay: 0 unique detections, 0 false positives, zero unique
- tftp-activity: 0 unique detections, 0 false positives, zero unique
- posture-listening-risky: 0 unique detections, 0 false positives, zero unique
- posture-wan-exposed: 0 unique detections, 0 false positives, zero unique
- proxy-relay: 0 unique detections, 0 false positives, zero unique
- new-asn: 0 unique detections, 0 false positives, zero unique
- new-country: 0 unique detections, 0 false positives, zero unique
- upnp-port-open: 0 unique detections, 0 false positives, zero unique
- tor-or-proxy: 0 unique detections, 0 false positives, zero unique
- lan-sweep: 0 unique detections, 0 false positives, zero unique
- brute-force-out: 0 unique detections, 0 false positives, zero unique
- brute-force-in: 0 unique detections, 0 false positives, zero unique
- slow-exfil: 0 unique detections, 0 false positives, zero unique
- protocol-mix-shift: 0 unique detections, 0 false positives, zero unique
- connection-churn: 0 unique detections, 0 false positives, zero unique
- new-beacon: 6 unique detections, 0 false positives
- long-connection: 0 unique detections, 0 false positives, zero unique
- src-spoof: 0 unique detections, 0 false positives, zero unique
- icmp-redirect: 0 unique detections, 0 false positives, zero unique
- zone-violation: 0 unique detections, 0 false positives, zero unique
- stream-to-new-destination: 0 unique detections, 0 false positives, zero unique
- cryptomining: 0 unique detections, 0 false positives, zero unique
- ot-wan-exposure: 0 unique detections, 0 false positives, zero unique
- vpn-protocol: 0 unique detections, 0 false positives, zero unique
- icmp-tunnel: 0 unique detections, 0 false positives, zero unique
- ipv6-tunnel: 0 unique detections, 0 false positives, zero unique
- ntp-rogue: 0 unique detections, 0 false positives, zero unique
- update-from-new-source: 0 unique detections, 0 false positives, zero unique
- update-over-cleartext: 0 unique detections, 0 false positives, zero unique
- posture-cleartext-auth: 0 unique detections, 0 false positives, zero unique
- cleartext-regression: 0 unique detections, 0 false positives, zero unique
- proxy-backconnect: 0 unique detections, 0 false positives, zero unique
- lan-via-proxy: 0 unique detections, 0 false positives, zero unique
- p2p-pattern: 0 unique detections, 0 false positives, zero unique
- credential-stuffing-out: 0 unique detections, 0 false positives, zero unique
- quic-new: 0 unique detections, 0 false positives, zero unique
- beacon-change: 1 unique detections, 0 false positives

## Proposals

None. The human decides any later change.

## Evasion

Synthetic known blind spots. Thresholds were not tuned against this suite.

- slow-scan: fired (new-port)
- beacon-jitter-40: fired (new-beacon)
- exfil-0.9-limit: no medium-or-above anomaly (none)
- flood-10-destinations: fired (new-port, egress-flood, stream-to-new-destination)
