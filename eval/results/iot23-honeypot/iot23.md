# iot23

Attack intervals: contiguous Malicious runs per (device, detailed-label), merged when the gap is under 5 minutes.

T1 only (conn.log). DNS, TLS, link-layer and app detectors not exercised.

Learning span: 0.0.0.0 19517353 ms; 192.168.2.1 19524637 ms; fe80::80e6:50ff:fe12:1464 19453751 ms; 169.254.15.115 19453750 ms; 192.168.2.3 17851657 ms; fe80::4eef:c0ff:fe27:561e 6510830 ms; :: 18884509 ms; fe80::482:6d20:b3e:adf4 125676 ms; 192.168.69.192 124241 ms; fe80::82e6:50ff:fe21:867c 948 ms; 192.168.69.129 125441 ms; fe80::1060:27a7:f64c:dec9 124931 ms; fe80::1847:a1bd:8d13:f43c 120630 ms; 192.168.69.73 122675 ms; fe80::ad:a9ad:1b82:2e67 71271 ms; fe80::14c5:8f26:563a:f0cb 63977 ms; 192.168.69.17 0 ms; 192.168.69.136 67862 ms; fe80::106c:9e5b:3af8:9cf 59188 ms; 192.168.69.200 58473 ms; fe80::183b:7564:dbcc:3eca 31948 ms; 192.168.69.178 26727 ms; 192.168.69.241 0 ms; fe80::1c5c:213d:7cf8:890 921 ms.

Malicious-label share inside the learning prefix: 0/1374.

Tiers: T1.

Learning: 0.0.0.0 learned 19517353 ms (under 24 h); 192.168.2.1 learned 19524637 ms (under 24 h); fe80::80e6:50ff:fe12:1464 learned 19453751 ms (under 24 h); 169.254.15.115 learned 19453750 ms (under 24 h); 192.168.2.3 learned 17851657 ms (under 24 h); fe80::4eef:c0ff:fe27:561e learned 6510830 ms (under 24 h); :: learned 18884509 ms (under 24 h); fe80::482:6d20:b3e:adf4 learned 125676 ms (under 24 h); 192.168.69.192 learned 124241 ms (under 24 h); fe80::82e6:50ff:fe21:867c learned 948 ms (under 24 h); 192.168.69.129 learned 125441 ms (under 24 h); fe80::1060:27a7:f64c:dec9 learned 124931 ms (under 24 h); fe80::1847:a1bd:8d13:f43c learned 120630 ms (under 24 h); 192.168.69.73 learned 122675 ms (under 24 h); fe80::ad:a9ad:1b82:2e67 learned 71271 ms (under 24 h); fe80::14c5:8f26:563a:f0cb learned 63977 ms (under 24 h); 192.168.69.17 learned 0 ms (under 24 h); 192.168.69.136 learned 67862 ms (under 24 h); fe80::106c:9e5b:3af8:9cf learned 59188 ms (under 24 h); 192.168.69.200 learned 58473 ms (under 24 h); fe80::183b:7564:dbcc:3eca learned 31948 ms (under 24 h); 192.168.69.178 learned 26727 ms (under 24 h); 192.168.69.241 learned 0 ms (under 24 h); fe80::1c5c:213d:7cf8:890 learned 921 ms (under 24 h).

Detection: no rate

Strict detection: no rate

False positives: 0 anomalies at medium or above, 0 benign device-days, no rate (0 device-days).

Benign intervals with a false positive: no rate

## By type

None.

## Hits

None.

## Misses

None.

## Ablation

- new-port: 0 unique detections, 0 false positives, zero unique
- new-protocol: 0 unique detections, 0 false positives, zero unique
- horizontal-scan: 0 unique detections, 0 false positives, zero unique
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
- tor-or-proxy: 0 unique detections, 0 false positives, zero unique
- lan-sweep: 0 unique detections, 0 false positives, zero unique
- brute-force-out: 0 unique detections, 0 false positives, zero unique
- brute-force-in: 0 unique detections, 0 false positives, zero unique
- slow-exfil: 0 unique detections, 0 false positives, zero unique
- protocol-mix-shift: 0 unique detections, 0 false positives, zero unique
- connection-churn: 0 unique detections, 0 false positives, zero unique
- new-beacon: 0 unique detections, 0 false positives, zero unique
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
- beacon-change: 0 unique detections, 0 false positives, zero unique

## Not exercised

- new-destination
- new-domain-family
- fan-out
- volume-spike
- volume-spike-hourly
- wrong-time
- went-silent
- tier-silent
- nxdomain-burst
- resolver-bypass
- dns-rebinding
- private-answer-for-public-name
- threat-intel-match
- new-device
- policy-violation
- input-gap
- clock-jump
- state-cap
- alert-storm
- class-violation
- supply-chain-suspect
- proxy-sdk-traffic
- blockchain-c2
- direct-ip
- upnp-port-open
- dga
- dns-tunnel
- arp-spoof
- gratuitous-arp-flood
- rogue-dhcp
- identity-change
- dhcp-starvation
- rogue-ra
- tunnel-service
- post-update-drift
- new-client-fingerprint
- cert-change
- sni-missing
- tls-on-odd-port
- browser-mimic
- posture-weak-tls
- ad-fraud
- answer-drift
- fast-flux
- ot-new-master
- ot-write-new
- ot-dangerous-op
- ot-value-out-of-range
- ot-write-rate
- ot-recon
- ot-spoof
- ot-error-burst
- mqtt-wildcard-subscribe
- mqtt-topic-new
- mqtt-publish-rate
- onvif-config-change
- peer-divergence
- fleet-wave

## Proposals

None. The human decides any later change.

## Evasion

Synthetic known blind spots. Thresholds were not tuned against this suite.

- slow-scan: no medium-or-above anomaly (none)
- beacon-jitter-40: no medium-or-above anomaly (none)
- exfil-0.9-limit: no medium-or-above anomaly (none)
- flood-10-destinations: fired (egress-flood, dispersed-flood)
