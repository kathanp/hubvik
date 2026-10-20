# Evaluation

`eval/run.mjs` scores a labeled capture with the C6.2 protocol. The human runs datasets. This file has no detection rates.

```
node eval/run.mjs --dataset iot23 --zeek-logs <dir>
```

That writes `eval/results/iot23.json` and `eval/results/iot23.md`.

The wired joiner is IoT-23. It reads Zeek TSV `conn.log` files (`conn.log` or `conn.log.*`, including `conn.log.labeled`). `#separator`, `#fields`, and `#types` are required. `-` and `(empty)` are unset. `label` and `detailed-label` are required. Some labeled files separate `tunnel_parents`, `label`, and `detailed-label` with spaces instead of tabs; those rows are accepted. Each data row is parsed by `@iotwarden/adapter-zeek`. The engine runs with tier T1 only. Outbound rows (`local_orig` T, or that column absent) use `id.orig_h` as the device. Inbound rows (`local_orig` F and `local_resp` T) use `id.resp_h`. That choice is per row in the capture. `label` other than `benign` is malicious. Attack intervals are contiguous Malicious runs per (device, detailed-label), merged when the gap is under 5 minutes. A gap of 5 minutes or more is another instance: 2 minutes apart is one instance, 10 minutes apart is two. A device learns on the benign prefix before its first malicious event, for 24 h when the capture has it, and the actual span is written next to the result when it does not. Every results file header states that learning span and the malicious-label share inside the learning prefix. The header says POISONED PREFIX when that share is above zero. Next to the C6.2 detection rate, strict detection counts only anomalies whose stage or category is listed for that label in `eval/label-map.json`. `UdpFlood` maps to impact or volume. A label with no row prints `unmapped`. Both rates print a 95% Wilson interval when a rate is printed. Every IoT-23 results file states: T1 only (conn.log). DNS, TLS, link-layer and app detectors not exercised. Dataset files stay in `eval/data/` and are not committed.

N-BaIoT is not scored. It has no flows.

IEEE DataPort joiner: UNVERIFIED: written from documentation, not run on real data. It does not read the 42 PCAPs. Extract each PCAP into a directory named with that PCAP's category (`Benign` for benign traffic). Put Zeek `conn.log` there when you have it. Put the host ARP and DHCP extraction in `arp.tsv` and `dhcp.tsv` (Zeek TSV). `arp.tsv` fields are `ts`, `ip`, `mac`, `op`, and optional `device`. `dhcp.tsv` fields are `ts`, `mac`, `msg`, and optional `device`, `server_ip`, `requested_ip`.

```
node eval/run.mjs --dataset ieee-dataport --zeek-logs <dir>
```

The engine runs tiers T1 and T4.

CICIoMT2024 joiner: UNVERIFIED: written from documentation, not run on real data. It does not read PCAPs. Convert one PCAP, then move `conn.log`, `dns.log`, `ssl.log`, `http.log`, `mqtt_connect.log`, `mqtt_subscribe.log`, and `mqtt_publish.log` into a directory named with that PCAP's attack category (`Benign` for benign traffic). Each MQTT row uses `id.orig_h` as the device.

```
node eval/run.mjs --dataset ciciomt2024 --zeek-logs <dir>
```

The engine runs tiers T1, T2, and T5.

## Measured results

These lines are copied from the result files. They are not a C6.3 pass. The malware capture's false-positive rate is above the gate.

From `eval/results/iot23-malware/iot23.md`:

- Detection: n too small (17 detected, 17 attack instances)
- Strict detection: 9/17 = 52.9% (95% Wilson 31.0%–73.8%)
- False positives: 314 anomalies at medium or above, 72.7037175925926 benign device-days, 4.31889881834587 per benign device-day.
- Benign intervals with a false positive: 308/876 = 35.2% (95% Wilson 32.1%–38.4%)

From `eval/results/iot23-honeypot/iot23.md`:

- Detection: no rate
- Strict detection: no rate
- False positives: 0 anomalies at medium or above, 0 benign device-days, no rate (0 device-days).
- Benign intervals with a false positive: no rate

CICIoT2023 joiner: UNVERIFIED: written from documentation, not run on real data. It does not read PCAPs. Convert one PCAP, then move `conn.log`, `dns.log`, and `ssl.log` into a directory named with that PCAP's attack category (`Benign` for benign traffic):

```
zeek -C -r capture.pcap
node eval/run.mjs --dataset ciciot2023 --zeek-logs <dir>
```

`<dir>` is the parent of those category directories. The engine runs tiers T1, T2, and T3.

The evasion suite in `eval/evasion/` is synthetic. Each attack uses only a port, a protocol, and a destination /24 the victim learned: a slow scan at one host per window on ports 80 and 443, a beacon with 40% jitter to the learned host, exfiltration at 0.9 × the `slow-exfil` limit to that host, and a one-way UDP flood split across 10 hosts in that /24. The report lists what fired. Thresholds are not tuned against it.
