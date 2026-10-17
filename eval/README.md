# Evaluation

`eval/run.mjs` scores a labeled capture with the C6.2 protocol. The human runs datasets. This file has no detection rates.

```
node eval/run.mjs --dataset iot23 --zeek-logs <dir>
```

That writes `eval/results/iot23.json` and `eval/results/iot23.md`.

The wired joiner is IoT-23. It reads Zeek TSV `conn.log` files (`conn.log` or `conn.log.*`, including `conn.log.labeled`). `#separator`, `#fields`, and `#types` are required. `-` and `(empty)` are unset. `label` and `detailed-label` are required. Some labeled files separate `tunnel_parents`, `label`, and `detailed-label` with spaces instead of tabs; those rows are accepted. Each data row is parsed by `@iotwarden/adapter-zeek`. The engine runs with tier T1 only. Outbound rows (`local_orig` T, or that column absent) use `id.orig_h` as the device. Inbound rows (`local_orig` F and `local_resp` T) use `id.resp_h`. That choice is per row in the capture. `label` other than `benign` is malicious. Attack intervals are contiguous Malicious runs per (device, detailed-label), merged when the gap is under 5 minutes. A gap of 5 minutes or more is another instance: 2 minutes apart is one instance, 10 minutes apart is two. A device learns on the benign prefix before its first malicious event, for 24 h when the capture has it, and the actual span is written next to the result when it does not. Every results file header states that learning span and the malicious-label share inside the learning prefix. The header says POISONED PREFIX when that share is above zero. Next to the C6.2 detection rate, strict detection counts only anomalies whose stage or category is listed for that label in `eval/label-map.json`. A label with no row prints `unmapped`. Both rates print a 95% Wilson interval when a rate is printed. Every IoT-23 results file states: T1 only (conn.log). DNS, TLS, link-layer and app detectors not exercised. Dataset files stay in `eval/data/` and are not committed.

N-BaIoT is not scored. It has no flows. The IEEE DataPort ARP set and CICIoMT2024 do not have a joiner yet.

CICIoT2023 joiner: UNVERIFIED: written from documentation, not run on real data. It does not read PCAPs. Convert one PCAP, then move `conn.log`, `dns.log`, and `ssl.log` into a directory named with that PCAP's attack category (`Benign` for benign traffic):

```
zeek -C -r capture.pcap
node eval/run.mjs --dataset ciciot2023 --zeek-logs <dir>
```

`<dir>` is the parent of those category directories. The engine runs tiers T1, T2, and T3.

The evasion suite in `eval/evasion/` is synthetic. Each attack uses only a port, a protocol, and a destination /24 the victim learned: a slow scan at one host per window on ports 80 and 443, a beacon with 40% jitter to the learned host, exfiltration at 0.9 × the `slow-exfil` limit to that host, and a one-way UDP flood split across 10 hosts in that /24. The report lists what fired. Thresholds are not tuned against it.
