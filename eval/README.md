# Evaluation

`eval/run.mjs` scores a labeled capture with the C6.2 protocol. The human runs datasets. This file has no detection rates.

```
node eval/run.mjs --dataset iot23 --zeek-logs <dir>
```

That writes `eval/results/iot23.json` and `eval/results/iot23.md`.

The wired joiner is IoT-23. It reads Zeek TSV `conn.log` files (`conn.log` or `conn.log.*`, including `conn.log.labeled`). `#separator`, `#fields`, and `#types` are required. `-` and `(empty)` are unset. `label` and `detailed-label` are required. Some labeled files separate `tunnel_parents`, `label`, and `detailed-label` with spaces instead of tabs; those rows are accepted. Each data row is parsed by `@iotwarden/adapter-zeek`. The engine runs with tier T1 only. Outbound rows (`local_orig` T, or that column absent) use `id.orig_h` as the device. Inbound rows (`local_orig` F and `local_resp` T) use `id.resp_h`. That choice is per row in the capture. `label` other than `benign` is malicious. Attack intervals are contiguous Malicious runs per (device, detailed-label), merged when the gap is under 5 minutes. A gap of 5 minutes or more is another instance: 2 minutes apart is one instance, 10 minutes apart is two. A device learns on the benign prefix before its first malicious event, for 24 h when the capture has it, and the actual span is written next to the result when it does not. Every IoT-23 results file states: T1 only (conn.log). DNS, TLS, link-layer and app detectors not exercised. Dataset files stay in `eval/data/` and are not committed.

N-BaIoT is not scored. It has no flows. CICIoT2023, the IEEE DataPort ARP set, and CICIoMT2024 do not have a joiner yet.

The evasion suite in `eval/evasion/` is synthetic: a slow scan at one host per window, a beacon with 40% jitter, exfiltration at 0.9 × the `slow-exfil` limit, and a flood split across 10 destinations. The report lists what fired. Thresholds are not tuned against it.
