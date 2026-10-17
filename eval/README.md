# Evaluation

`eval/run.mjs` scores a labeled capture with the C6.2 protocol. The human runs datasets. This file has no detection rates.

```
node eval/run.mjs --dataset iot23 --zeek-logs <dir>
```

That writes `eval/results/iot23.json` and `eval/results/iot23.md`.

The wired joiner is IoT-23. It reads Zeek TSV `conn.log` files (`conn.log` or `conn.log.*`, including `conn.log.labeled`) and requires `label` and `detailed-label`. Each data row is parsed by `@iotwarden/adapter-zeek`. The engine runs with tier T1 only. `label` other than `benign` is malicious. An attack instance is a run of one `detailed-label` on one device; a gap above 5 minutes starts another instance. A device learns on the benign prefix before its first malicious event, for 24 h when the capture has it, and the actual span is written next to the result when it does not. Dataset files stay in `eval/data/` and are not committed.

N-BaIoT is not scored. It has no flows. CICIoT2023, the IEEE DataPort ARP set, and CICIoMT2024 do not have a joiner yet.

The evasion suite in `eval/evasion/` is synthetic: a slow scan at one host per window, a beacon with 40% jitter, exfiltration at 0.9 × the `slow-exfil` limit, and a flood split across 10 destinations. The report lists what fired. Thresholds are not tuned against it.
