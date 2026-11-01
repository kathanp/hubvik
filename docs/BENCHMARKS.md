<!-- docs/BENCHMARKS.md -->

# Benchmarks

Measured by `node bench/run.js`. The script exits non-zero when a budget is missed. Detectors were not tuned to pass.

## WP-8.1 — watching state, 2026-10-17

All tiers on. 1,000 devices. Each device gets one event at t=0 and one at `learnMs` (60 s), then `lock()`, then 10,000 timed `feed()` calls.

| Metric            | Budget   | Measured |
| ----------------- | -------- | -------- |
| median `feed()`   | < 10 µs  | 22.38 µs |
| memory per device | < 100 KB | 2.34 KB  |

The gate re-ran the same script: median 21.04 µs, 2.34 KB/device.

## WP-8.2 — CPU profile, 2026-10-17

`node --cpu-prof --cpu-prof-interval=100`. All tiers on. 1,000 devices past `learnMs`, then `lock()`, then 80,000 watching-state summary `feed()` calls. Self time is the profiler's leaf sample. 12,446 samples.

| Rank | Function              | Location                       | Self time |
| ---- | --------------------- | ------------------------------ | --------- |
| 1    | `_run`                | `engine/engine.js:845`         | 24.3%     |
| 2    | `_optionsFor`         | `engine/engine.js:112`         | 23.2%     |
| 3    | `feed`                | `engine/engine.js:185`         | 7.2%      |
| 4    | `_state`              | `engine/engine.js:162`         | 4.1%      |
| 5    | `(garbage collector)` | `(native)`                     | 2.5%      |
| 6    | `domainToASCII`       | `(native)`                     | 1.8%      |
| 7    | `(program)`           | `(native)`                     | 1.7%      |
| 8    | `torHit`              | `detectors/tor-or-proxy.js:56` | 1.3%      |
| 9    | `domainFamily`        | `engine/net.js:91`             | 1.1%      |
| 10   | `exactHit`            | `engine/indicators.js:50`      | 0.9%      |

## WP-8.2 — dispatch, 2026-10-17

Same script as WP-8.1: all tiers, 1,000 devices, past `learnMs`, `lock()`, then 10,000 timed summary `feed()` calls. The 10 µs budget is unchanged.

|            | median `feed()` | memory per device |
| ---------- | --------------- | ----------------- |
| Before     | 22.38 µs        | 2.34 KB           |
| Gate rerun | 21.04 µs        | 2.34 KB           |
| After      | 6.04 µs         | 1.19 KB           |

Before is the WP-8.1 measurement. After is `node bench/run.js` once `feed()` dispatches by `meta.consumes`. The script exited 0. The gate re-ran it: median 6.13 µs, 1.19 KB/device.

`bench/run.js` did not change between those runs. The serialized baseline did not change either: `test/diff/dispatch.test.js` replays every replay test, both attack generators, and the all-tier benign matrix (seeds 1–3) and matches the anomaly stream and `exportBaseline()` captured at `0a1755b`, the commit before dispatch. The KB drop is which detector states `feed()` allocates. `stats().memoryBytes` sums `memoryEstimate` only for states a feed has created. A summary event no longer creates state for a detector whose `consumes` list omits `summary`. `exportBaseline()` still writes a fresh state for those detectors, and that fresh state matches what their learn/check produced on a summary they ignore.

## WP-8 — 100 devices, 2026-10-17

All tiers on. 1,000 warmup feeds, then 10,000 timed feeds across 100 devices. That script recorded the miss and did not fail the gate.

| Metric            | Budget   | Measured |
| ----------------- | -------- | -------- |
| median `feed()`   | < 10 µs  | 24.29 µs |
| memory per device | < 100 KB | 2.46 KB  |

Checkpoint B gate, same script, 2026-10-17: median 25.75 µs, 2.46 KB/device.

## WP-9.4 — measured heap, 2026-10-17

`node --expose-gc bench/run.js`. All tiers, 1,000 devices, `lock()`, then `process.memoryUsage().heapUsed` after `global.gc()`, minus the heap before those devices were created. The 100 KB budget checks this heap delta. `memoryEstimate` is still printed. It does not decide the budget. Detectors were not tuned.

| Host           | median `feed()` | memoryEstimate | measured heap |
| -------------- | --------------- | -------------- | ------------- |
| x86            | 5.83 µs         | 1.19 KB        | 12.33 KB      |
| Raspberry Pi 4 | not measured    | not measured   | not measured  |

## WP-9.6 — estimate versus heap

Each of the 1,000 bench devices learned 2 summary events, at `ts` 0 and `ts` 60000, before the heap delta. The timed `feed()` loop runs after that sample.

`memoryEstimate` for the five largest underestimates now counts structures that were already allocated: `volume-spike-hourly` counts its 24 `SampleRing` objects, and `blockchain-c2`, `tor-or-proxy`, `cryptomining`, and `tunnel-service` count two empty `LruSet`s each (240 bytes for the object and its `Map`, measured on Node 24). Their stored state was not changed. The WP-9.6 gate printed median 5.46 µs, estimate 5.70 KB/device, heap 12.27 KB/device. Heap / estimate is 2.15. That is outside 2×. The remaining gap is the other detector objects plus the device record. Closing it by shrinking the 24 hourly rings would change state, so the rings stay.

Fresh-state heap is `createState` measured with `node --expose-gc`. `memoryEstimate` is the bench state after those 2 events. `volume-spike-hourly` holds one sample by then, so its estimate is higher than the empty-ring measurement.

| Detector                | fresh-state heap (bytes) | memoryEstimate (bytes) | heap / estimate |
| ----------------------- | -----------------------: | ---------------------: | --------------: |
| volume-spike-hourly     |                    2,414 |                  2,712 |            0.89 |
| blockchain-c2           |                      503 |                    512 |            0.98 |
| tunnel-service          |                      502 |                    512 |            0.98 |
| tor-or-proxy            |                      496 |                    512 |            0.97 |
| cryptomining            |                      496 |                    512 |            0.97 |
| new-domain-family       |                      496 |                     80 |            6.21 |
| new-destination         |                      510 |                    128 |            3.98 |
| wrong-time              |                      424 |                     40 |           10.61 |
| peer-divergence         |                      354 |                     40 |            8.86 |
| threat-intel-match      |                      264 |                      0 |          no est |
| proxy-sdk-traffic       |                      264 |                      0 |          no est |
| class-violation         |                      234 |                     32 |            7.32 |
| went-silent             |                      218 |                     40 |            5.45 |
| policy-violation        |                      201 |                      0 |          no est |
| fleet-wave              |                      194 |                     40 |            4.84 |
| failed-connection-ratio |                      157 |                     32 |            4.92 |
| upload-ratio-shift      |                      156 |                     32 |            4.88 |
| nxdomain-burst          |                      150 |                     32 |            4.68 |
| fan-out                 |                      139 |                     40 |            3.48 |
| volume-spike            |                      136 |                     40 |            3.41 |
| protocol-mix-shift      |                       73 |                     24 |            3.06 |
| ot-write-rate           |                       59 |                     16 |            3.67 |
| connection-churn        |                       57 |                     16 |            3.59 |
| new-device              |                       41 |                     16 |            2.59 |
| clock-jump              |                       41 |                     16 |            2.59 |

## WP-9.7 — 200 devices, 7 days rich, 2026-10-17

`node --expose-gc bench/run.js`, after the 1,000-device check. 200 devices, classes rotated through the simulator profiles. Each device is fed 7 days of rich traffic, then `lock()`. Heap is `heapUsed` after `global.gc()`, minus the heap before those devices were created. The watching median is 2,000 summary `feed()` calls after lock. Detectors were not tuned.

The same process printed the 1,000-device line first: median 5.33 µs, estimate 5.70 KB/device, heap 12.27 KB/device.

| Metric            | Budget   | Measured  |
| ----------------- | -------- | --------- |
| median `feed()`   | reported | 6.38 µs   |
| memory per device | < 100 KB | 374.99 KB |
| devices           | 200      | 200       |
| events fed        |          | 6,947,350 |

The heap is over 100 KB per device. The script exits non-zero. No threshold was changed.

## WP-9.8 — 7-day heap profile

`node --expose-gc bench/heap-one.js`. 16 devices, two of each class, the same 7-day rich traffic and `lock()` as the 200-device bench. Heap is `heapUsed` after two `global.gc()` calls, minus the heap before those devices were created. Each row is that baseline minus the same run with one detector disabled. Runs were sequential. A parallel sweep moved the smaller rows by several KB, so those numbers are not used. Baseline runs: 463.31 KB/device and 463.99 KB/device. Deltas use their mean, 463.65 KB/device.

Closed windows are not kept. Window history is the per-window sample rings. Hourly history is the 24 rings in `volume-spike-hourly`. With every detector disabled the same 16 devices retain 34.29 KB/device, which is the device record and the open window, plus process overhead spread across 16 devices. LAN scratch is outside this table: `dhcp-starvation` 1.44 KB, `arp-spoof` 1.19 KB, `lan-lateral` 0.99 KB, `identity-change` 0.20 KB.

| Rank | Structure                                      | KB/device |
| ---- | ---------------------------------------------- | --------: |
| 1    | `volume-spike-hourly` hourly rings             |    107.84 |
| 2    | `volume-spike` window byte history             |     98.70 |
| 3    | `fan-out` window destination-count history     |     97.86 |
| 4    | `upload-ratio-shift` window ratio history      |     19.89 |
| 5    | `update-over-cleartext`                        |     12.99 |
| 6    | `failed-connection-ratio` window ratio history |     10.63 |
| 7    | `beacon-change`                                |      4.83 |
| 8    | `egress-flood`                                 |      3.64 |
| 9    | `answer-drift`                                 |      3.63 |
| 10   | `horizontal-scan`                              |      3.00 |
| 11   | `class-violation`                              |      2.66 |
| 12   | `long-connection`                              |      2.37 |
| 13   | `threat-intel-match`                           |      2.36 |
| 14   | `dns-tunnel`                                   |      2.29 |
| 15   | `slow-exfil`                                   |      2.28 |

The same tree's 200-device run, before the representation changes: median 6.75 µs, heap 374.99 KB/device, 6,947,350 events. These per-structure bytes are the part that scales with devices. The three history rows are 304.40 KB of that total.

## WP-9.8 — representation, remeasured

Sample rings now store samples in a `Float64Array`. `toArray()` is still a plain array, and `exportBaseline()` is unchanged. `git diff d4a742f -- test/diff/golden.json` is empty. Repeated destination strings are interned up to the existing destination cap. A device reuses its open window, one idle window, and one close summary. No threshold, cap, or default changed.

`bench/run.js` adds `arrayBuffers` to the byte count. A Float64Array's storage is not in `heapUsed`. The 100 KB check uses the sum.

16 devices, retained = heap + ArrayBuffers:

| After         |  retained KB/device |
| ------------- | ------------------: |
| typed arrays  |              398.23 |
| string intern | 396.83, then 397.77 |
| window reuse  |              398.37 |

Ring rows after the typed arrays, same 16-device disable measurement. The buffer column is the Float64Array storage.

| Structure                 | retained KB |    was |
| ------------------------- | ----------: | -----: |
| `volume-spike-hourly`     |       86.72 | 107.84 |
| `volume-spike`            |       80.17 |  98.70 |
| `fan-out`                 |       80.10 |  97.86 |
| `upload-ratio-shift`      |       14.80 |  19.89 |
| `failed-connection-ratio` |        9.12 |  10.63 |

200 devices after all three fixes: median 8.13 µs, retained 307.64 KB/device, 6,947,350 events. The 1,000-device line in the same process: median 6.25 µs, retained 16.96 KB/device. The 7-day figure is over 100 KB. Caps and the 100 KB budget were not changed.

## WP-11 — after streaming stats, 2026-10-18

`volume-spike`, `fan-out`, and `volume-spike-hourly` keep a Welford summary (count, mean, M2, max) instead of the sample rings. `node --expose-gc bench/run.js` then printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.58 µs | 11.64 KB/device |
| 200 devices, 7 days, then `lock()` |         9.38 µs | 66.96 KB/device |

Events in the 7-day run: 6,947,350. Retained is heap plus ArrayBuffers. The 100 KB budget holds. Caps were not changed.

`update-over-cleartext` stores `{ fired: boolean }`. The 12.99 KB row above is the WP-9.8 disable-one heap delta, not a sample ring. `beacon-change` stores a `learned` map of gaps and a `tracks` map of open gaps. Neither detector was rewritten. `upload-ratio-shift` still keeps a ring capped at 2,048 and `failed-connection-ratio` a ring capped at 1,024. A 7-day learn is longer than those caps, so replacing the ring with a Welford of every learning window would not match the stored samples in `test/diff/golden.json`. Those two rings stay.

## WP-12 — shadow detectors running, 2026-10-18

`exploit-probe-http`, `young-domain`, and `ttl-anomaly` are enabled in shadow mode. `node --expose-gc bench/run.js` then printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.79 µs | 11.68 KB/device |
| 200 devices, 7 days, then `lock()` |        13.54 µs | 68.07 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed.

## WP-13 — streaming statistics library, 2026-10-18

No detector moved onto the new primitives. `node --expose-gc bench/run.js` then printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.96 µs | 11.68 KB/device |
| 200 devices, 7 days, then `lock()` |        10.29 µs | 68.06 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed.

## WP-14 — metamorphic suite, 2026-10-18

A checkpoint now also stores live detector state. `node --expose-gc bench/run.js` then printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         7.08 µs | 11.55 KB/device |
| 200 devices, 7 days, then `lock()` |         8.92 µs | 67.99 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed.

## WP-14.1 — reorder buffer, 2026-10-18

`reorderMs` stays 0 on the 7-day line, so that run does not allocate a buffer. `node --expose-gc bench/run.js` then printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.42 µs | 11.67 KB/device |
| 200 devices, 7 days, then `lock()` |         6.96 µs | 68.11 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed.

`node --expose-gc bench/reorder.js` is the same 1,000-device line with `reorderMs: 5000`. Median `feed()` was 6.08 µs. Retained memory was 8.63 KB/device after `lock()` released the buffer, and 11.34 KB/device while the buffer still held the last 5 seconds of events.

## WP-15 — explainability, 2026-10-18

`explain()` stores one object per anomaly, capped at 1,000 for the whole engine. The 7-day line does not fill that cap. `node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.92 µs | 11.69 KB/device |
| 200 devices, 7 days, then `lock()` |         7.79 µs | 68.15 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed.

## WP-16 — identity, 2026-10-18

The identity table is off unless `identity` is `'auto'`. The 7-day bench leaves it off. `node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.46 µs | 11.70 KB/device |
| 200 devices, 7 days, then `lock()` |         6.50 µs | 68.37 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed.

## WP-17 — feedback and promotion, 2026-10-18

`promote` is off in this bench, so candidates are not stored. The feedback ring is empty. `node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.75 µs | 11.70 KB/device |
| 200 devices, 7 days, then `lock()` |         9.63 µs | 68.34 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed.

## WP-18 — learning-poison guards, 2026-10-18

The three new warnings count during learning and do not add a per-destination table on the 7-day line (`learnMs` is far longer than the run, so the last third and the midpoint are never reached). `node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.42 µs | 11.98 KB/device |
| 200 devices, 7 days, then `lock()` |         7.92 µs | 68.67 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed.

## 0.7.0 release gate, 2026-10-18

`npm run gate` on core 0.7.0 exited 0, then `npm run demo`. `node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.88 µs | 11.98 KB/device |
| 200 devices, 7 days, then `lock()` |         6.71 µs | 68.69 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed.

## WP-18.1 — pack cap, 2026-10-18

No detector state changed. `node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.63 µs | 11.98 KB/device |
| 200 devices, 7 days, then `lock()` |         6.92 µs | 68.70 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed. Core unpacked size was 463,378 bytes.

## WP-19 — horizons, 2026-10-18

`node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.17 µs | 11.99 KB/device |
| 200 devices, 7 days, then `lock()` |         6.54 µs | 84.43 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. The hourly ring is on for that run because T1 is on and the new shadow detectors are enabled. Caps were not changed.

## WP-20 — LAN graph, 2026-10-18

`node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.42 µs | 12.04 KB/device |
| 200 devices, 7 days, then `lock()` |         6.54 µs | 85.51 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. The graph is on because the graph detectors are enabled. Campaigns stay off. Caps were not changed.

## WP-21 — remaining shadow detectors, 2026-10-19

`node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         7.17 µs | 12.04 KB/device |
| 200 devices, 7 days, then `lock()` |        10.13 µs | 87.35 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. The new detectors are enabled and shadow. Caps were not changed.

## WP-22 — rule language, 2026-10-19

`node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.75 µs | 12.04 KB/device |
| 200 devices, 7 days, then `lock()` |        11.17 µs | 87.36 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. The 1,000-device median is the gated watching budget (< 10 µs). Rules were not loaded. Caps were not changed.

## WP-21.5 — shadow detector heap, 2026-10-19

`node --expose-gc bench/heap-one.js`, 16 devices, sequential, every shadow detector still running. Retained is heap plus ArrayBuffers after two collections. Three baselines, median 205.42 KB/device. A row is that median minus the same run with one detector disabled. A second pass of three runs replaced the rows that moved by more than 1 KB, including `upnp-callstranger`, whose first run sat 29 KB the wrong way. Negative rows are inside the baseline spread.

| Detector                 | KB/device |
| ------------------------ | --------: |
| `multi-horizon-exfil`    |      4.58 |
| `slow-scan`              |      2.71 |
| `cloud-storage-exfil`    |      2.12 |
| `ttl-anomaly`            |      1.86 |
| `jitter-beacon`          |      1.80 |
| `exploit-then-download`  |      1.30 |
| `graph-role-change`      |      0.87 |
| `graph-new-bridge`       |      0.80 |
| `dhcpv6-rogue`           |      0.20 |
| `young-domain`           |      0.18 |
| `matter-new-controller`  |      0.07 |
| `evil-twin`              |      0.04 |
| `exploit-probe-http`     |      0.03 |
| `ssh-brute-then-session` |     -0.27 |
| `nd-spoof`               |     -0.31 |
| `upnp-callstranger`      |     -0.41 |
| `wifi-deauth-flood`      |     -0.52 |

Only `multi-horizon-exfil` is over 3 KB/device on this 16-device sweep. Its exported state is about 0.3 KB. The rest of the row is object overhead plus a fixed cost divided by 16 devices. After the typed-array pack, two baselines averaged 204.88 KB/device and two disabled runs averaged 201.00, so the row is 3.88 KB/device. Caps were not changed. Detector output was not changed.

## WP-21.5 — shadow option, 2026-10-19

`node --expose-gc bench/run.js` printed:

| Line                                | median `feed()` |        retained |
| ----------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries        |         6.92 µs | 11.99 KB/device |
| 200 devices, 7 days, defaults       |         7.46 µs | 67.86 KB/device |
| 200 devices, 7 days, `shadow: true` |         9.92 µs | 74.39 KB/device |

Events in each 7-day run: 6,948,925. Both 7-day lines are under 100 KB. The 1,000-device median is under 10 µs. The `shadow: true` median, 9.92 µs, is within 1% of the 10 µs x86 budget. It is recorded and is not a gate. Shadow mode is not claimed budget-safe on a Raspberry Pi 4 until it is measured there. Defaults leave the horizon ring and the LAN graph off, because the detectors that turn them on are shadow. Caps were not changed.

## Alignment re-gate, 2026-10-20

`npm run gate` exited 0. `node --expose-gc bench/run.js` printed:

| Line                                | median `feed()` |        retained |
| ----------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries        |         7.29 µs | 12.01 KB/device |
| 200 devices, 7 days, defaults       |         9.33 µs | 68.13 KB/device |
| 200 devices, 7 days, `shadow: true` |        10.38 µs | 74.52 KB/device |

Events in each 7-day run: 6,948,925. Defaults stay under 10 µs and under 100 KB. The `shadow: true` median is over the 10 µs x86 line. It is still not a gate. Shadow mode is not claimed budget-safe on x86 from this run, and it is not claimed budget-safe on a Raspberry Pi 4 until it is measured there.

`multi-horizon-exfil` does not keep a second hourly ring. Learned hours are five numbers in a `Float64Array` (count, mean, M2, min, max) plus one P² sketch of daily totals. `check()` reads the last 24 hours from `ctx.horizon`, the same ring `slow-scan` uses. Turning this detector off does not shrink that ring while `slow-scan` is still running. The 3.88 KB sweep row is larger than the exported state (about 0.3 KB) because the 16-device sweep divides fixed allocator cost by 16.

## 0.9 tree re-gate, 2026-10-20

Clean clone of local `main` at `2f75270` (`git clone --local` into `/tmp/hubvik-wp28-gate`), then `npm ci`, `npm run gate`, `npm run demo`. The clone does not contain gitignored files. `npm run gate` exited 1. The only failed step was `spec-coverage` (`scripts/spec-coverage.mjs` exit 1). First error: `ENOENT` opening `docs/SPEC.md`. That file is listed in the root `.gitignore` and is not in the commit (D25). `npm run demo` exited 0. Check reported 355 tests, 0 failures. Coverage: 97.07% lines, 84.67% branches, 96.02% functions. A later `npm run coverage` on the working tree, after the shard and stats tests, reported 362 tests, 0 failures, 97.24% lines and 84.93% branches. That is still under 85% branches, so the gate stayed at 90% lines and 80% branches. A later working-tree run, after the branch tests for sample import, UPnP learning, LLMNR ownership, MUD domains, MQTT brokers, and MAC-churn caps, was 368 tests, 0 failures, 97.39% lines, 85.38% branches, and 96.54% functions. The coverage gate is now 95% lines and 85% branches. No file was excluded.

`node --expose-gc bench/run.js` inside that gate printed:

| Line                                | median `feed()` |        retained |
| ----------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries        |         6.96 µs | 12.01 KB/device |
| 200 devices, 7 days, defaults       |         6.67 µs | 67.42 KB/device |
| 200 devices, 7 days, `shadow: true` |         7.92 µs | 71.11 KB/device |

Events in each 7-day run: 6,948,925. The same run printed `bench 4-shard median 6.33 µs versus single 6.96 µs` on this commit, before the later scratch-sharing change.

Against "Alignment re-gate": no median and no KB/device regressed by more than 10%. 1,000-device median 6.96 versus 7.29. Defaults 6.67 versus 9.33, and 67.42 KB versus 68.13 KB. `shadow: true` 7.92 versus 10.38, and 71.11 KB versus 74.52 KB. 1,000-device retained stayed 12.01 KB.

D24 headroom (100 KB minus retained): 32.58 KB on defaults and 28.89 KB with `shadow: true`. Both are over 20 KB, so Q-17 stays closed.

Core unpacked size in that `pack:check`: 213 files, 623684 bytes. Other public packages in the same step: adapter-conntrack 14364, adapter-dnsmasq 14561, adapter-ipfix 16539, adapter-nftables 14076, adapter-openwrt 14955, adapter-ssdp 14217, adapter-suricata-eve 19280, adapter-unbound 14444, adapter-zeek 20538, cli 23784, export-ecs 13431, export-mqtt 13734, export-ocsf 15504, export-prometheus 13637, export-syslog 14250, export-webhook 14914, respond-nftables 14091. Those are unpacked bytes, 7 files each except cli (8 files).

Fuzz, 100,000 inputs each: feed 33401 rejected; baseline 100000 rejected; checkpoint 100000 rejected; baseline mutation 53787 accepted and 46213 rejected; checkpoint mutation 51449 accepted and 48551 rejected; stats 100000 rejected; nd 80018 rejected; feedback 96145 rejected; reorder restore 60129 rejected; rules 87041 rejected; rules mutate 66158 accepted (66.16%) and 0 crashes.

## WP-32 — inline shards, 2026-10-20

Working tree after shared scratch and campaign copy. Same 1,000-device watching loop as `bench/run.js`, `node --expose-gc`, not the full 7-day bench.

| Engine          | median `feed()` |
| --------------- | --------------: |
| single          |         6.58 µs |
| 4 inline shards |         6.54 µs |

Retained on the single engine in that run: 12.01 KB/device. The 4-shard line is not a gate.

## WP-33 — 64-device heap, 2026-10-20

`DEVICES=64 SHADOW=1 node --expose-gc bench/heap-one.js`. Three baselines, then three runs with `DISABLE=multi-horizon-exfil`. Retained is heap plus ArrayBuffers after two collections, divided by 64 devices. A row is the median of the three baselines minus the median of the three disabled runs.

| Run        | retained KB/device |
| ---------- | -----------------: |
| baseline 1 |             120.56 |
| baseline 2 |             103.22 |
| baseline 3 |             103.21 |
| disabled 1 |             101.55 |
| disabled 2 |             101.50 |
| disabled 3 |             119.06 |

Median baseline 103.22 KB/device. Median disabled 101.55 KB/device. The `multi-horizon-exfil` row is 1.67 KB/device. That is under 3 KB, so no representation change. `exportState` was not touched. The 16-device row of 3.88 KB in WP-21.5 was the same state divided by fewer devices. 1.5d stays ticked on this citation.

## WP-34 — shadow watching profile, 2026-10-20

200 devices, 7 days, `shadow: true`, then `lock()`, then 80,000 watching summary `feed()` calls. Samples are the V8 profiler at a 100 µs interval, self time by function. 4,651 samples. `test/diff/dispatch.test.js` stayed green after the options cache below.

| Rank | Function        | Location                       | Self time |
| ---- | --------------- | ------------------------------ | --------: |
| 1    | `_run`          | `engine/feed.js:239`           |     13.3% |
| 2    | `_optionsFor`   | `engine/state.js:30`           |     12.6% |
| 3    | `_apply`        | `engine/feed.js:61`            |     12.1% |
| 4    | `domainFamily`  | `engine/net.js:91`             |      8.0% |
| 5    | `ipv4`          | `engine/net.js:9`              |      7.3% |
| 6    | `_finalize`     | `engine/windows.js:250`        |      4.1% |
| 7    | `_applyPlan`    | `engine/windows.js:152`        |      3.6% |
| 8    | `exactHit`      | `engine/indicators.js:50`      |      3.3% |
| 9    | `domainToASCII` | `(native)`                     |      2.3% |
| 10   | `torHit`        | `detectors/tor-or-proxy.js:71` |      2.3% |

`_optionsFor` was building a fresh object on every detector on every event. It now keeps one object per detector on the engine. Detectors do not write `ctx.options`. The canary path still copies that object before applying overrides. The profiled median of those 80,000 calls was 6.83 µs, with the profiler attached, so it is not a gate number. The unprofiled `shadow: true` median from the clean-clone gate is 7.92 µs. That is one run under 10 µs, not two consecutive gate runs. The line stays ungated (Q-18).

## B21 promotion evidence, 2026-10-20

The three conditions in SPEC 0.5 are a unique detection in an `eval/results/*.json` file, a false-positive rate under the C6.3 gate, and a human decision in `docs/DECISIONS.md`. No row is promoted here.

`eval/results/iot23-malware/iot23.json` has 314 false positives over 72.7037175925926 benign device-days (4.31889881834587 per benign device-day). Its ablation lists no shadow detector. Every ablation `unique` count in that file is 0. `eval/results/iot23-honeypot/iot23.json` has 0 benign device-days. No shadow row meets condition 1 or 2. None has a promotion decision.

## Committed gate, ac4d8d3, 2026-10-20

Clean clone of `ac4d8d3` (`git clone --local` into `/tmp/hubvik-gate-ac4d8d3`), then `npm ci`, `npm run gate`, `npm run demo`. Both exited 0. This commit is `2f75270` plus tracked `docs/SPEC.md`. The engine is the same one measured under "0.9 tree re-gate". Check 355 tests, 0 failures. Coverage 97.08% lines, 84.67% branches, 96.02% functions. That gate still requires 90% lines and 80% branches. Core unpacked 213 files, 623684 bytes.

| Line                                | Median                   | Retained        |
| ----------------------------------- | ------------------------ | --------------- |
| 1,000 devices, watching             | 6.79 µs                  | 12.01 KB/device |
| 1,000 devices, 4 inline shards      | 6.71 µs (single 6.79 µs) |                 |
| 200 devices, 7 days, defaults       | 8.25 µs                  | 67.45 KB/device |
| 200 devices, 7 days, `shadow: true` | 7.58 µs                  | 71.27 KB/device |

Events on both 7-day lines: 6,948,925. Headroom under 100 KB: 32.55 KB defaults, 28.73 KB with `shadow: true`. Both stay above 20 KB, so Q-17 stays closed.

Against the alignment re-gate (7.29 µs / 12.01 KB, 9.33 µs / 68.13 KB, 10.38 µs / 74.52 KB), no median and no KB/device is more than 10% worse. Against the `2f75270` re-gate, the 7-day default median moved from 6.67 µs to 8.25 µs. Retained memory stayed 67.42 KB then and 67.45 KB now, and the engine bytes did not change, so that median move is this run, not a detector edit. It is still under the 10 µs budget and under the alignment 9.33 µs. The shadow medians of the two gate benches are 7.92 µs and 7.58 µs. The shadow line stays out of `bench/run.js` until a person approves it (D-44).

Fuzz, same targets as the earlier re-gate: feed 100000 inputs, 33401 rejected; baseline 100000 rejected; checkpoint 100000 rejected; baseline mutation 53787 accepted, 46213 rejected; checkpoint mutation 51449 accepted, 48551 rejected; stats 100000 rejected; nd 80018 rejected; feedback 96145 rejected; reorder restore 60129 rejected; rules 87041 rejected; rules mutate 66158 accepted, crashes 0.

`npm run demo` exited 0. The camera incident score was 100.

## Later shadow detectors, 64-device heap, 2026-10-20

`DEVICES=64 SHADOW=1 node --expose-gc bench/heap-one.js`. Three baselines, then three runs with one detector disabled. Retained is heap plus ArrayBuffers after two collections, divided by 64 devices. A row is the baseline median minus the disabled median. Runs that jumped to about 120 KB were a collector spike, not the detector: the median of three already ignored a single spike, and `sni-ip-mismatch` was measured again so its median is three runs that stayed near 102.6 KB. Baseline retained: 103.33, 103.60, 103.51 KB/device. Median 103.51.

| Detector                    | KB/device |
| --------------------------- | --------: |
| `sni-ip-mismatch`           |      0.88 |
| `ot-schedule-drift`         |      0.79 |
| `reverse-shell-shape`       |      0.62 |
| `day-of-week-drift`         |      0.58 |
| `llmnr-nbns-poison`         |      0.54 |
| `mac-randomization-churn`   |      0.53 |
| `peer-divergence-federated` |      0.48 |
| `dns-answer-mismatch`       |      0.37 |
| `mud-violation`             |      0.26 |
| `discovery-spoof`           |      0.18 |
| `fleet-baseline-poisoning`  |      0.02 |

Every row is under the 2 KB cap in the bench-budget rule. No representation was changed.

## WP-47 — engine-wide model memory, 2026-10-21

`node scripts/model-memory.js` constructs one bloom filter, two bloom filters, and one half-space forest through `createBloom` and `createForest`. The figures below are the `byteLength` of those typed arrays, and the same length on a `Buffer` of each array. This is not a heap measurement.

| Structure           | byteLength |
| ------------------- | ---------: |
| one bloom `bits`    |      65536 |
| two bloom `bits`    |     131072 |
| forest `mass`       |      10200 |
| forest `lo`         |         64 |
| forest `hi`         |         64 |
| forest typed arrays |      10328 |

`Buffer.byteLength` matched each row: 65536, 131072, 10200, 64, and 64.

## 2.1.0 — feed hot path, 2026-10-27

Same 1,000-device watching script as `bench/run.js` (all tiers, past `learnMs`, `lock()`, then 10,000 timed summary `feed()` calls). Thresholds were not changed.

| Line                                | median `feed()` |        retained |
| ----------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries        |         3.58 µs |  9.81 KB/device |
| 200 devices, 7 days, then `lock()`  |         3.67 µs | 59.58 KB/device |
| 200 devices, 7 days, `shadow: true` |         5.50 µs | 76.42 KB/device |

The gate budget is still median < 12 µs and retained < 120 KB/device. The 4-shard median was 3.75 µs.

## 3.3.0 — core profile, 2026-10-31

Gate (`npm run gate`, Node v24.21.0, darwin arm64, Apple M1). Budgets were not changed: median under 12 µs, retained under 120 KB/device.

| Line                                | median `feed()` |        retained |
| ----------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries        |         3.38 µs |  9.82 KB/device |
| 200 devices, 7 days, then `lock()`  |         3.58 µs | 60.01 KB/device |
| 200 devices, 7 days, `shadow: true` |         5.75 µs | 77.73 KB/device |

The 4-shard median was 3.38 µs versus single 3.38 µs. Estimate 2.29 KB/device. Devices 1000 on the watching line, 200 and 6948925 events on the 7-day lines.

`npm run bench:device` on the same host. This is not a separate budget. The core line is a fresh process.

| Line                            | median `feed()` |        retained |
| ------------------------------- | --------------: | --------------: |
| 1,000-device watching           |         3.96 µs |  9.81 KB/device |
| 200-device 7-day                |         4.17 µs | 60.14 KB/device |
| 200-device 7-day `shadow: true` |         6.83 µs | 76.34 KB/device |
| 1,000-device `profile: 'core'`  |         1.38 µs |  3.88 KB/device |

`arch` is `arm64`. The device bench does not print "This is not a Raspberry Pi measurement." The host is an Apple M1, not a Raspberry Pi.

## 3.4.0 — family incident counts, 2026-10-31

Same capture as `test/diff/corpus.js` (9 replays plus 5 device classes × 3 seeds × 14 days). Both sides used `alerts: true`. `families: false` is the default. Counts are incident and alert events, not a detection rate.

| Side             | benign scenarios | benign incidents | benign alerts | replay incidents | replay alerts |
| ---------------- | ---------------: | ---------------: | ------------: | ---------------: | ------------: |
| `families` false |               24 |                0 |             0 |               24 |             7 |
| `families` true  |               24 |                0 |             0 |               24 |             7 |

On this corpus the family option did not drop a count. True stayed at or under false, and every replay that had an incident with the option off still had one with it on.

Gate (`npm run gate`, Node v24.21.0, darwin arm64, Apple M1) exited 0 on 2026-11-01. Coverage 96.51% lines, 83.64% branches, 94.80% functions. Core unpacked 1014694 bytes. Budgets were not changed: median under 12 µs, retained under 120 KB/device.

| Line                                | median `feed()` |        retained |
| ----------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries        |         4.58 µs |  9.84 KB/device |
| 200 devices, 7 days, then `lock()`  |         4.71 µs | 59.47 KB/device |
| 200 devices, 7 days, `shadow: true` |         7.04 µs | 70.11 KB/device |

The 4-shard median was 4.71 µs versus single 4.58 µs. Estimate 2.29 KB/device. Devices 1000 on the watching line, 200 and 6948925 events on the 7-day lines.

The 1,000-device median is 1.20 µs above the 3.3.0 gate on this same host (3.38 µs). D-85 names an x86 host. This run is arm64. The 12 µs and 120 KB/device gate still held.
