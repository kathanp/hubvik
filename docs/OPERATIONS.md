# Operations

iotwarden runs inside a gateway process. The host owns capture, clocks, and any response.

## What the host sends

Enable only the tiers you can fill. The default is `['T0']`. A detector whose tiers are missing stays inactive, which `engine.stats().detectors` reports. A tier you enable but never feed emits `TIER_NEVER_SEEN` once. A tier that stops while others keep flowing fires `tier-silent`.

Pass event time on every event. Call `engine.tick(now)` or `engine.flush(now)` with that same clock. A bare `flush()` is an end-of-input drain. It is not a periodic timer.

If you merge two or more log sources (for example conntrack and dnsmasq), set `reorderMs: 5000`. Without it, a flow that arrives before its DHCP ack can be reported as `src-spoof`. Alerts are then delayed by 5 seconds. With the default `reorderMs: 0`, a backward step inside the open window is still accepted. Late events after a window has closed emit `LATE_EVENT`.

## Learning

Each device learns for `learnMs` (default 7 days) from its first event. Review the baseline, then call `lock()`. `lock()` on a device that is not ready emits `LOCKED_UNREVIEWED` and still enters watching.

`stats().learningQuality` reports windows, families, suspicious reasons, and `ready`. Warnings use `SUSPICIOUS_LEARNING`. They are not anomalies.

Shadow detectors stay off unless `createEngine({ shadow: true })` or `shadow` is a list of ids. The default is `false`.

## Checkpoints

`checkpoint()` writes the baseline, the watermark, learning progress, and the LAN scratch tables. A snapshot over 16 MB drops the oldest ARP bindings, then the oldest learned MACs, and emits `CHECKPOINT_TRUNCATED`. `restore()` checks the snapshot, including HMAC when a key was set, and replaces state only after that check.

Checkpoint after a reboot-sensitive change, not just on a timer. Without a restore, the first ARP binding seen after a reboot is learned as truth. `checkpointDelta()` keeps frequent saves small so they do not wear out router flash.

## Memory and speed

With default options, the gate budgets on x86 are under 100 KB retained per device for a 7-day run and under 10 µs median `feed()` at 1,000 devices. With `shadow: true` the last run measured 10.38 µs, which is over that line and not gated. `docs/BENCHMARKS.md` holds the numbers from the last run. A Raspberry Pi 4 measurement is still a person's job. Do not copy an x86 number into that row.

## Response

The core never applies a firewall rule. `@iotwarden/respond-nftables` (0.1.0, UNVERIFIED) renders rule text from `anomaly.response` hints when `responseHints: true`. It never executes anything. Applying the text is the host's decision. Building-controller (`ot-*`) anomalies only ever get a `review` hint.

## Incidents

Anomalies on one device group into an incident for 30 minutes. Two stages, or a score of at least 70, is critical. `ack` halves the score. Shared `dedupGroup` values contribute once.
