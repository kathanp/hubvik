AUTOPILOT-2. Save this message unchanged to docs/AUTOPILOT-2.md, commit "chore: add autopilot-2 plan", then execute in order. Tick boxes as you go. Do not stop between WPs. Same operating rules as docs/AUTOPILOT.md Section 1 (no push, no publish, no download, never edit an assertion or golden file to pass, log ASSUMED decisions in docs/DECISIONS.md).

HARD STOP if: a protected test or the differential golden fails after 3 honest attempts; passing needs a detector disabled, a severity lowered, or a budget loosened; anything needs network or deletion of user files.

Fast check after each WP. Full gate + demo at the end only.

## WP-9.1 — Harness correctness
- [x] Wilson unit tests against hand-computed values: 18/20, 0/25, 25/25, 0/0 (must print "no rate"). Use z = 1.96. Put the expected bounds in the test to 4 decimals.
- [x] Generated synthetic corpus (eval/fixtures/gen.mjs, seeded PRNG, no Date.now/Math.random): 5 devices, 2 days benign learning prefix then lock, 3 benign device-days after lock, and >= 20 labeled attack instances across 4 types (horizontal scan, slow vertical scan, C2 beacon to a new host, UDP flood). Writes Zeek-format conn.log with label / detailed-label columns.
- [x] Run eval on it. Every code path must execute: detection %, FP per device-day, Wilson intervals, "n too small", time-to-detect, per-detector table. Commit the output as a golden fixture.
- [x] Explain the missing beacon from the WP-9 fixture: not labeled, not scored, or not detected. If not detected, that is a finding, not a bug to tune away. Record it in docs/progress/WORK-PACKAGES.md.
- [x] Ablation: per detector, detection with it disabled; mark detectors with zero unique detections. Write the C6.2 step 6 proposal file; do not change any default.
- [x] Evasion suite in eval/evasion/: slow scan 1 host/window, beacon 40% jitter, exfil at 0.9 x slow-exfil limit, flood split over 10 destinations. Publish results as known blind spots in eval/results/evasion.md. Do not tune.
- [x] eval/run.mjs prints a 5-line summary to stdout (dataset, devices, attack instances, detection, FP/device-day).

## WP-9.2 — IoT-23 parser and attack intervals
- [x] Parse Zeek TSV exactly: #separator, #fields, #types headers; "-" and "(empty)" as unset. Handle the labeled files where the last three columns (tunnel_parents, label, detailed-label) may be space-separated rather than tab-separated. Test both layouts with hand-written fixture lines.
- [x] Device = id.orig_h for outbound, id.resp_h for inbound, per capture. Document it.
- [x] Attack interval definition: contiguous runs of Malicious-labeled flows per (device, detailed-label), merged when gaps < 5 min. Write it in eval/README.md and in every results file header. Test with a fixture that has two runs separated by 10 min (= 2 instances) and by 2 min (= 1 instance).
- [x] Every results file states: "T1 only (conn.log). DNS, TLS, link-layer and app detectors not exercised."

## WP-9.3 — CICIoT2023 joiner (unverified against real data)
- [x] Joiner that takes Zeek conn.log + dns.log + ssl.log produced from CICIoT2023 PCAPs and labels by the attack category of the source PCAP file. Mark "UNVERIFIED: written from documentation, not run on real data" in the joiner header and eval/README.md.
- [x] eval/README.md: exact zeek command to turn one PCAP into logs, then the run.mjs command.
- [x] Fixture test with hand-written lines only.

## WP-9.4 — Real memory in the bench
- [x] bench reports both memoryEstimate per device AND measured heap delta per device (node --expose-gc, process.memoryUsage().heapUsed before/after, 1,000 watching devices). Budget check uses the heap number. If over 100 KB, HARD STOP with the number; do not tune.
- [x] docs/BENCHMARKS.md table gets a "measured heap" column and a "Raspberry Pi 4: not measured" row.

## WP-9.5 — Docs
- [ ] README and packages/core/README.md: Evaluation section says "Not yet evaluated on real traffic. Harness: eval/README.md." No numbers.
- [ ] docs/QUESTIONS.md: add any open question about label semantics you could not resolve.

## Final
- [ ] Full gate + demo. AUTOPILOT REPORT with every field filled from THIS run only (no copied values from earlier reports), plus: corpus summary line, ablation zero-unique list, evasion blind spots, beacon finding, heap per device.
