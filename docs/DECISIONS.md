# Decisions

D-1 | WP-2 | bare `flush()` drains windows whose start is ≤ the watermark | Q-6
D-2 | WP-2 | a backward step inside the open window is always accepted | Q-7
D-3 | WP-2 | `minLearnWindows` stays 0 and is not stored per class in this run | Q-2
D-4 | WP-2 | `reorderMs` stays 0 through 0.5 | Q-3
D-5 | WP-2 | the camera example ticks two hours after the first watching heartbeat | ASSUMED: the hijack watermark is 03:00, outside learned active hours, so `went-silent` cannot print from `tick(watermark)` alone
D-6 | WP-3 | spec-coverage accepts an implemented detector whose Rel is ahead of the package version | ASSUMED: the 0.5.0 bump is deferred to the end of this run, and a present Rel 0.5 file must not fail the gate
D-7 | WP-5 | while learning, a new DHCP fingerprint for a known MAC replaces the stored one and does not alert | ASSUMED: the spec does not say whether learning keeps the first fingerprint or the latest, and keeping the latest avoids an alert after a change that happened before watching. Revised in WP-8.1: keep the first fingerprint, and emit `SUSPICIOUS_LEARNING` reason `identity-change`
D-8 | WP-6 | a Part B severity cell that names more than one severity is not compared to `defaults.severity` | ASSUMED: `proxy-sdk-traffic` is medium on two classes and high otherwise, so the row has no single default for spec-coverage to require
D-9 | WP-8 | the bench median is recorded as measured and the detectors are not tuned | ASSUMED: this run measured 24.29 µs median `feed()` and 2.46 KB per device with every tier on, over the 10 µs budget and under the 100 KB budget
D-10 | WP-8.1 | core stays 0.5.0 and C10 row 0.5 Met? records the bench miss | the watching-state bench measured 22.38 µs against a < 10 µs budget; reverting the package version would not change that, and the 0.5 detectors are already in the tree. Revised in WP-8.2: dispatch by `meta.consumes` measured 6.13 µs in the gate, under the same 10 µs budget. Core stays 0.5.0
D-11 | WP-8.2 | C10 row 0.5 Met? records the bench after dispatch | the 10 µs budget was not changed; the gate median was 6.13 µs and 1.19 KB/device
D-12 | WP-9.2 | each conn row picks its own device | ASSUMED: "per capture" means each row in that capture, outbound `id.orig_h` and inbound `id.resp_h`, not one device for the whole file
D-13 | WP-9.6 | evasion destinations stay in the learned /24 | ASSUMED: the /24 is only the address list in `eval/evasion/scenarios.js`. `domainFamily()` is unchanged: an IP has no family. No detector file implements a /24. Also mentioned in `eval/README.md` and `docs/progress/WORK-PACKAGES.md`. Revised in WP-9.7.
D-14 | WP-9.7 | the 7-day rich bench is recorded over budget and the detectors are not tuned | measured heap 374.99 KB/device after lock, 200 devices, 6,947,350 events, watching median 6.38 µs. The 100 KB budget was not raised
D-15 | WP-9.7 | each simulated bench device gets its own id | ASSUMED: every class profile names one device id, and feeding that id 200 times would collapse the heap into one device
D-16 | WP-9.9 | baseline files are version 3 | APPROVED: version 2 imports are upgraded by computing streaming stats from the stored samples. Version 1 still imports
D-17 | WP-9.9 | the differential golden comparison tolerates float noise | APPROVED: detector, device, timestamp, severity, and category match exactly. Numeric fields match within a relative difference of 1e-9. Strings that embed numbers are compared after parsing those numbers with the same tolerance. The golden file itself is not edited
