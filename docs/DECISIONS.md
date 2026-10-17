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
