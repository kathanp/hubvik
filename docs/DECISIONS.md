# Decisions

D-1 | WP-2 | bare `flush()` drains windows whose start is ≤ the watermark | Q-6
D-2 | WP-2 | a backward step inside the open window is always accepted | Q-7
D-3 | WP-2 | `minLearnWindows` stays 0 and is not stored per class in this run | Q-2
D-4 | WP-2 | `reorderMs` stays 0 through 0.5 | Q-3
D-5 | WP-2 | the camera example ticks two hours after the first watching heartbeat | ASSUMED: the hijack watermark is 03:00, outside learned active hours, so `went-silent` cannot print from `tick(watermark)` alone
D-6 | WP-3 | spec-coverage accepts an implemented detector whose Rel is ahead of the package version | ASSUMED: the 0.5.0 bump is deferred to the end of this run, and a present Rel 0.5 file must not fail the gate
D-7 | WP-5 | while learning, a new DHCP fingerprint for a known MAC replaces the stored one and does not alert | ASSUMED: the spec does not say whether learning keeps the first fingerprint or the latest, and keeping the latest avoids an alert after a change that happened before watching
