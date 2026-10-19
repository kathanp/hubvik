# Evasion

Synthetic known blind spots. Thresholds were not tuned against this suite.

Attack intervals: contiguous Malicious runs per (device, detailed-label), merged when the gap is under 5 minutes.

T1 only (conn.log). DNS, TLS, link-layer and app detectors not exercised.

Learning span: the benign prefix of each scenario, then lock.

Malicious-label share inside the learning prefix: 0.

- slow-scan: blind spot (none)
- beacon-jitter-40: blind spot (none)
- exfil-0.9-limit: fired (multi-horizon-exfil)
- flood-10-destinations: fired (egress-flood)

Shadow rows measured on this suite. A miss stays a blind spot. The holdout is separate.

- slow-scan: blind spot
- jitter-beacon: blind spot
- multi-horizon-exfil: fired
