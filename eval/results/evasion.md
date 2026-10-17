# Evasion

Synthetic known blind spots. Thresholds were not tuned against this suite.

Attack intervals: contiguous Malicious runs per (device, detailed-label), merged when the gap is under 5 minutes.

T1 only (conn.log). DNS, TLS, link-layer and app detectors not exercised.

- slow-scan: fired (new-port)
- beacon-jitter-40: fired (new-beacon)
- exfil-0.9-limit: blind spot (none)
- flood-10-destinations: fired (new-port, egress-flood, stream-to-new-destination)
