# Adaptive adversary

White-box. The generator read exportBaseline() of the target device and shaped each goal inside the learned envelope: destinations among learned families or new names in learned CDNs, rates at 0.9 times each learned threshold, timing inside learned active hours, and the learned JA4 when one exists.

No threshold was tuned. Detector defaults were not changed.

alerts: measured on the attack engine with alerts true. A goal is reached only when the attack lands and that run emits no alert and no anomaly at medium or above.

## Goals

- exfiltrate 500 MB in 7 days: not reached (new-destination, stream-to-new-destination, slow-exfil, new-beacon, tier-silent); alerts 3 [incident:critical, hard-rule:high]
- scan 1,000 LAN or WAN hosts in 7 days: not reached (new-destination, direct-ip); alerts 1 [incident:critical]
- keep a C2 beacon for 7 days: reached (white-box blind spot); alerts 0
- write one OT setpoint outside its learned range: not reached (ot-value-out-of-range); alerts 1 [incident:critical]

Reached goals are published as white-box blind spots.
