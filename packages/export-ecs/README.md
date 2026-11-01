# @hubvik/export-ecs

@hubvik/export-ecs 0.1.0. UNVERIFIED.

`toDocument(record)` maps an anomaly, incident, or campaign to an ECS 8.11 document. Campaigns set `event.category` to `intrusion_detection` and copy `devices` to `related.hosts`.
