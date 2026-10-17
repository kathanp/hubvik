# Changelog

## 0.2.0

`toFinding` takes `{ ocsfVersion }`, default `1.4.0`, and writes it to `metadata.version`. `fingerprint` becomes `finding_info.uid`. `evidence.sample` becomes `evidences[]` and is omitted when the anomaly has no evidence. An incident, recognized by `anomalyIds`, is an Update (`type_uid` 200402).

## 0.1.0

Map an anomaly to an OCSF Detection Finding. Not validated on real traffic.
