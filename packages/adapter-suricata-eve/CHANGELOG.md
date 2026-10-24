# Changelog

## 0.2.0

`flow` events carry `direction` from the addresses, `tcpOutcome` from `flow.state` and `tcp.rst`, `durationMs` from `flow.age`, and `uid` from `flow_id`. `bytesOut` is what the device sent. DNS answers keep `ttl`. The same `flow_id` on a dns line and a later flow is the join key for hubvik `correlate`. Not validated on real traffic.

## 0.1.0

Parse Suricata EVE `flow`, `dns`, `tls`, `http`, and `alert` lines. Alert records are passed through for the host and are not engine events. Not validated on real traffic.
