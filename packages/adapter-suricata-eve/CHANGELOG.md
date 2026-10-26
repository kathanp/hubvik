# Changelog

## 0.2.1

A private, loopback, link-local (`fe80::/10`), or ULA address decides direction, including `::1`, `fe90::1`, and `::ffff:10.0.0.0/8`. `tls.alpn` is copied onto the TLS event.

## 0.2.0

`flow` events carry `direction` from the addresses, `tcpOutcome` from `flow.state` and `tcp.rst`, `durationMs` from `flow.age`, and `uid` from `flow_id`. `bytesOut` is what the device sent. DNS answers keep `ttl`. The same `flow_id` on a dns line and a later flow is the join key for hubvik `correlate`. Not validated on real traffic.

## 0.1.0

Parse Suricata EVE `flow`, `dns`, `tls`, `http`, and `alert` lines. Alert records are passed through for the host and are not engine events. Not validated on real traffic.
