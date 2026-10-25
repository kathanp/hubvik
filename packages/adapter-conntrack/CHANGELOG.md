# Changelog

## 0.3.0

A conntrack line now carries TCP outcome, both directions of bytes, and a direction taken from private addresses when the caller does not pass one. An inbound flow counts the device's bytes. `SYN_SENT` is `no-response`. `ESTABLISHED` is `established`. Three silent inbound ports and one established session drive `port-knock`. An explicit `direction` function still wins.

## 0.2.0

Parse conntrack list and event lines into flow events.
