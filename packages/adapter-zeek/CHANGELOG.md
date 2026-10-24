# Changelog

## 0.2.0

`conn` events carry `tcpOutcome` from `conn_state`, `direction` from `local_orig` and `local_resp` (otherwise from private addresses), and `uid`. `bytesOut` is what the device sent, so an inbound flow swaps Zeek's orig and resp counters. DNS answers use the query type and per-answer TTLs. Modbus keeps `unit_id`. MQTT publish keeps `retain`, and MQTT connect keeps `will_topic` as a will flag. Not validated on real traffic.

## 0.1.0

Parse Zeek JSON `conn`, `dns`, `ssl`, `http`, Modbus, DNP3, MQTT, and ICSNPP BACnet, S7, and EtherNet/IP lines into hubvik events. Not validated on real traffic.
