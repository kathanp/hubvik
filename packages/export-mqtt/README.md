# @hubvik/export-mqtt

@hubvik/export-mqtt 0.1.1. UNVERIFIED.

`toMessages(record)` returns `{ topic, payload }` pairs. `publishWith(publish, record)` calls `publish(topic, payload)` for each pair. This package does not open a socket.
