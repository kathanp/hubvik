# @hubvik/adapter-zeek

Version 0.2.0. Turns Zeek JSON logs into hubvik events. No dependencies.

Supported `log` values: `conn`, `dns`, `ssl`, `http`, `modbus`, `dnp3`, `mqtt_connect`, `mqtt_subscribe`, `mqtt_publish`, and the CISA ICSNPP logs `bacnet`, `s7comm`, `enip`.

```js
const { createParser } = require('@hubvik/adapter-zeek');

const parser = createParser({
  log: 'conn',
  device: (ip) => ip,
  now: (zeekSeconds) => Math.round(zeekSeconds * 1000),
});

for (const event of parser.write(line)) engine.feed(event);
```

`ssl` becomes a TLS metadata event. JA4 is copied as a string when Zeek already computed it. This package does not compute JA4.

`conn` copies `uid`, maps `conn_state` to `tcpOutcome`, and sets `direction` from `local_orig` and `local_resp`. `bytesOut` is the device's bytes. Feed `dns` and `ssl` before the matching `conn` line and set `correlate: true` on the engine to attach the query name to that flow.

Building-protocol logs become `app` events. The controller is `id.resp_h`. The master or client is `id.orig_h`.
