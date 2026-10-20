# @hubvik/adapter-zeek

Turns Zeek JSON logs into hubvik events. No dependencies.

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

Building-protocol logs become `app` events. The controller is `id.resp_h`. The master or client is `id.orig_h`.
