# @hubvik/adapter-suricata-eve

Version 0.2.0. Turns Suricata EVE JSON lines into hubvik events. No dependencies.

`flow`, `dns`, `tls`, and `http` are safe to pass to `engine.feed`. `alert` is returned as `{ type: 'alert', signature, category, severity, ... }` for the host product. The engine does not accept that object.

```js
const { createParser } = require('@hubvik/adapter-suricata-eve');

const parser = createParser({ device: (ip) => ip, now: (iso) => Date.parse(iso) });
for (const event of parser.write(line)) {
  if (event.type === 'alert') continue;
  engine.feed(event);
}
```

JA4 is copied when Suricata already computed it. This package does not compute JA4.

`flow` copies `flow_id` to `uid` and sets `direction` from the addresses. `bytesOut` is the device's bytes. Feed the `dns` or `tls` line before the `flow` line and set `correlate: true` on the engine to attach the name to that flow.
