# @iotwarden/adapter-suricata-eve

Turns Suricata EVE JSON lines into iotwarden events. No dependencies.

`flow`, `dns`, `tls`, and `http` are safe to pass to `engine.feed`. `alert` is returned as `{ type: 'alert', signature, category, severity, ... }` for the host product. The engine does not accept that object.

```js
const { createParser } = require('@iotwarden/adapter-suricata-eve');

const parser = createParser({ device: (ip) => ip, now: (iso) => Date.parse(iso) });
for (const event of parser.write(line)) {
  if (event.type === 'alert') continue;
  engine.feed(event);
}
```

JA4 is copied when Suricata already computed it. This package does not compute JA4.
