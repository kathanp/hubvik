# @hubvik/export-webhook

POSTs one hubvik anomaly as JSON. No dependencies. Pass your own `fetch` so the package never chooses a network stack.

Failed responses are retried. The wait doubles each time (`backoffMs`, then `2 × backoffMs`). `sign` adds an `x-hubvik-signature` header: hex HMAC-SHA256 of the raw body.

```js
const { createSender } = require('@hubvik/export-webhook');

const sender = createSender({
  url: 'https://collector.example/hooks/hubvik',
  fetch,
  sign: process.env.IOTWARDEN_HOOK_KEY,
});

engine.on('anomaly', (anomaly) => {
  sender.send(anomaly).catch((err) => console.error(err));
});
```

The README example is the only place this package mentions logging. The library code does not log, and it does not block traffic.
