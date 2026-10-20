# @hubvik/adapter-dnsmasq

Turns dnsmasq `log-queries=extra` lines into hubvik DNS events. No dependencies.

```js
const { createParser } = require('@hubvik/adapter-dnsmasq');

const parser = createParser({
  device: (clientIp) => clientIp,
  resolver: '10.0.0.1',
  now: () => Date.now(),
});

parser.write(line); // [] for a query, one dns event for a reply
```

A reply is attached to the latest query for that name. `reply name is NXDOMAIN` sets `rcode` to `NXDOMAIN`.
