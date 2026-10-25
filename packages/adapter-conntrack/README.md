# @hubvik/adapter-conntrack

Turns `conntrack -L` and `conntrack -E` lines into hubvik T1 flow events. No dependencies.

```js
const { createParser } = require('@hubvik/adapter-conntrack');

const parser = createParser({
  device: (srcIp) => srcIp,
  direction: (srcIp, dstIp) => (dstIp.startsWith('10.') ? 'lan' : 'out'),
  now: () => Date.now(),
});

parser.write(line); // array of flow events, or empty
```

The first `src`/`dst` pair is the original direction. The second pair is the reply. `bytesOut` is the device's bytes, so an inbound flow swaps the counters. With no `direction` function, a private address chooses `out`, `in`, or `lan`. Pass `direction` to keep your own choice. TCP `ESTABLISHED` becomes `tcpOutcome: 'established'`. `SYN_SENT` becomes `no-response`.

```js
const { createEngine } = require('hubvik');
const { createParser } = require('@hubvik/adapter-conntrack');

const engine = createEngine({ learnMs: 0, tiers: ['T1'], shadow: ['port-knock'] });
const parser = createParser({ now: () => Date.now() });
for (const event of parser.write(line)) engine.feed(event);
```
