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

The first `src`/`dst` pair on the line is the original direction. Reply counters on the same line are not added.
