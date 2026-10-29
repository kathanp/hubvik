# @hubvik/trail

Reads a trail file you already have on disk. One host per line. `#` starts a comment. An IPv4 address, an IPv4 CIDR, or a domain name becomes a row for `loadIndicators()`.

The package does not download a trail, does not ship indicator rows, and does not block traffic.

```js
const { loadTrailFile } = require('@hubvik/trail');
const { createEngine } = require('hubvik');

const engine = createEngine();
engine.loadIndicators(loadTrailFile('./malware.txt', { source: 'lab' }));
```

UNVERIFIED. Written from the public one-host-per-line trail shape, not from a live Maltrail install.
