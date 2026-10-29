# @hubvik/decisions-file

Reads a decisions file you already have on disk. Each row needs `value` and `scope` (`Ip`, `Range`, or `Domain`). `duration` (`4h`, `30m`, `1d`, or a number of seconds) needs `now` and becomes `expiresTs`. `scenario` becomes the indicator source.

A decision type of ban, captcha, or throttle is not copied and is not applied. Pass the rows to `loadIndicators()`. The package does not open a socket and does not install a firewall rule.

```js
const { loadDecisionsFile } = require('@hubvik/decisions-file');

const rows = loadDecisionsFile('./decisions.json', { now: Date.now() });
```

UNVERIFIED. Written from the public decisions JSON shape, not from a live CrowdSec install.
