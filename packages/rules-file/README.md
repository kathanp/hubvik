# @hubvik/rules-file

Reads a JSON array of site rules you already stored. Pass the result to `loadRules()`.

Keys named `regex`, `regexp`, or `pcre` are rejected, including nested ones. The package does not execute a rule, does not spawn a process, and does not install a firewall rule.

```js
const { loadRulesFile } = require('@hubvik/rules-file');
const { createEngine } = require('hubvik');

const engine = createEngine();
engine.loadRules(loadRulesFile('./rules.json'));
```
