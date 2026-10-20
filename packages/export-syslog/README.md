# @hubvik/export-syslog

Formats one hubvik anomaly as an RFC 5424 syslog line. The message is a CEF record. No dependencies. This package does not open a socket.

```js
const { format } = require('@hubvik/export-syslog');

engine.on('anomaly', (anomaly) => {
  const line = format(anomaly, { host: 'gateway' });
});
```

Facility is local0. Severity follows the anomaly: critical is 2, high is 3, medium is 4, low is 5, info is 6.
