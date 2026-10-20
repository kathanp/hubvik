# @hubvik/export-ocsf

Maps one hubvik anomaly to an OCSF Detection Finding (`class_uid` 2004). Pass `{ ocsfVersion: '1.4.0' }` to pin the schema version written into `metadata.version`. An incident object becomes an Update. No dependencies.

```js
const { toFinding } = require('@hubvik/export-ocsf');

engine.on('anomaly', (anomaly) => {
  const finding = toFinding(anomaly);
});
```

The library still only reports. This package does not send the finding anywhere.
