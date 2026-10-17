# @iotwarden/export-ocsf

Maps one iotwarden anomaly to an OCSF Detection Finding (`class_uid` 2004, `type_uid` 200401). No dependencies.

```js
const { toFinding } = require('@iotwarden/export-ocsf');

engine.on('anomaly', (anomaly) => {
  const finding = toFinding(anomaly);
});
```

The library still only reports. This package does not send the finding anywhere.
