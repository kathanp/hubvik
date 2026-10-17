# iotwarden

Per-device network anomaly detection for **IoT gateways, smart-home hubs, building-management servers and small network appliances**.

Every IoT device talks through a gateway. iotwarden runs on that gateway, learns each device's normal network behavior, and raises an event when a device changes: a new server, a scan, a traffic flood, activity at the wrong time. No software on the devices, no cloud, zero dependencies.

> Status: 0.4.0 prototype. Not for production. Not validated on real traffic.

## Install

```
npm install iotwarden
```

## Use

```js
const { createEngine } = require('iotwarden');

const engine = createEngine({ learnMs: 7 * 24 * 3600e3 }); // learn for 7 days

// Feed connection summaries from DNS logs, conntrack, or flow records
engine.feed({ device: 'aa:bb:cc:dd:ee:ff', dst: 'video.vendor.com', bytes: 2048, ts: Date.now() });

engine.on('anomaly', (a) => {
  // { device, detector, severity, ts, actual, expected }
  // The host product decides the action.
});

setInterval(() => engine.flush(), 60e3); // close traffic windows

// Learn on one gateway, ship to the fleet
const baseline = engine.exportBaseline();
otherEngine.importBaseline(baseline);
```

iotwarden never blocks anything by itself. It only reports.

## Detectors (0.4.0)

Default enabled tier is `T0`. Pass `tiers: ['T0', 'T1', 'T2']` to turn on flow and DNS detectors. A detector whose required tiers are not enabled stays inactive. 0.1.0 shipped these four:

| Detector          | Catches                                                       | Severity |
| ----------------- | ------------------------------------------------------------- | -------- |
| `new-destination` | Device contacts a host it never used (capped at 3 per window) | medium   |
| `fan-out`         | Too many unique hosts in one window: scanning, DDoS           | high     |
| `volume-spike`    | Far more data than normal: data theft, flooding               | high     |
| `wrong-time`      | Activity in an hour the device was never active               | low      |

0.2.0 adds domain family, port, protocol, scans, volume by hour, DNS, threat indicators, bogons, inbound WAN, policy, ADB, MQTT, SMTP, TFTP, posture, and integrity detectors (`clock-jump`, `input-gap`, `state-cap`, `alert-storm`). 0.3.0 adds class priors, incidents, proxy relay, and the link-layer and tunnel detectors. 0.4.0 adds TLS metadata, building-protocol writes, MQTT topics, and fleet comparison. Those stay off until you enable the tier and send `tls`, `http`, or `app` events. The full list and the tunables are in [`docs/SPEC.md`](../../docs/SPEC.md) and [`docs/DEVELOPERS.md`](../../docs/DEVELOPERS.md).

## Options

| Option               | Default  | Meaning                                              |
| -------------------- | -------- | ---------------------------------------------------- |
| `learnMs`            | 7 days   | Learning period per device, from its first event     |
| `windowMs`           | 60 s     | Traffic window size                                  |
| `sigma`              | 4        | Volume spike sensitivity                             |
| `minFanout`          | 10       | Never flag fan-out below this many hosts per window  |
| `minBytes`           | 1 MB     | Never flag volume below this per window              |
| `maxNewDstPerWindow` | 3        | Cap on new-destination alerts per window             |
| `hourOf`             | UTC hour | Function `(ts) => hour`; pass local time if needed   |
| `fanoutFactor`       | 3        | Fan-out limit is at least this times the learned max |
| `peakFactor`         | 2        | Volume limit is at least this times the learned max  |
| `tiers`              | `['T0']` | Event tiers the host is sending                      |

## Limits

- Sees only traffic that passes through the gateway.
- Encrypted traffic hides content; who, how much and when stay visible.
- Attacks that stay inside normal behavior are not caught.
- If the device is already compromised during learning, that behavior becomes "normal". Use `lock()` after reviewing the baseline.
- A compromised gateway defeats everything.

## License

Apache-2.0
