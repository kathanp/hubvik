# Architecture

iotwarden is a library that runs on a gateway. The host feeds observations. The library emits anomalies, warnings, incidents, and campaigns. It does not capture packets, block destinations, or rewrite traffic.

The publishable core is `packages/core` (`iotwarden@0.8.0`). It has no runtime dependencies. Adapters and exporters are separate packages and also have no runtime dependencies. They never call `feed` or send a packet.

## Path of one event

1. An adapter turns a log line or a buffer into an event. The host calls `engine.feed(event)`.
2. The engine's validator checks the event. Unknown fields are dropped with a `warning` of `FIELD_DROPPED`. Keys named `__proto__`, `constructor`, or `prototype` are rejected.
3. The engine assigns the event to an epoch-aligned window and updates the device baseline while the device is learning.
4. Each enabled detector whose required tiers are present may return an anomaly. A detector with `meta.mode: 'shadow'` emits `shadow-anomaly` only when the `shadow` option selects it. Shadow anomalies do not enter incidents, campaigns, or exporter output unless the host subscribes to `shadow-anomaly`.
5. Incidents group live anomalies on one device. Campaigns link incidents across devices when `campaigns` is on.
6. Exporters map those records to OCSF, syslog, or a webhook. The webhook caller supplies `fetch`.

## Layout

| Path                           | Role                                                        |
| ------------------------------ | ----------------------------------------------------------- |
| `packages/core/src/engine/`    | Feed, windows, learning, emit, state, persist, validation   |
| `packages/core/src/detectors/` | One file per detector                                       |
| `packages/core/src/data/`      | Port list, class priors, public-suffix snapshot, ATT&CK map |
| `packages/adapter-*`           | Log or message parsers                                      |
| `packages/export-*`            | Record formatters                                           |
| `packages/respond-nftables`    | Renders nftables rule text from response hints. Never runs  |
| `packages/cli`                 | `replay`, `report`, `doctor`, `baseline`, `rules` commands  |
| `eval/`                        | Dataset joiners and the evasion suite                       |

`createEngine` is the public constructor. Methods stay on `Engine.prototype`.

## What is deliberately absent

No payload inspection, no packet capture, no automatic blocking, no bundled threat feed, and no automatic device-class assignment. Those choices are recorded in Part D of `docs/SPEC.md`.
