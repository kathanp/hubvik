# How to add the next feature

Follow this order. A feature that skips the spec or the benign gate will fail `npm run gate` or will change behavior the prototype tests depend on.

## 1. Write the behavior into `docs/SPEC.md` first

If the idea is already a row in `docs/SPEC.md`, implement that row. If the row is marked `1.x` or `1.0`, stop and ask. Those wait for a real-traffic evaluation.

If the idea is new, add a row to the matching section (or a short new section) before writing the detector: id, what it catches, tier, method, severity, false-positive note, and the numeric default. Put the same numbers in a "Defaults shipped in …" table when they are not obvious from the row. Note the change in `packages/core/CHANGELOG.md`.

When the spec is ambiguous, stop. Append the question to `docs/QUESTIONS.md` and ask. Do not pick a threshold silently. The 36-hour clock jump exists because a 1-hour threshold failed the benign gate; that kind of choice gets written down.

Do not invent a detection rate to justify the feature.

## 2. Decide the tier before writing code

- T0 runs on every existing test, including 14 benign days and the six prototype tests. It must no-op unless its own precondition is present (a peer group, a class, an indicator, a policy rule, an engine signal).
- T1–T5 stay off when `tiers` is the default `['T0']`. Prefer the lowest tier the spec allows so default installs do not change.
- `hardRule: true` only for the cases in SPEC B10: the attack is meaningful even when the device is still learning, or the detector is an engine-integrity signal. A hard rule must still be silent on the benign fixtures.

## 3. Detector file

Path: `packages/core/src/detectors/<id>.js`. Then add one `require` to the `ALL` array in `packages/core/src/detectors/index.js`. Export order is not load-bearing, but keep new ids at the end.

Shape:

```js
'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'example',
  version: 1,
  requires: ['T1'],
  category: 'scan',
  hardRule: false,
  defaults: { minCount: 10, severity: 'high' },

  createState() {
    return { seen: new Set(), fired: false };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    // record only. no anomaly
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow') return;
    // return an anomaly draft or undefined
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: 'what happened',
      expected: 'what normal looks like',
      data: {},
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { seen: [...dev.seen].slice(0, 5000) };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.seen = new Set(Array.isArray(state.seen) ? state.seen.slice(0, 5000) : []);
    dev.fired = false;
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.seen.size * 24 + 16;
  },
};

module.exports = detector;
```

Rules inside the file:

- Read tunables from `ctx.options`, which is `defaults` overlaid with `createEngine({ detectors: { [id]: { ... } } })`. Do not read root `sigma` / `minBytes` unless this is one of the original four detectors.
- Cap every structure that grows with traffic. 5,000 is the usual per-device cap. Throw on import when an array is over the cap, matching the older detectors. A silent `return` on oversize import is weaker and should not be copied (`beacon-change` does that; do not spread it).
- `exportState` of a fresh state must import back without throwing. The prototype baseline round trip exports every detector.
- `onWindowClose(dev, win, ctx)` is optional. The window is closed in `_advanceTo` before the event that fell into the next window is processed, so the closing window still holds its counts.
- Per-window counters must reset when `ctx.window.start` changes.
- Shared LAN state goes on `ctx.scratch`, not on the device, when events arrive under different device ids.
- If the detector is an engine signal, `check` returns unless `ctx.extra.kind` is the signal name, and the engine calls `_special`. Do not emit from ordinary `feed` traffic.
- Add an ATT&CK id to `src/data/attack-map.json` only when the mapping is real. Add a stage (`recon`, `c2`, `spread`, `impact`) to `src/data/stages.json` only when the detector should move an incident's stage. Duplicate JSON keys are a bug; the second one wins.
- Update `packages/core/src/index.d.ts` when the public event shape or options grow. `tsc -p tsconfig.json --noEmit` checks `packages/core/src` only.
- JSDoc every public function. Prettier (`printWidth` 100, `singleQuote`, `trailingComma: all`, `proseWrap: preserve`) will reflow a `/** @param */` that sits on an arrow. Use a named function instead.

`packages/core/src/detectors/lib.js` has `seenState`, `exportSeen`, `importSeen`, `memorySeen`, `entropy`, `median`, and `listed` for the common "remember strings, alert once" detectors.

## 4. Tests

Add a case to the current phase file, or add `packages/core/test/detectors/<id>.test.js`. The project rule wants one file per id. The tree today uses grouped `phaseN.test.js` plus replay files. A new id can have its own file. Do not delete the grouped suites.

Every new detector needs all of these, or the gate is not honest:

- Fires on a crafted attack.
- Stays silent on 14 benign days for every simulated class. The existing `benign.test.js` and `benign-matrix.test.js` cover this if the detector is T0 or if higher tiers stay off. If you enable a higher tier inside those files, fix the detector rather than skipping the test.
- Respects its cap (a test that hits the cap).
- Survives `exportBaseline` / `importBaseline`.
- A hard rule fires while `learnMs` is still in the future, and the anomaly's `hardRule` field is true.

Timestamps are explicit numbers. No `Date.now()`, no `Math.random()`. Seeded PRNG is `packages/core/test/fixtures/prng.js`.

`createEngine({ learnMs: 0, tiers: ['T0', 'T1'] })` makes a non-hard detector `check` the first event. That is the empty-baseline case. A "learned, then changed" detector needs a long `learnMs`, the learning events, then `lock(device)`, then the attack.

Public addresses in tests: `1.2.3.x`, `8.8.8.8`, `9.9.9.9`. `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24` are bogons.

A flow that should be one window uses timestamps inside the same 60-second epoch bucket. `flush(windowEnd)` closes it. `onWindowClose` detectors need that flush.

## 5. Adapters and exporters

New package under `packages/<name>/` at `0.1.0` unless it already exists. `dependencies` is `{}`. Copy `LICENSE` from `packages/core/LICENSE`. Include `README.md`, `CHANGELOG.md`, `src/index.js`, and `test/*.test.js`. `package.json` `files` is `src`, `README.md`, `LICENSE`, `CHANGELOG.md`.

The root test script is `packages/*/test/**/*.test.js`, so the new test runs in `npm test`. `scripts/pack-check.mjs` packs every workspace that is not `"private": true`.

Parsers return engine events. They do not call `feed`. Suricata `alert` is a host object and must not be given to `engine.feed`. Zeek `ssl` becomes `tls`. Zeek and ICSNPP building-protocol logs become `app` events: the controller is `id.resp_h`, the master is `id.orig_h`.

Webhook tests pass a fake `fetch` and a fake `sleep`. They must not open a socket.

## 6. Docs the human will hand to the next session

Update `docs/DEVELOPERS.md` when the host has a new event field or option. Update `packages/core/README.md` and the root `README.md` status line only when the version changes. Keep the prototype sentence. Append the real gate output to `docs/progress/PHASES.md` or `docs/progress/WORK-PACKAGES.md` after the gate, not before.

## 7. Run the gate

```
export PATH="$HOME/.nvm/versions/node/v24.21.0/bin:$PATH"
npm run check     # eslint, prettier --check, tsc, tests
npm run gate      # check + coverage + pack-check + bench/fuzz no-ops
npm run demo
```

Coverage flags are `--test-coverage-lines=90 --test-coverage-branches=80`. A branch gap in a brand-new detector can pull the repo under 80. Cover both sides of the early returns that matter, or the gate fails. Do not lower the thresholds.

`npm run gate` is the check that has to pass before calling a release done. Bump `packages/core/package.json` only after the behavior is green, then run `npm install --package-lock-only` so `package-lock.json` shows the new version, then run the gate once more so the packed version matches. `engine.pkg` is read from that `package.json`.

## 8. Do not do these

- Do not `npm publish`, `npm login`, `git push`, or `gh repo create`.
- Do not add a runtime dependency anywhere in `packages/*`.
- Do not start Phase 5 (fuzz, bench, eval harness) or Phase 6 (GitHub and npm release) unless the human says go. Phase 5's benchmark budgets and dataset steps are in `CURSOR_BUILD.md`. The human runs the datasets. The agent may write the harness only after that go-ahead, and README numbers come only from files the harness writes.
- Do not compute JA4 or any JA4+ variant.
- Do not ship a threat-intel feed, ASN database, or Tor list inside core.
- Do not claim this package is the best detector, or publish a percentage it has not measured.
- Do not commit unless the human asks. Conventional message when they do: `feat(detector): example`.

## Suggested next work, if the human says go

In order, and only the one they name:

1. `identity-change` (the missing 0.4 row), using a host-supplied DHCP fingerprint string.
2. A 1.x row needs a numeric default written into SPEC by the human first. A row with no number is not started. New detectors ship off by default until WP-12, then in shadow mode.
3. Phase 5 from `CURSOR_BUILD.md`: fuzz, bench, eval harness. Still no invented metrics.
4. One test file per detector id, without deleting the grouped suites, until `scripts/spec-coverage.mjs` exists and can check the SPEC tables.

Anything else is a new spec row, written first.
