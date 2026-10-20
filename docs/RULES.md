# Rules

These are the rules that keep a change reviewable. `docs/SPEC.md` is the behavior spec. This file is how to change the tree.

## Code

- Node.js 22 or newer. CommonJS. `'use strict'`. JSDoc on every public function. `index.d.ts` stays in sync with the public API.
- `packages/core` has no runtime dependencies. `dependencies` stays `{}`. Dev dependencies belong in the repo root.
- One detector is one file, `packages/core/src/detectors/<id>.js`, plus `packages/core/test/detectors/<id>.test.js`.
- A detector test fires on the attack, stays silent on benign traffic for each simulated device class, respects its caps, and survives export and import. A hard rule also fires during learning.
- Tests are deterministic. Use the seeded PRNG in `test/fixtures/prng.js`. Do not call `Date.now()` or `Math.random()` in a test or in a decision path.
- Every `Set`, `Map`, or array that grows with traffic has a cap from options and a test that hits the cap.
- Validate external input. Reject `__proto__`, `constructor`, and `prototype` keys.
- The library reports. It does not block, drop, or modify traffic.

## Thresholds

Do not change a detector threshold, default, severity, or formula unless `docs/SPEC.md` and `CHANGELOG.md` change in the same commit.

## Evidence

Do not invent detection rates, benchmarks, or dataset results. Publish a number only when a script in this repo produced it.

## Gates

`npm run check` is green before a commit. Do not skip, todo, or delete a failing test to make a gate pass. Fix the code, or stop and write the question in `docs/QUESTIONS.md`.

Do not start the next phase until the current phase gate passes and a person says to continue.

## Release

Do not run `npm publish`, `git push`, or `npm login` from an agent session. A person does those. Do not create or store npm or GitHub tokens.
