# Quality gate

`npm run gate` runs every step below and lists every failure. Core is `hubvik`. Nothing here is a detection-rate claim.

| Step          | Command                          | Threshold                                                                                                                                                                          |
| ------------- | -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| check         | `npm run check`                  | lint, `tsc --noEmit`, and the test suites exit 0                                                                                                                                   |
| coverage      | `npm run coverage`               | at least 95% lines and 85% branches                                                                                                                                                |
| pack:check    | `npm run pack:check`             | core unpacked at most 900 KB; other packages 500 KB; no packed file over 60 KB; `src/data/` at most 200 KB; no `TODO`, `FIXME`, `console.log`, or token-shaped string              |
| spec-coverage | `node scripts/spec-coverage.mjs` | every SPEC detector row has a file, and the generated catalog matches this core version                                                                                            |
| numbers-check | `node scripts/numbers-check.mjs` | every percentage or per-device-day figure in the READMEs and `docs/handoff/` cites an `eval/results/` file that contains it                                                        |
| no-dynamic    | `node scripts/no-dynamic.mjs`    | no `child_process`, `eval`, `new Function`, or non-literal `require` in a packed file; `npm audit --omit=dev` reports 0                                                            |
| knip          | `npm run knip`                   | no unused file. Export names are not a failure: knip misses `const api = require(...); api.fn()`, and those names are used by the stats and validate tests                         |
| detector-lint | `node scripts/detector-lint.mjs` | detector modules stay inside the import and size rules                                                                                                                             |
| publint-lite  | `node scripts/publint-lite.mjs`  | package entry points and `files` match                                                                                                                                             |
| api-snapshot  | `node scripts/api-snapshot.mjs`  | public exports match `api/*.api.json`                                                                                                                                              |
| fuzz          | `npm run fuzz`                   | 100,000 seeded inputs per target, no invariant failure                                                                                                                             |
| bench         | `node --expose-gc bench/run.js`  | 1,000-device median `feed()` under 10 µs; 7-day retained memory under 100 KB per device. The `shadow: true` median is recorded and is not a gate until a person approves that line |

`node scripts/no-dynamic.mjs` rejects `child_process`, `eval`, `new Function`, and a non-literal `require` in a packed file, and requires `npm audit --omit=dev` to report 0. `test/types/public-api.ts` is part of `npm run types`.

`node scripts/clean-clone.mjs` clones to a temporary directory and runs the gate, then packs tarballs and runs the `examples/01` feed under CJS and ESM. `--pack-only` skips the clone. It is not inside `npm run gate`, because that would call the gate from inside the gate.
