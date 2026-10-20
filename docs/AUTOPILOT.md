# AUTOPILOT v2 — team run playbook

Local only (`.gitignore`), never pushed. To start a run, the human writes a plan and says: "Run AUTOPILOT.md with this plan." The master reads this file, then `docs/RULES.md`, `CONTRIBUTING.md`, `docs/SPEC.md`. All of them apply in full.

**Principle of v2:** every rule that can be checked by a script is checked by a script (`scripts/autopilot/guard.mjs`). A prose rule is a fallback only when no check is possible. A green guard is required for every merge.

---

## 0. Launch modes (decide before the run, write it in the run state)

| Mode                 | How workers run                                                                                                                                         | Isolation guarantee                                                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A — real workers** | Master launches each worker as a separate headless Cursor agent (CLI/background agent) in its own worktree, with only the task card file as its prompt. | Real: workers cannot see each other or the run history.                                                                                                          |
| **B — single agent** | One Cursor agent does every role in sequence.                                                                                                           | Weak: it has seen the code. Compensate: test cards are written and tests committed _before_ any code task in the batch starts, and the guard enforces ownership. |

If the master cannot actually launch separate agents, it uses Mode B and says so in the report. It never claims Mode A isolation in Mode B.

---

## 1. Roles

| Role       | Max at once                                       | Owns                                                                  | Never does                                        |
| ---------- | ------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------- |
| Master     | 1                                                 | Plan, run state, every merge, every shared file, talking to the human | Write detector code or tests                      |
| Spec agent | 1 (2–3 only if the gap changes which alerts fire) | `docs/proposals/<task>-<n>.md`                                        | Edit `docs/SPEC.md` or code                       |
| Test agent | 3                                                 | Test paths in its card                                                | Edit `src/`, an existing assertion, a golden file |
| Reviewer   | 1                                                 | `.autopilot/reviews/<task>.md`                                        | Edit anything else                                |
| Code agent | 3                                                 | Source paths in its card                                              | Edit any test or shared file; invent a threshold  |

Workers never talk to each other. A worker receives only: its card file, `docs/RULES.md`, and the SPEC sections the card names.

---

## 2. File ownership

**Master only:** `docs/SPEC.md`, `docs/DECISIONS.md`, `docs/QUESTIONS.md`, `docs/BENCHMARKS.md`, `docs/DETECTORS.md` (generated), every `CHANGELOG.md`, every `package.json` version, `package-lock.json`, `packages/core/src/detectors/index.js`, `packages/core/src/index.d.ts`, `src/data/attack-map.json`, `src/data/stages.json`.

**Nobody, ever:** `test/diff/golden.json`, the six prototype tests in `packages/core/test/engine.test.js`.

Both lists live in `.autopilot/protected.json`. At run start the master records their SHA-256 hashes in `.autopilot/protected.sha256` (`node scripts/autopilot/guard.mjs --snapshot`). The guard fails any branch that changes a hash.

A worker that needs a master-only change puts the file, exact line, and reason in its report. The master applies it at merge.

---

## 3. Git hygiene (enforced, not requested)

**Target shape of `main` after a run:**

- one `docs(spec): run <name> decisions` commit, only if Phase 1 changed the SPEC;
- one commit per finished task;
- one `--no-ff` merge commit.

Nothing else.

**Run start, once:**

```
echo ".autopilot/" >> .gitignore          # if not already there
node scripts/autopilot/guard.mjs --install-hooks
node scripts/autopilot/guard.mjs --snapshot
```

Make sure `.gitignore` also has `.worktrees/` and `docs/proposals/`.

The commit-msg hook strips agent co-author trailers (`Co-authored-by: … cursor|agent|bot`) on `run/*` and `main`. It also rejects any commit on `run/*` or `main` whose subject is not:

- `<type>(<area>): <T-n|#n> <title>`,
- `docs(spec): run <name> decisions`,
- `release: x.y.z`, or
- a merge.

`fixup!` is allowed temporarily. Commits on `wk/*` are unrestricted, because they are squashed away.

| Never commit                                                        | Where it goes instead                                                                                                                                   |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Reports, run state, snapshots, verify logs, checkpoints, scan diffs | `.autopilot/` (gitignored): `RUN_STATE.md`, `reports/<task>.md`, `logs/`                                                                                |
| Spec revisions mid-run                                              | Batched into the one `docs(spec)` commit. A mid-run SPEC change rides inside the task commit that needed it.                                            |
| A fix to an already-merged task                                     | `git commit --fixup=<task sha>`, then `git rebase -i --autosquash <base>` before the gate. `run/<name>` is local and unpushed, so rewriting it is safe. |
| A revert                                                            | Drop the task commit with an interactive rebase and mark the task PARKED.                                                                               |
| Changelog/record-only commits                                       | Part of the task commit (master edits).                                                                                                                 |

**Agents must run locally.** Cursor cloud/background agents work on a branch pushed to GitHub, which produces exactly the push-per-step history this section forbids. Mode A means local headless agents in local worktrees only.

---

## 3a. Run state (survives context loss)

`.autopilot/RUN_STATE.md` is the master's memory. It rewrites the whole file after **every** state change: card written, worker started, report received, merge, park.

```
RUN <name>   MODE <A|B>   STARTED <iso>   BASE <main sha>
PHASE <spec | build | gate | done | hard-stop>
TASKS
  <id>  <status: queued|spec|tests|code|review|merging|done|parked>  <branch>  <round n/3>  <note>
OPEN QUESTIONS  <Q-n: one line>
DECISIONS       <D-n: one line, ASSUMED marked>
NEXT ACTION     <exactly one line>
```

If the master's context resets or compacts, its first act is to read `RUN_STATE.md` and `git worktree list`, then continue from NEXT ACTION. It never re-plans from scratch mid-run.

---

## 4. Phases

### Phase 1 — Spec (before any code)

1. For every task in the plan, the master checks that the SPEC row states every default, threshold, event field, and cap the task needs.
2. Every gap becomes one question, resolved now, not mid-build.
   - Default: 1 spec agent writes the proposal (option, numbers, false-positive risk, what the benign matrices need to stay silent).
   - Escalate to 2–3 independent spec agents only if the choice changes which alerts fire.
3. The master edits `docs/SPEC.md` and logs `D-<n> | <task> | decision | reason`. If the decision changes alerts and the human has not decided it, it is logged as `ASSUMED`, and the master picks the option that changes the fewest alerts.
4. The master builds the dependency graph: an edge for each engine dependency and each shared file. Writes it into RUN_STATE.

The build phase starts only when there are zero open questions for the first wave of tasks.

### Phase 2 — Build (pipelined)

The pipeline keeps all lanes busy: while the code agent works on task N, the test agent already writes tests for task N+1 (if it is independent).

#### 4.1 Task card

Written to `.autopilot/cards/<id>.json`, and the guard reads it from there:

```json
{
  "id": "T-07",
  "title": "beacon-jitter detector",
  "spec": ["§4.3", "row BJ-1"],
  "owns": {
    "tests": ["packages/core/test/detectors/beacon-jitter.test.js"],
    "code": ["packages/core/src/detectors/beacon-jitter.js"]
  },
  "contract": "exports, detector id, requires, defaults, event fields (copied from SPEC verbatim)",
  "done_when": "npm run check && node --test packages/core/test/detectors/beacon-jitter.test.js",
  "master_edits": ["registry line", "index.d.ts line", "CHANGELOG line"],
  "timebox_min": 45
}
```

No number in the contract may be absent from the SPEC. If it is, go back to Phase 1.

#### 4.2 Test agent

- Writes the tests from the card and SPEC only.
- **Standard five:**
  1. Fires on the attack.
  2. Silent on benign all-tier traffic.
  3. Hits its cap.
  4. Survives export → import.
  5. Boundary pair: just below threshold → silent, at threshold → fires.
- Hard rules also get "fires during learning".
- Deterministic: seeded PRNG, explicit timestamps. No `Date.now()`, `Math.random()`, `.only`, or `.skip`. The guard rejects them in test files.
- **Red must be the right red.** The agent reports each failing test with its failure message. Every failure must be an assertion failure, not `MODULE_NOT_FOUND`, a `SyntaxError`, or a timeout. For a missing module, it ships a stub export (owned by the code task) so the failures are real assertions.
- Commits tests on `wk/test/<id>`. The guard runs with `--role test`.

#### 4.3 Code agent

- Branches from the test branch. Implements until `done_when` is green, then runs `npm run check` and `node scripts/autopilot/guard.mjs --card <id> --role code`.
- Never edits a test. If a test contradicts the SPEC, it stops and reports the test name and the SPEC line. The master decides; only a test agent changes tests.
- **Retry ladder:**
  - Round 1: normal.
  - Round 2: the master sends the failing output and the current diff.
  - Round 3: a **fresh** code agent with the card plus failing output only, with no prior attempt in its context, to avoid anchoring on a wrong approach.
  - After round 3, or after the timebox runs out: park.

#### 4.4 Reviewer (cheap, catches what tests don't)

A fresh agent reads the card, the SPEC rows, and the diff. It has no history. It answers only:

1. Any threshold/default in code not present in SPEC?
2. Any event field read that the contract doesn't list?
3. Any hot-path allocation, unbounded collection, or per-event regex/JSON work?
4. Do the tests assert behavior (alert fields, counts), or just "something was returned"?

Each item gets PASS or FAIL with a file:line. Any FAIL goes back to the code agent as round feedback (it counts as a round). The reviewer cannot approve its own suggestions into the code.

#### 4.5 Test-strength check (master, before merge)

The master temporarily mutates the new detector: it inverts the main comparison, or returns no alerts, and runs the task's tests. **At least one test must fail.** If all pass, the tests are too weak, so the task goes back to the test agent. The master then reverts the mutation; it is never committed.

#### 4.6 Master merge

1. Guard both branches **before rebasing**: `guard.mjs --card <id> --role test` on `wk/test/<id>`, then `guard.mjs --card <id> --role code` on `wk/code/<id>` (it diffs against `wk/test/<id>` automatically).
2. Rebase the code branch onto `run/<name>`.
3. Fast check: `npm run check && node --test test/diff/dispatch.test.js`.
4. If green: `git merge --squash wk/code/<id>`, apply master edits (registry, `index.d.ts`, CHANGELOG) into the **same** staged change, then make exactly one commit `feat(<area>): <id> <title>`. Delete the branch and worktree, update RUN_STATE.
5. If red: send it back (counts as a round). Nothing is committed on `run/<name>`.

Never cherry-pick a worker commit and also merge its branch. That is what produces the duplicate task commits.

The master resolves every conflict, and never by taking the worker's side on a test, golden file, threshold, or budget.

### Phase 3 — Gate

```
export PATH="$HOME/.nvm/versions/node/v24.21.0/bin:$PATH"
npm run gate && npm run demo
node scripts/spec-coverage.mjs     # regenerates docs/DETECTORS.md
node scripts/autopilot/guard.mjs --verify-protected
node scripts/autopilot/guard.mjs --verify-history --base main
```

The gate runs **before** anything touches `main`. Every fix it forces is folded into its task commit with `--fixup` and autosquash, then the gate is re-run from the top. A "fix type errors found by typecheck" or "satisfy the quality gate" commit on top of a merge means this step was skipped.

1. Record bench numbers in `docs/BENCHMARKS.md`.
2. If any bench median regresses more than 10% versus the previous `BENCHMARKS.md` entry, the run finishes but the report flags it. The master does not loosen the budget.
3. If everything passes: merge `run/<name>` → `main` once, with `--no-ff`. Version bumps only if the plan says so.
4. Print the report (§7) to chat. It is never written to a file.
5. Erase the run: `node scripts/autopilot/guard.mjs --cleanup --run <name>`. It refuses unless HEAD is `main`, the tree is clean, and `run/<name>` is already merged. It then deletes:
   - every `wk/*` and `run/*` branch;
   - the worktrees under `.worktrees/`;
   - `.autopilot/` (except `protected.json`) and `docs/proposals/`;
   - the reflog entries and objects of the intermediate commits.

   Afterwards `main` holds only the task commits and the merge, with no record of which agent did what. This cannot be undone, which is why it runs last and never on a hard stop.

`docs/DECISIONS.md` and `docs/BENCHMARKS.md` are tracked product docs, not run logs, so they stay.

---

## 5. Parallel limits

- At most 3 code agents, 3 test agents, 1 reviewer, and spec agents per §4 Phase 1.
- Two tasks that touch the same file (including shared files via master edits) are serialized. The dependency graph says which.
- A task that depends on an engine change waits for that merge.
- A parked task is recorded as `PARKED: <reason>` and the run continues with the next independent task.

---

## 6. Hard stops (whole run stops)

1. A protected test (six prototype tests, nine acceptance tests, both benign matrices) or `test/diff` still fails after the retry ladder, and the only remaining fix edits that test or the golden.
2. Passing requires disabling a detector, lowering a severity, excluding a detector from a benign run, or loosening a bench budget.
3. `guard.mjs --verify-protected` fails at any point (a protected file changed), or `--verify-history` still fails after an autosquash.
4. Anything needs the network, `git push`, `npm publish`, `npm login`, or deleting the human's files.
5. More than 50% of planned tasks are parked: the plan itself is wrong, so stop and report instead of grinding.

On a hard stop: leave `run/<name>` as it is, set `PHASE hard-stop` in RUN_STATE, print the report, stop. Do not merge to `main`, and do not run `--cleanup`. The run state is what the human needs to resume.

---

## 7. Report (print this and nothing else)

```
AUTOPILOT REPORT
Run: <name>   Mode: <A|B>   Result: <merged to main | HARD STOP: one line>
Tasks: <done n> / <planned n>    Parked: <id: reason, one per line>
Rounds: <tasks green in round 1 / 2 / 3>    Review FAILs caught: <n>    Weak tests caught: <n>
Commits on main: <hash title, one per task>
Gate: tests N/N, lines %, branches %, bench median µs (Δ vs last), KB/device (7-day defaults)
Demo: <stages printed in the incident>
Thresholds/defaults changed: <none | list, before → after>
Decisions logged: <D-n one-liners, ASSUMED marked>
Next action for human: <one line>
```

The Rounds and caught-counts lines are for tuning: if most tasks need round 3, the cards or the SPEC are too vague, not the agents.
