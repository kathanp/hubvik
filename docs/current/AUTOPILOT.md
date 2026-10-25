# AUTOPILOT — full-cycle run playbook

Local only (`.gitignore`), never pushed. One run produces one version. The master reads this file, then `docs/RULES.md`, `CONTRIBUTING.md`, and `docs/SPEC.md`. All of them apply in full. The master chooses the next `x.y.z` and starts the run.

**Next version.** Read `packages/core/package.json` and the unfinished spec. A fix to behavior that is already specified is a patch. A large new behavior that does not change an existing call is a minor version. A change to a public method, a removed method, or a default that changes which anomalies fire is a major version. The aim of every version is a large improvement: the strongest behavior the catalog does not already report.

**Size of the cycle.** The feature list is the catalog in the spec. There is no separate features file. When a cycle adds a feature or changes one that is already there, the upgrade is large. A small edit to one detector is not a version. The same cycle improves every package under `packages/` that is not already at the level of that version: `core`, `cli`, every adapter, every export, and `respond-nftables`. Each of those changes is real behavior, written in the spec first, report-only, with tests written before the code. The version number still follows the rules above.

**Cycle:** spec → design → tests → code → review → gate → docs → one local commit `release: x.y.z` → one push of the release branch and the tag → GitHub Actions runs `npm publish` → merge into main. If the npm website then shows the version as staged, the person clicks Approve there. That click is not a step in this playbook. Do not stop the run to ask for it. Do not run `npm publish` or `npm login` in the terminal.

**Principle:** every rule a script can check is checked by `scripts/autopilot/guard.mjs`. Prose is the fallback only when no check is possible. A green guard is required at every step that names one.

**Order is fixed:** tests are written from the SPEC before any code exists. Tests written after the code describe the code, so a wrong threshold passes them.

**The gate is `npm run gate`.** `npm run check` is lint, types, and tests. It does not run the API snapshot, the pack check, fuzz, or the bench. A green `npm run check` is not a reason to push. Before any push, `npm run gate` has to exit 0 on that same tree. Step 6's fast check does not replace step 7.

**Green means continue.** A local `npm run gate` that exits 0 is the signal to commit `release: x.y.z`, push `release/<x.y.z>` and tag `v<x.y.z>`, and merge into main once GitHub is green. Do not stop to ask. Do not run `npm publish` or `npm login`. The workflow publishes. The npm Approve button, if the version is staged, is clicked on the npm website and is not a stop in this run.

---

## 0. Launch modes (write the mode in RUN_STATE)

| Mode                 | How workers run                                                                                                                                                                 | Isolation                                                                                                                 |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **A — real workers** | Normal mode. One master. Many local subagents, each in its own worktree under `.worktrees/`, with only its card or brief as the prompt (Cursor CLI, or Claude Code `claude -p`) | Real: workers cannot see each other or the run history. The master is the only one that sees every result                 |
| **B — single agent** | One agent does every role in sequence. Used only when separate agents cannot be launched                                                                                        | Weak: it has seen the code. Compensate: all test cards in a batch are committed before any code task in that batch starts |

Workers never push. A per-step push is not allowed. The master pushes only at step 10: the release branch, the merge, and the tag. If the master cannot launch separate agents, it uses Mode B.

---

## 1. Roles

| Role         | Max at once                                                | Owns                                                                                            | Never does                                                                           |
| ------------ | ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Human        | —                                                          | The Approve button on the npm website, after the workflow has published                         | —                                                                                    |
| Master       | 1                                                          | Version choice, plan, cards, merges, shared files, the release commit, the step 10 push and tag | Write detector code or tests; run `npm publish` or `npm login` in the terminal       |
| Spec agent   | 3 per open question, plus 1 market subagent per version    | Its reply to the master, in memory                                                              | Write any file                                                                       |
| Design agent | 3 per task (smallest, lowest memory, largest new behavior) | Its reply to the master, in memory                                                              | Write any file; introduce a number                                                   |
| Test agent   | 1 per independent task                                     | Test paths in its card, plus the code stub                                                      | Edit `src/` beyond the stub, an existing assertion, a golden file                    |
| Code agent   | 1 per independent task                                     | Source paths named on its card                                                                  | Edit a test or a shared file; invent a threshold; edit a file the task does not name |
| Reviewer     | 1                                                          | Its reply to the master, in memory                                                              | Write any file                                                                       |
| Docs agent   | 1                                                          | Docs listed in `protected.json` `docs.files`                                                    | Edit code, tests, SPEC numbers                                                       |

Workers never talk to each other. A worker receives only its card or brief, `docs/RULES.md`, and the SPEC sections the card names.

### 1a. Communication: local channel only, no logs

- Workers and the master talk only over the local in-process channel: the subagent's reply, a `SendMessage`, or the stdout of a local headless agent. Nothing goes through files, GitHub, or any remote service.
- Spec proposals, design plans, and review verdicts exist only in the master's memory. The master copies the **result** into the place it belongs (the SPEC, the card, a fix round) and drops the rest.
- Nothing is saved about the run itself: no transcripts, no agent counts, no record of which agent did what, no timing, no rounds, no `.log` files. That holds until the docs sync, and the docs sync records only product facts (versions, numbers, decisions), never the run.
- `.autopilot/` holds only what the guard needs: `protected.json`, `protected.sha256`, `spec-approved.json`, `cards/`, `RUN_STATE.md`, and `gate-pass`. `gate-pass` holds the HEAD sha of a green step 7 gate and nothing else. `RUN_STATE.md` lists step, task status, push count, and next action, so a master that loses context can resume. It names no agent and counts none. Cleanup deletes it, including `gate-pass`.
- `node scripts/autopilot/guard.mjs --verify-no-logs` fails if `.autopilot/` holds anything else, if `docs/proposals/` exists, or if the tree holds a `.log` file. `gate-pass` is allowed. It runs in the gate.

---

## 2. Files the guard reads

`.autopilot/protected.json` (kept between runs):

```json
{
  "never": ["test/diff/golden.json", "packages/core/test/engine.test.js"],
  "masterOnly": [
    "docs/SPEC.md",
    "docs/DECISIONS.md",
    "docs/QUESTIONS.md",
    "docs/BENCHMARKS.md",
    "docs/DETECTORS.md",
    "**/CHANGELOG.md",
    "**/package.json",
    "package-lock.json",
    "packages/core/src/detectors/index.js",
    "packages/core/src/index.d.ts",
    "packages/core/src/data/attack-map.json",
    "packages/core/src/data/stages.json"
  ],
  "docs": {
    "files": ["README.md", "docs/**/*.md", "packages/*/README.md"],
    "staleNames": [
      { "name": "iotwarden", "allowIn": ["docs/adr/**", "docs/DECISIONS.md", "docs/SPEC.md"] }
    ],
    "mustMentionVersion": ["docs/DEVELOPERS.md"],
    "versioned": ["README.md", "docs/DEVELOPERS.md", "docs/OPERATIONS.md", "docs/ARCHITECTURE.md"],
    "apiDoc": "docs/DEVELOPERS.md"
  }
}
```

Other local state, all in `.autopilot/`: `protected.sha256`, `spec-approved.json`, `RUN_STATE.md`, `cards/<id>.json`, `gate-pass`. Nothing else (section 1a).

`.autopilot/` lives only in the main checkout (it is gitignored, so worktrees do not get a copy). The guard finds it through git's common directory, so every guard command works the same from the main checkout and from `.worktrees/<id>`.

---

## 3. Git model

```
main ──────────────────────────────●───────────●  (merge of the PR, on GitHub)
      \                           /
       run/<name>  T-1 ─ T-2 ─ T-3          local only, one commit per task
         \     \
          wk/test/<id>   wk/code/<id>       local worktrees, squashed away
                                     release/<x.y.z>  main + ONE commit "release: x.y.z"
```

- `run/<name>` keeps one commit per task during the run. That is what lets the master fix one task with `--fixup` and autosquash, or drop a broken task, without redoing the others.
- At the end, `--squash` builds `release/<x.y.z>` from main with **exactly one commit**, whose tree is byte-identical to `run/<name>`. That one commit is what goes to GitHub. Its body lists the task subjects.
- **Trade-off, accepted:** after `--cleanup`, the per-task history is gone. Bisect inside a version is not possible. If a version needs bisecting later, skip `--cleanup` and keep `run/<name>` locally.

The commit-msg hook (installed by `--init`):

- On `run/*`: `<type>(<area>): <T-n|#n> <title>`, merges, and `release: x.y.z`. `fixup!` and `amend!` are allowed temporarily; `--verify-history` fails until they are autosquashed.
- On `release/<v>`: only `release: <v>`.
- On `main`: task, release, and merge subjects only.
- `wk/*`: anything. Those commits are squashed away.
- Agent co-author trailers (`cursor`, `agent`, `bot`, `claude`) are stripped on `run/*`, `release/*`, and `main`.

---

## 3a. Run state (survives context loss)

`.autopilot/RUN_STATE.md` is the master's memory. The master rewrites the whole file after **every** state change.

```
RUN <name>   VERSION <x.y.z>   BASE <main sha>
PHASE <spec | approval | design | build | gate | docs | squash | release | done | hard-stop>
PUSHES <n>
SPEC APPROVED <no | yes sha>
TASKS
  <id>  <queued|design|tests|code|review|merging|done|parked>  <branch>  <note>
OPEN QUESTIONS  <Q-n: one line>
DECISIONS       <D-n: one line, PROPOSED or APPROVED>
NEXT ACTION     <exactly one line>
```

After a context reset, the master's first act is to read `RUN_STATE.md` and `git worktree list`, then continue from NEXT ACTION. It never re-plans from scratch mid-run.

---

## 3b. Push discipline (enforced by pre-push hook)

`--init` installs `.git/hooks/pre-push`. It refuses every push unless ALL hold:

1. The ref is `release/<x.y.z>` or tag `v<x.y.z>`. Every other branch is refused.
2. `.autopilot/gate-pass` holds the HEAD sha, written only by a green step 7 gate on that exact tree.
3. The push count in RUN_STATE for this version is 0. One push is allowed. A second push is refused.

**When CI fails on GitHub or a budget is exceeded:**

- Never push a fix commit. Never push to see if it passes.
- Reproduce locally: `npm run gate`. If it passes locally and fails in CI, stop. That is an environment difference, not a code bug. Report it to the human.
- Fix on `run/<name>` with `--fixup`, autosquash, re-run the full gate, re-run `--squash`.
- The repair stays local. The one allowed push has already been used, so the master does not push again. The human decides whether this version stops.
- A bench budget failure is fixed in the code or the task is parked. The budget is never raised.

The master sets `PUSHES` to 1 after that single push.

---

## 3c. Red results stay local

The code is made strong locally first. A red result is not fixed by pushing again.

| Where it fails                                             | What happens                                                                                                                                                                                                       |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Local test or local commit                                 | Fixed on the machine, before any push. Tests are written first. The code is retried up to three times (step 4). The full step 7 gate must be green, and `gate-pass` must hold that HEAD, before a push is allowed. |
| A subbranch (`run/<name>`, `wk/test/<id>`, `wk/code/<id>`) | The push is refused. Those branches stay local. Only `release/<x.y.z>` and its tag `v<x.y.z>` can be pushed, and only once.                                                                                        |
| GitHub push or npm publish, after that one push            | No second push. The run stops and the human is told. A repair can be made locally, and it stays local.                                                                                                             |

The one push happens only after the local gate is already green. If GitHub or npm is red anyway, that is the end of the version until the human decides.

---

## 4. Steps

### Step 0 — Start

The master chooses `x.y.z` by the rule at the top of this file, then a person confirms `.autopilot/` and `.worktrees/` are in `.gitignore` (once). Then:

```
node scripts/autopilot/guard.mjs --init --run <name> --version <x.y.z>
```

This installs the hook, snapshots the protected files, creates `run/<name>` from main, clears any old approval, and writes the RUN_STATE skeleton. It refuses a dirty tree and a version that is not above the current core version. The state file keeps the field name `PHASE` because the guard writes that word. The work itself is these steps.

### Step 1 — Spec: the whole version is written into SPEC first

1. The master lists every task in the version scope and, for each, every default, threshold, event field, cap, and severity the task needs.
2. Anything the SPEC does not already state is an open question. Each question goes to three spec subagents in parallel, one per lane:
   - **threat lane:** what attack it catches, with a source line for Appendix B.
   - **false-positive lane:** which simulated classes and benign-matrix traffic would trip it, and the number that keeps them silent.
   - **budget lane:** memory per device on the 7-day line and µs per `feed()`.
     Each replies to the master with options, numbers, and risks. Nothing is written to a file. One lane is enough when the choice does not change which alerts fire.
     A fourth subagent lists behaviors current gateway products report that this catalog does not. The master adds one only when the gateway can see it from events the library already accepts, the library reports and does not block, and the behavior has a cap.
3. The master writes the large version into `docs/SPEC.md`. A number already approved stays. Every new or changed number is marked `[PROPOSED D-n]`. Each choice is logged in `docs/DECISIONS.md` as `D-n | <task> | decision | reason | PROPOSED`.
4. The master builds the dependency graph (engine dependencies and shared files) into RUN_STATE. A `[PROPOSED D-n]` mark stays in the spec. It does not pause the run, and the master does not ask for approval in chat.

The SPEC and DECISIONS edits are committed on `run/<name>` as `docs(spec): #0 run <name> decisions` before any worktree is created. Workers branch from `run/<name>`, so they must see that SPEC.

From here, **the SPEC is frozen** for the rest of the run. Every later guard step checks its hash. A needed SPEC change mid-run stops the build lanes and goes back through this step. A new `[PROPOSED D-n]` mark does not ask for approval in chat.

### Step 2 — Design

For each task, three design subagents reply in parallel:

- **smallest change:** fewest lines and files.
- **lowest memory:** lowest per-device state; names every structure that grows and its cap.
- **largest new behavior:** the strongest behavior the catalog does not already report. It names the cap and the test. It builds on `detectors/lib.js` and `engine/stats/` when those helpers already exist.

Each reply has numbered implementation steps, the state shape with caps, the events consumed, the test cases, and the risks. A design subagent does not introduce a number that is not in the approved SPEC.

The master keeps the largest new behavior when every number is already in the spec and the memory stays inside the budget, including the 2 KB/device budget for a new shadow detector (SPEC 0.5). It writes those steps into the card's `design` field. The other replies are dropped.

When that plan needs a new number, the master marks `[PROPOSED D-n]` and returns to step 1. It does not shrink the task to the smallest change.

When that plan does not fit in memory, the master keeps the behavior and lowers only the memory. If it still does not fit, the task is parked and the next-largest idea that fits is used.

The card must pass:

```
node scripts/autopilot/guard.mjs --verify-spec --card <id>
```

#### Task card (`.autopilot/cards/<id>.json`)

```json
{
  "id": "T-07",
  "version": "0.9.0",
  "title": "beacon-jitter detector",
  "base": "run/0.9-shadow",
  "spec": ["`beacon-jitter`", "### Defaults shipped in 0.9"],
  "design": "1. state: Map dst -> 16-bucket histogram, cap 64 LRU. 2. consume flow only. 3. ...",
  "owns": {
    "tests": ["packages/core/test/detectors/beacon-jitter.test.js"],
    "code": ["packages/core/src/detectors/beacon-jitter.js"]
  },
  "defaults": { "minCount": 30, "spanMs": { "value": 7200000, "spec": "2 h" } },
  "contract": "exports, id, requires, consumes, event fields (copied from SPEC verbatim)",
  "done_when": "npm run check && node --test packages/core/test/detectors/beacon-jitter.test.js",
  "master_edits": ["registry line", "index.d.ts line", "CHANGELOG line"],
  "mutantsSkip": [],
  "timebox_min": 45
}
```

- `spec` anchors: a string starting with `#` selects that SPEC section; any other string selects every SPEC line containing it.
- Every number in `defaults` must appear in those anchored lines. Use `{ "value", "spec" }` when the SPEC writes it differently ("2 h", "1 MB").

### Step 3 — Tests

- Tests come from the card and the SPEC only. The test agent never sees a design plan's code sketches.
- **Standard five:** fires on the attack; silent on the all-tier benign matrix; hits its cap; survives export → import; boundary pair (just below the threshold is silent, at the threshold fires). Hard rules also fire during learning.
- Deterministic: seeded PRNG, explicit timestamps. The guard rejects `Date.now()`, `Math.random()`, `.only`, `.skip`, `todo`.
- **Red for the right reason:** every failure is an assertion failure, not `MODULE_NOT_FOUND`, a `SyntaxError`, or a timeout. For a missing module, the test agent ships a stub export so the failures are real assertions.
- Commits on `wk/test/<id>`. Gate: `guard.mjs --card <id> --role test`.

### Step 4 — Code

- Branches from `wk/test/<id>`. Edits a file only when the task names it, and only until `done_when` is green. Then runs `npm run check` and `guard.mjs --card <id> --role code`.
- Does not walk old files looking for extra rewrites, and does not invent a threshold.
- Never edits a test. If a test contradicts the SPEC, the code agent stops and reports the test name and the SPEC line. The master decides. Only a test agent changes tests.
- **Retry ladder:** round 1 normal; round 2 with the failing output and the current diff; round 3 a **fresh** code agent with the card and the failing output only. After round 3, or past the timebox: park.

### Step 5 — Review and mutation

1. A fresh reviewer reads the card, the SPEC rows, and the diff, and answers PASS or FAIL with file:line for each:
   1. Any threshold or default in code that is not in the card's `defaults`?
   2. Any event field read that the contract does not list?
   3. Any hot-path allocation, unbounded collection, or per-event regex or JSON work?
   4. Do the tests assert behavior (alert fields, counts), not just "something returned"?
   5. Does the code meet section 4a (names, one job per function, JSDoc on every export, no commented-out code, no TODOs, helpers reused)?
      Any FAIL goes back to the code agent and counts as a round.
2. Mutation check, by the master, on the committed code branch:

   ```
   node scripts/autopilot/guard.mjs --mutate --card <id>
   ```

   The guard generates these mutants, runs `done_when` against each, and restores the file:

   | Mutant                                        | What it catches                                   |
   | --------------------------------------------- | ------------------------------------------------- |
   | each `defaults` value +1 and −1               | wrong threshold, any threshold not just the first |
   | each `<`↔`<=`, `>`↔`>=` in the detector       | off-by-one at every boundary                      |
   | each cap −1 and +1                            | cap not enforced, or enforced one late            |
   | LRU eviction removes newest instead of oldest | broken eviction                                   |
   | LRU eviction is a no-op                       | unbounded growth                                  |
   | `check` returns nothing                       | dead detector                                     |
   | `onWindowClose` returns nothing               | dead window logic                                 |
   | alert `severity` changed                      | tests that ignore severity                        |
   | one alert field dropped                       | tests that only assert "something fired"          |

   **Every mutant must fail.** A survivor sends the task back to the test agent, never to the code agent.
   - The boundary pair must be exact (threshold−1 silent, threshold fires), or the ±1 mutants survive. Time thresholds are tested to the millisecond.
   - Max 60 mutants per card. If more exist, defaults, comparisons, and caps run first.
   - A meaningless mutant goes into `mutantsSkip` with a one-line reason in DECISIONS. More than 3 skips on one card is a review FAIL.

### Step 6 — Merge the task into the run branch

1. Guard both branches **before rebasing**: `--card <id> --role test` on `wk/test/<id>`, then `--card <id> --role code` on `wk/code/<id>`.
2. Rebase the code branch onto `run/<name>`.
3. Fast check: `npm run check && node --test test/diff/dispatch.test.js`. This is not the gate. Do not push on it.
4. Green: `git merge --squash wk/code/<id>`, apply the master edits (registry, `index.d.ts`, CHANGELOG) into the **same** staged change, and make exactly one commit `feat(<area>): <id> <title>`. Delete the branch and worktree. Update RUN_STATE.
5. Red: send it back (counts as a round). Nothing is committed on `run/<name>`.

Never cherry-pick a worker commit and also merge its branch. The master resolves every conflict, and never by taking the worker's side on a test, a golden file, a threshold, or a budget.

### Step 7 — Gate (on `run/<name>`, before anything else)

```
export PATH="$HOME/.nvm/versions/node/v24.21.0/bin:$PATH"
npm run gate && npm run demo
node scripts/spec-coverage.mjs
node scripts/autopilot/guard.mjs --verify-spec
node scripts/autopilot/guard.mjs --verify-protected
node scripts/autopilot/guard.mjs --verify-history --base main
node scripts/autopilot/guard.mjs --verify-no-logs
```

- Every fix the gate forces is folded into its task commit with `git commit --fixup=<task sha>` and `git rebase -i --autosquash main`, then the gate runs again from the top.
- Record the bench numbers in `docs/BENCHMARKS.md`. A median regression over 10% versus the previous entry is flagged in the final summary. The budget is never loosened.
- When every command above exits 0, the master writes HEAD's full sha, and nothing else, to `.autopilot/gate-pass`. A later commit makes that file stale.
- The version bump is the last task of the run: `packages/core/package.json` to x.y.z, `npm install --package-lock-only`, the CHANGELOG `## x.y.z` entry, then the gate once more so the packed version matches. The master rewrites `gate-pass` after that last green gate.

### Step 8 — Docs sync

Every doc a reader or the next agent opens must match the tree at x.y.z. The docs agent works through this list and the guard checks it:

1. **Version on top.** Every file in `docs.versioned` (section 2) starts with a version line within its first 5 lines:
   `> Version: x.y.z · Updated: YYYY-MM-DD`
   The docs agent sets it to the new version and today's date.
2. **Root `README.md`:** status line, install line, feature list (every live detector group and every new option or method), the current version, and links to `docs/DEVELOPERS.md` and `docs/OPERATIONS.md`. Numbers only from `eval/results/` or `docs/BENCHMARKS.md`.
3. **Every package README** (`packages/*/README.md`) whose package changed in this run, except `packages/core`: version, what changed, usage example that still runs. `hubvik` uses the root `README.md`. Do not add `packages/core/README.md`.
4. **Every package CHANGELOG** whose package source changed in this run: a `## <its version>` entry at the top.
5. **`docs/DEVELOPERS.md`:** every public method, option, event, and warning code added in this run, with a short example.
6. **`docs/OPERATIONS.md`, `docs/ARCHITECTURE.md`:** any change in what the host must send, defaults, budgets, or module layout.
7. **Generated files:** re-run `node scripts/spec-coverage.mjs` so `docs/DETECTORS.md` matches.
8. **Dated records** (`docs/DECISIONS.md`, `docs/BENCHMARKS.md`) get a new entry; old entries are never rewritten. A rename never edits a dated record.

The changes go in one task commit `docs: sync to x.y.z`. Then:

```
node scripts/autopilot/guard.mjs --verify-docs --base main
```

It fails on:

- a doc in `docs.versioned` with no version line at the top, or a version other than the core version;
- a public name added to `packages/core/src/index.d.ts` in this run that `docs/DEVELOPERS.md` does not mention;
- a package whose `src/` changed in this run with no `## <version>` entry at the top of its CHANGELOG, or a changed package whose README does not mention its version;
- a stale name outside its allowed files, a doc that claims a future version, a "not implemented" bullet whose detector file exists, and a `docs/DETECTORS.md` generated for another version.

### Step 9 — One commit

```
node scripts/autopilot/guard.mjs --squash --run <name> --version <x.y.z>
```

It refuses unless the tree is clean, `run/<name>` sits on top of main, the history, protected files, and SPEC approval all pass, and core's version is x.y.z. It then creates `release/<x.y.z>` from main with one commit `release: x.y.z` (body: the task subjects), checks the tree equals `run/<name>`, and runs `--verify-release`. Nothing is pushed.

### Step 10 — Push the tag so GitHub publishes

```
node scripts/autopilot/guard.mjs --release-check --version <x.y.z>
```

It lists blockers (missing `repository` / `bugs` / `homepage`, no disclosure email in `SECURITY.md`, no `origin` remote, no trusted-publishing workflow, tag already exists) and the manual checks it cannot do (trademark search, npm org). A missing file or a red `npm run gate` stops the push. The npm website Approve button does not. The master does not run `npm publish` or `npm login` in the terminal.

The local `release: x.y.z` commit already exists from step 9. Nothing has been pushed yet.

1. One push only. It sends `release/<x.y.z>` and the tag `v<x.y.z>` together. There is no second push.
2. The tag starts the GitHub publish workflow, which runs `npm publish`. Cursor does not wait. If npm shows the version as staged, the person clicks Approve on the npm website.
3. Merge into main only after both are green. Use **"Create a merge commit"** (the branch is already one commit; a GitHub squash changes the hash and breaks `--cleanup`). Then fast-forward local main.
4. Do not merge while either GitHub workflow is red or still running. Do not push a fix to make one of them green.

### Step 11 — Cleanup

```
node scripts/autopilot/guard.mjs --cleanup --run <name> --version <x.y.z>
```

It refuses unless the tree is clean, `release/<x.y.z>` is merged into `origin/main` (fetch first), and its tree equals `run/<name>`. It then deletes every `wk/*` and `run/*` branch, the merged local `release/<x.y.z>` branch, the worktrees under `.worktrees/`, `.autopilot/` except `protected.json`, and the reflog. This cannot be undone. It never runs on a hard stop.

---

## 4a. Code must read clearly

Checked by `npm run lint` inside `npm run check` (ESLint, zero warnings allowed):

| Rule                  | Limit                                                          |
| --------------------- | -------------------------------------------------------------- |
| function length       | ≤ 40 lines                                                     |
| file length           | ≤ 300 lines                                                    |
| cyclomatic complexity | ≤ 10                                                           |
| nesting depth         | ≤ 3                                                            |
| parameters            | ≤ 4 (else one options object)                                  |
| nested ternary        | banned                                                         |
| magic numbers         | banned; every number comes from `defaults` or a named constant |
| unused vars / exports | banned                                                         |

Not checkable by script. Reviewer question 5, PASS or FAIL with file:line:

- Names say what a thing is (`spanMs`, `peerCount`), not `x`, `tmp`, `data2`.
- One function does one job. Early returns over deep `if`.
- Every exported function has a JSDoc line: what it takes, what it returns, what state it touches.
- No commented-out code, no TODOs.
- Reuses `detectors/lib.js` and `engine/stats/` helpers instead of re-writing them.

A lint failure is a code-agent round like any other. The code agent never adds `eslint-disable`.

---

## 5. Parallel limits

- Spec lanes: 3 per question, plus one market subagent for the version. Design: one subagent for each of the three replies on a task. Test and code: one subagent per independent task. Reviewer: 1. Docs agent: 1.
- Two tasks that touch the same file, including shared files through master edits, wait. The dependency graph says which.
- A task that depends on an engine change waits for that merge.
- Pipeline: while code agents work on task N, test agents may write tests for an independent task N+1.
- A parked task is recorded `PARKED: <reason>` and the run continues with the next independent task.

---

## 6. Hard stops (the whole run stops)

1. A protected test (the six prototype tests, the nine acceptance tests, both benign matrices) or `test/diff` still fails after the retry ladder, and the only remaining fix edits that test or the golden.
2. Passing requires disabling a detector, lowering a severity, excluding a detector from a benign run, or loosening a bench budget.
3. `--verify-protected` fails at any point, or `--verify-history` still fails after an autosquash.
4. The SPEC hash no longer matches the approval and the human is not available to re-approve.
5. A worker pushes, any agent runs `npm publish` or `npm login`, or someone deletes the human's files. The master's push and tag in step 10 are allowed.
6. More than 50% of planned tasks are parked. The plan is wrong. Stop.
7. CI fails twice on the same version, or any push is attempted outside step 10.

On a hard stop: leave `run/<name>` as it is, set PHASE `hard-stop`, print the summary, stop. Do not squash and do not run `--cleanup`.

Release blockers from `--release-check` are not hard stops. The run ends with `release/<x.y.z>` ready, and the blockers are the human's next action.

---

## 7. Final summary (print to chat; never written to a file)

Results only. No agent counts, lanes, rounds, or who did what.

```
AUTOPILOT
Version: <x.y.z>   Result: <release/x.y.z ready | HARD STOP: one line>
Tasks: <done n> / <planned n>    Parked: <id: reason, one per line>
Release commit: <hash> release: x.y.z
Gate: tests N/N, lines %, branches %, bench median µs (Δ vs last), KB/device (7-day defaults, shadow:true)
Demo: <stages printed in the incident>
Thresholds/defaults changed: <none | list, before → after>
Decisions approved: <D-n list>
Release blockers: <none | list from --release-check>
Next action for human: <the npm website Approve button, after the workflow publishes | one line>
```
