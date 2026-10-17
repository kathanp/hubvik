# AUTOPILOT — long unattended run (WP-2 finish → WP-8 + WP-10, release 0.5.0)

**First action:** save this whole message, unchanged, to `docs/AUTOPILOT.md` and commit it as `chore: add autopilot plan`. Then read `docs/SPEC.md` and execute this file from the first unticked box to the end. Do not stop between work packages. In chat, print only the final report from Section 5.

You are the coding agent for `iotwarden`. The human does not read code and will not answer questions during this run. **This file overrides the "stop after each WP" rule in `docs/SPEC.md` Part E for this run only.** Everything else in SPEC.md and the standing rules still applies.

Save this file as `docs/AUTOPILOT.md`. Tick each box (`[ ]` → `[x]`) as you finish it and commit the tick. If your session is interrupted, the human will say "continue docs/AUTOPILOT.md". Then resume at the first unticked box.

---

## 1. Operating rules for this run

1. **Do not stop between work packages.** Finish one, commit it, and start the next.
2. **Do not stop for a question that Section 2 already answers.** Apply the decision. Write one line in `docs/DECISIONS.md`: `D-<n> | WP | decision | reason`.
3. **New question not covered here:** pick the option that changes the fewest alerts, the most conservative one. Log it in `docs/DECISIONS.md` as `ASSUMED`. Keep going.
4. **Stop only for a HARD STOP:**
   - A protected test (the six in `packages/core/test/engine.test.js`, the nine acceptance tests, both benign matrices) still fails after **3** honest fix attempts, and the only remaining fix would edit that test.
   - Passing would require disabling a detector, lowering a severity, or excluding a detector from a benign run.
   - Any action needs network publish, `git push`, npm login, or deleting user files.

   On a HARD STOP: commit the work in progress on a branch `wip/<wp>`, write the report from Section 5, and stop.
5. **Never edit an assertion to make it pass. Never edit timestamps in an existing test to hide a behavior change.**
6. **Local commits are allowed.** Use one commit per WP, with message `feat: WP-<n> <title>`. **No push. No publish.**
7. **Checks:**
   - After each WP, run the **fast check**: `npm run check`.
   - Run the **full gate** only at checkpoints A and B, below:
     ```
     export PATH="$HOME/.nvm/versions/node/v24.21.0/bin:$PATH"
     npm run gate && npm run demo
     ```
   - If a fast check fails, fix it before moving on. Never carry a red check into the next WP.
8. Write `docs/progress/WP-<n>.md` for each WP. Keep it short: what changed, tests added, the tail of the fast-check output (last 15 lines), and any threshold changes, before and after.
9. Follow the zero-runtime-dependency rule. Do not use `Date.now()` or `Math.random()` in tests. Do not compute JA4. Do not bundle threat feeds. Do not write invented metrics in the README.

---

## 2. Decisions (binding; also copy each into `docs/QUESTIONS.md` as "RESOLVED")

**Q-6 (blocking): what `flush()` with no argument closes.**
- `flush()` with **no argument** means **end-of-input drain**. It closes every open window whose **start ≤ watermark**, including the window that contains the watermark. Then it calls `tick(watermark)`.
- `flush(now)` with an explicit `now` closes only windows whose **end ≤ now** (A4 rule, unchanged).
- A live host should call `flush(now)` or `tick(now)` from a timer, never a bare `flush()`. State this in `docs/DEVELOPERS.md` and the README.
- Events that arrive after a drain and fall into a closed window: `LATE_EVENT`, dropped.
- Update SPEC A2.3 and A4 to say this. Add a CHANGELOG line.
- Expected result: the "catches a volume spike" prototype passes unedited. The demo again shows `volume-spike`, `went-silent`, and the impact stage.

**Q-7 (new): in-window reordering.**
- The old engine accepted a backward step inside the current open window. Keep that behavior: **a backward step that stays inside the device's current open window is always accepted, whatever `reorderMs` is set to.**
- `reorderMs` only extends tolerance beyond that point.
- A backward step that is outside the open window and larger than `reorderMs` is `CLOCK_JUMP`.
- **Revert the timestamp edits made to `packages/core/test/phase4.test.js` in the uncommitted WP-2 tree.** Restore that file to its committed version (`git checkout -- packages/core/test/phase4.test.js`). It must pass as it was.
- Update SPEC A2.3.

**Q-1:** A moved threshold does not bump the version. Bump core to 0.5.0 only at the end of WP-8.

**Q-2:** `minLearnWindows` default stays `0`. Do not add per-class values in this run. Add one sentence to the docs: "500 suits devices with a steady heartbeat; leave at 0 for devices that can be idle for days, such as printers."

**Q-3:** `reorderMs` default stays `0` through all of 0.5. Examples that merge adapters set `5000`.

**Q-4:** `proxy-sdk-traffic` is `medium` on `smart-tv` and `tv-box` and `high` otherwise, as the spec says.

**Q-5:**
- The `smart-tv` upload cap stays at 50,000,000.
- **Bug to fix in WP-6:** B20 says `smart-tv` allows browser-class JA4, but `browser-mimic` hard-codes `tv-box`, `nas`, and `hub`. Replace the hard-coded list with a class-file flag, `allowsBrowserJa4: true`. Set it in `tv-box`, `nas`, `hub`, and `smart-tv`.
- Add a test showing that `smart-tv` with a browser JA4 stays silent and `camera` with a browser JA4 fires.

**Security email and repository URLs:** leave the existing placeholders. They do not block this run, so do not invent values. If `pack-check` fails on them, use the literal text `security contact: see repository` and log a decision.

---

## 3. Checklist

### WP-2 — Event time (finish the uncommitted tree)
- [ ] Apply Q-6 and Q-7. Restore `phase4.test.js` from git.
- [ ] Add tests for `flush()` drain: closes the watermark window; `flush(now)` does not close a window that is still open; an event after a drain into a closed window gives `LATE_EVENT`.
- [ ] Add a test that an in-window backward step with `reorderMs: 0` gives no `clock-jump`.
- [ ] Keep the WP-2 tests already written: `went-silent` via `tick()`, and the 2 s and 10 s skew tests.
- [ ] Fast check passes. The six prototype tests pass unedited. The demo shows the impact stage again.
- [ ] Write `docs/progress/WP-2.md` and commit.

### WP-3 — `tier-silent`, `SUSPICIOUS_LEARNING`, learning quality (D4, D5)
- [ ] Implement as in SPEC WP-3, B10, B11, and A4.1.
- [ ] Add one firing test per `SUSPICIOUS_LEARNING` reason. The benign matrices must emit no `SUSPICIOUS_LEARNING`.
- [ ] Add a test for `LOCKED_UNREVIEWED` and a test for `LEARNING_EXTENDED`.
- [ ] Fast check passes. Write the progress file and commit.

### WP-4 — Anomaly evidence, fingerprint, dedup (D6)
- [ ] Add the A7.1 fields, the C1 dedup rule, the `evidence: false` option, and `index.d.ts`.
- [ ] Add the done-when tests from SPEC WP-4.
- [ ] Fast check passes. Write the progress file and commit.

### ▶ CHECKPOINT A — full gate
- [ ] Run the full gate and the demo. Paste the tail into `docs/progress/CHECKPOINT-A.md`. If it fails, fix before continuing; up to 3 attempts, then HARD STOP.

### WP-5 — `identity-change`
- [ ] Add the `dhcp.fingerprint` field and the detector. Cap 5,000 MACs.
- [ ] Add the four standard tests.
- [ ] `spec-coverage` must no longer list `identity-change` as missing.
- [ ] Fast check passes. Write the progress file and commit.

### WP-6 — B20: `egress-flood`, `proxy-sdk-traffic`, `smart-tv`
- [ ] Add both detectors, the `proxy-sdk` indicator type, `packet-flood` `data.bytesPerPacket`, and `dedupGroup: 'flood'`.
- [ ] Fix `browser-mimic` with the class flag from Q-5.
- [ ] Add both replay tests from SPEC WP-6.
- [ ] The all-tier benign matrix still passes.
- [ ] Fast check passes. Write the progress file and commit.

### WP-7 — `checkpoint()` / `restore()` (D7)
- [ ] Implement as in SPEC A4.1. Include `identity-change` scratch.
- [ ] Add the ARP-after-restore test and the 1,000 corrupt-checkpoint test.
- [ ] Fast check passes. Write the progress file and commit.

### WP-8 — Hardening and release prep
- [ ] Add fuzz for feed, baseline, and checkpoint: 100,000 seeded inputs each.
- [ ] Run the bench with all tiers on. The x86 budget is median `feed()` < 10 µs and < 100 KB per device. If the bench misses the budget, **record the real number** in `docs/BENCHMARKS.md` and log a decision. Do not tune the bench to pass.
- [ ] `spec-coverage` passes with no 0.5 rows missing.
- [ ] Fast check passes. Write the progress file and commit.

### WP-10 — `export-ocsf` version option
- [ ] Add the `{ ocsfVersion }` option, default `'1.4.0'`, written into `metadata.version`. Apply the full C3 mapping table, including `fingerprint` → `finding_info.uid` and `evidence.sample` → `evidences[]` (omitted when `evidence: false`).
- [ ] Create a vendored fixture of the OCSF 1.4.0 Detection Finding required fields at `packages/export-ocsf/test/fixtures/`. Write it by hand from the spec's C3 table and the fields the exporter already emits. **Do not download anything.** Add a comment at the top of the fixture: `hand-written from SPEC C3; verify against schema.ocsf.io before 1.0`.
- [ ] Add tests: one anomaly and one escalated incident each validate against the fixture; `ocsfVersion: '1.6.0'` appears in `metadata.version`.
- [ ] Bump `export-ocsf` minor version and add a CHANGELOG line.
- [ ] Fast check passes. Write `docs/progress/WP-10.md` and commit.

### ▶ CHECKPOINT B — full gate, then version
- [ ] Run the full gate and the demo. Paste the tail into `docs/progress/CHECKPOINT-B.md`.
- [ ] If it passes: bump `packages/core` to `0.5.0`, add the CHANGELOG release section, and commit `release: core 0.5.0 (local, not published)`.
- [ ] If it fails: fix, up to 3 attempts, then HARD STOP. Do not bump the version.

---

## 4. Out of scope for this run
- WP-9 (eval harness). It needs the human's datasets and is the next run.
- Any new detector not named above.
- README detection numbers.
- git push, npm publish, GitHub setup.

---

## 5. Final report (print this in chat, nothing else, at the end or at a HARD STOP)

```
AUTOPILOT REPORT
Finished: WP-x … WP-y            Stopped at: <WP or "end">
Reason: <done | HARD STOP: one line>
Commits: <hash title> (one per line)
Checkpoint A: pass/fail — tests N/N, lines %, branches %
Checkpoint B: pass/fail — tests N/N, lines %, branches %, bench median µs, KB/device
Demo: <stages printed in the incident>
Thresholds/defaults changed: <none | list with before → after>
Decisions logged (ASSUMED only): <D-n one-liners>
Next action for human: <one line>
```
