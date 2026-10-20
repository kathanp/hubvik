#!/usr/bin/env node
// scripts/autopilot/guard.mjs — mechanical enforcement for AUTOPILOT v2. No dependencies.
//
//   --snapshot                          hash the "never" files (run start)
//   --verify-protected                  fail if any "never" file changed
//   --card <id> --role test             test branch vs its base (card.base, e.g. run/<name>)
//   --card <id> --role code             code branch vs wk/test/<id>. Run BEFORE rebasing.
//   --verify-history --base <ref>       commits in <ref>..HEAD: one clean commit per task, no noise
//   --install-hooks                     commit-msg hook: blocks noise commits on run/* and main
//   --commit-msg <file>                 (called by the hook; also strips agent co-author trailers)
//   --cleanup --run <name>              after a successful merge only: erase every trace of the run
//
// .autopilot/ is local state and must be in .gitignore. It is ignored by every check.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  readFileSync,
  writeFileSync,
  existsSync,
  chmodSync,
  mkdirSync,
  readdirSync,
  rmSync,
} from 'node:fs';
import { join, resolve } from 'node:path';

const args = process.argv.slice(2);
const flag = (n) => args.includes(n);
const opt = (n, d) => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : d;
};

const STATE = '.autopilot/';
const PROTECTED = '.autopilot/protected.json';
const HASHES = '.autopilot/protected.sha256';
const errors = [];

const git = (...a) => execFileSync('git', a, { encoding: 'utf8' }).trim();
const lines = (s) => s.split('\n').filter(Boolean);
const sha = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const die = (msg) => {
  console.error(`guard: ${msg}`);
  process.exit(2);
};
const loadJson = (p) => (existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : die(`missing ${p}`));

// "dir/**" matches anything under dir; otherwise exact path.
const matches = (f, p) => (p.endsWith('/**') ? f.startsWith(p.slice(0, -2)) : f === p);
const inAny = (f, ps) => ps.some((p) => matches(f, p));
const isTestFile = (f) => /(^|\/)test\/|\.test\.[cm]?[jt]s$/.test(f);

// ---- commit-message policy (shared by the hook and --verify-history) ----
// Allowed on run/* and main: one task commit, the phase-1 spec commit, the release commit, merges.
const TASK_RE = /^(feat|fix|perf|refactor|docs|test|chore)\([\w./-]+\): (T-\d+|#\d+) \S/;
const ALLOWED_RE = [
  TASK_RE,
  /^docs\(spec\): run \S+ decisions$/,
  /^release: \d+\.\d+\.\d+$/,
  /^Merge /,
];
const NOISE_RE =
  /^(report|snapshot|wip|verify|spec: rev|checkpoint|fixup!|squash!|amend!|Revert ")/i;
const msgProblem = (subject) => {
  if (NOISE_RE.test(subject))
    return `bookkeeping/noise commit: "${subject}" (keep it in .autopilot/ or squash it)`;
  if (!ALLOWED_RE.some((re) => re.test(subject)))
    return `non-conforming subject: "${subject}" (want "feat(<area>): <T-n|#n> <title>")`;
  return null;
};
const taskId = (subject) => subject.match(TASK_RE)?.[2];

// ---------------------------------------------------------------- hooks
if (flag('--install-hooks')) {
  const dir = git('rev-parse', '--git-path', 'hooks');
  mkdirSync(dir, { recursive: true });
  const hook = join(dir, 'commit-msg');
  writeFileSync(
    hook,
    `#!/bin/sh\nexec node "$(git rev-parse --show-toplevel)/scripts/autopilot/guard.mjs" --commit-msg "$1"\n`,
  );
  chmodSync(hook, 0o755);
  console.log(`guard: installed ${hook}`);
  process.exit(0);
}

if (flag('--commit-msg')) {
  let branch = '';
  try {
    branch = git('symbolic-ref', '--short', 'HEAD');
  } catch {
    process.exit(0);
  } // detached (rebase): allow
  if (!/^(run\/|main$)/.test(branch)) process.exit(0); // wk/* branches: anything goes, they get squashed
  const msgFile = opt('--commit-msg');
  const msg = readFileSync(msgFile, 'utf8');
  // No "who did what" on run/* or main: drop agent co-author trailers.
  const stripped = msg.replace(/^Co-authored-by:.*\b(cursor|agent|bot)\b.*\n?/gim, '');
  if (stripped !== msg) writeFileSync(msgFile, stripped);
  const subject = stripped.split('\n')[0].trim();
  // fixup!/amend! are allowed here (temporary); --verify-history fails until they are autosquashed.
  if (/^(fixup|amend)! /.test(subject)) process.exit(0);
  const p = msgProblem(subject);
  if (p) {
    console.error(`guard: commit rejected on ${branch}: ${p}`);
    process.exit(1);
  }
  process.exit(0);
}

// ---------------------------------------------------------------- cleanup
// Runs only on main, only when run/<name> is already merged. On a hard stop it refuses, so the state survives.
if (flag('--cleanup')) {
  const run = opt('--run') ?? die('--cleanup needs --run <name>');
  const top = git('rev-parse', '--show-toplevel');
  let branch = '';
  try {
    branch = git('symbolic-ref', '--short', 'HEAD');
  } catch {
    // Detached HEAD has no branch name; cleanup is main-only.
  }
  if (branch !== 'main') die('cleanup must run on main');
  if (git('status', '--porcelain', '--untracked-files=no'))
    die('uncommitted changes on main; nothing erased');
  try {
    git('merge-base', '--is-ancestor', `run/${run}`, 'main');
  } catch {
    die(`run/${run} is not merged into main; nothing erased (a hard stop keeps its state)`);
  }

  // 1. Worker worktrees (only ours, under .worktrees/; the human's other worktrees are untouched).
  const wtRoot = resolve(top, '.worktrees') + '/';
  for (const l of lines(git('worktree', 'list', '--porcelain')).filter((l) =>
    l.startsWith('worktree '),
  )) {
    const p = resolve(l.slice(9)) + '/';
    if (p.startsWith(wtRoot)) git('worktree', 'remove', '--force', p);
  }
  git('worktree', 'prune');
  // 2. Every run/* and wk/* branch.
  const branches = lines(
    git('for-each-ref', '--format=%(refname:short)', 'refs/heads/wk/', 'refs/heads/run/'),
  );
  for (const b of branches) git('branch', '-D', b);
  // 3. Local state. protected.json is config for the next run, so it stays.
  for (const f of existsSync(join(top, STATE)) ? readdirSync(join(top, STATE)) : [])
    if (f !== 'protected.json') rmSync(join(top, STATE, f), { recursive: true, force: true });
  for (const d of ['docs/proposals', '.worktrees'])
    rmSync(join(top, d), { recursive: true, force: true });
  // 4. Git's local record of the intermediate commits. Stash is left alone.
  git('reflog', 'expire', '--expire=now', '--expire-unreachable=now', 'HEAD', 'refs/heads/main');
  git('gc', '--prune=now', '--quiet');

  console.log(
    `guard: run ${run} erased: ${branches.length} branches, worktrees, run state, proposals, reflog`,
  );
  process.exit(0);
}

// ---------------------------------------------------------------- history
if (flag('--verify-history')) {
  const base = opt('--base') ?? die('--verify-history needs --base <ref>');
  const commits = lines(git('log', '--first-parent', '--format=%H%x09%P%x09%s', `${base}..HEAD`));
  const seenTask = new Map();
  const seenSubject = new Map();
  for (const c of commits) {
    const [h, parents, subject] = c.split('\t');
    const short = h.slice(0, 7);
    if (parents.split(' ').length > 1 && !/^Merge /.test(subject))
      errors.push(`${short} unexpected merge commit "${subject}"`);
    const p = msgProblem(subject);
    if (p) errors.push(`${short} ${p}`);
    if (seenSubject.has(subject))
      errors.push(`${short} duplicate of ${seenSubject.get(subject)}: "${subject}"`);
    seenSubject.set(subject, short);
    const id = taskId(subject);
    if (id && seenTask.has(id) && seenSubject.get(subject) === short)
      errors.push(
        `${short} second commit for ${id} (first: ${seenTask.get(id)}). Fold fixes in with --fixup + autosquash`,
      );
    if (id && !seenTask.has(id)) seenTask.set(id, short);
  }
  if (!errors.length)
    console.log(`guard: history OK (${commits.length} commits, ${seenTask.size} tasks)`);
  report();
}

// ---------------------------------------------------------------- protected
const prot = loadJson(PROTECTED);

if (flag('--snapshot')) {
  const out = prot.never.filter(existsSync).map((p) => `${sha(p)}  ${p}`);
  writeFileSync(HASHES, out.join('\n') + '\n');
  console.log(`guard: snapshot of ${out.length} protected files`);
  process.exit(0);
}

if (flag('--verify-protected')) {
  if (!existsSync(HASHES)) die(`missing ${HASHES} (run --snapshot at run start)`);
  const recorded = new Map(
    lines(readFileSync(HASHES, 'utf8')).map((l) => {
      const i = l.indexOf('  ');
      return [l.slice(i + 2), l.slice(0, i)];
    }),
  );
  for (const p of prot.never) {
    if (!existsSync(p)) errors.push(`protected file deleted: ${p}`);
    else if (recorded.get(p) !== sha(p)) errors.push(`protected file changed: ${p}`);
  }
  report();
}

// ---------------------------------------------------------------- task branch
const id = opt('--card');
const role = opt('--role');
if (!id || !['test', 'code'].includes(role))
  die(
    'usage: --snapshot | --verify-protected | --verify-history --base <ref> | --install-hooks | --card <id> --role test|code [--base <ref>]',
  );

const card = loadJson(`.autopilot/cards/${id}.json`);
// Code branches are cut from the test branch, so a code agent is judged only on its own commits.
const base = opt('--base', role === 'code' ? `wk/test/${id}` : card.base);
if (!base) die('pass --base or set "base" (e.g. "run/<name>") in the card');

const changed = lines(git('diff', '--name-only', `${base}...HEAD`)).filter(
  (f) => !f.startsWith(STATE),
);
// Test agents may also create the code stub (AUTOPILOT §4.2) so red failures are real assertions.
const owned = role === 'test' ? [...card.owns.tests, ...card.owns.code] : card.owns.code;

for (const f of changed) {
  if (inAny(f, prot.never)) errors.push(`touches never-edit file: ${f}`);
  else if (inAny(f, prot.masterOnly))
    errors.push(`touches master-only file: ${f} (put it in the report instead)`);
  else if (role === 'code' && isTestFile(f)) errors.push(`code agent edited a test: ${f}`);
  else if (!inAny(f, owned)) errors.push(`outside card ownership (${role}): ${f}`);
}

const banned = [
  [/\bDate\.now\s*\(/, 'Date.now()'],
  [/\bMath\.random\s*\(/, 'Math.random()'],
  [/\.(only|skip)\s*\(|\{\s*(only|skip)\s*:\s*true/, '.only/.skip'],
  [/\btodo\s*:\s*true|\.todo\s*\(/, 'todo test'],
];
for (const f of changed.filter((f) => isTestFile(f) && existsSync(f))) {
  const diff = lines(git('diff', '-U0', `${base}...HEAD`, '--', f));
  for (const l of diff.filter((l) => l.startsWith('+') && !l.startsWith('+++')))
    for (const [re, name] of banned)
      if (re.test(l)) errors.push(`${name} in ${f}: ${l.slice(1).trim().slice(0, 80)}`);
  const removed = diff.filter(
    (l) => l.startsWith('-') && !l.startsWith('---') && /assert|expect\(/.test(l),
  );
  if (removed.length) errors.push(`${removed.length} assertion line(s) removed in ${f}`);
}

report();

function report() {
  if (errors.length) {
    console.error(`guard: FAIL (${errors.length})\n  - ` + errors.join('\n  - '));
    process.exit(1);
  }
  if (!flag('--verify-history')) console.log('guard: OK');
  process.exit(0);
}
