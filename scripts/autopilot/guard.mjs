#!/usr/bin/env node
// scripts/autopilot/guard.mjs — mechanical enforcement for AUTOPILOT.md. No dependencies.
//
// Run start
//   --init --run <name> --version <x.y.z>   check .gitignore, install hook, snapshot protected files,
//                                           create run/<name> from main, write a RUN_STATE skeleton
// Phase 1 (spec)
//   --approve-spec --run <name>             PERSON ONLY, in a terminal: freeze docs/SPEC.md for this run
//   --verify-spec [--card <id>]             approval present and SPEC unchanged; no [PROPOSED] marks;
//                                           every card default appears in that card's SPEC rows
// Phases 3-5 (tests, code, review)
//   --card <id> --role test|code [--base <ref>]   ownership, banned test patterns, removed assertions
//   --mutate --card <id>                          every generated mutant must fail the card's done_when
// Phases 7-9 (gate, docs, squash)
//   --verify-protected                      no "never" file changed since --init
//   --verify-history --base <ref>           run/<name>: one clean commit per task, no noise
//   --verify-docs                           stale names, future versions, "not implemented" ids that
//                                           exist, generated catalog version
//   --verify-no-logs                        no run logs: .autopilot/ holds only guard state, no
//                                           docs/proposals/, no .log files
//   --squash --run <name> --version <v>     release/<v> = main + exactly one commit, same tree as run/<name>
//   --verify-release --version <v>          that one commit, package versions, lockfile, changelog
// Phase 10 (release, read-only)
//   --release-check --version <v>           list publish blockers and the person's push/merge/tag/publish order
// Phase 11
//   --cleanup --run <name> --version <v>    after release/<v> is merged into origin/main: erase the run
// Hook
//   --install-hooks | --commit-msg <file>
//
// This script never pushes, publishes, tags, or logs in. .autopilot/ is local state and must be gitignored.

import { execFileSync, execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  readFileSync,
  writeFileSync,
  existsSync,
  chmodSync,
  mkdirSync,
  readdirSync,
  rmSync,
  readSync,
} from 'node:fs';
import { join, resolve } from 'node:path';

const args = process.argv.slice(2);
const flag = (n) => args.includes(n);
const opt = (n, d) => {
  const i = args.indexOf(n);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : d;
};

// .autopilot/ is gitignored, so it exists only in the main checkout. Worker worktrees under
// .worktrees/ resolve it there through git's common dir.
const MAIN_ROOT = (() => {
  try {
    const common = execFileSync(
      'git',
      ['rev-parse', '--path-format=absolute', '--git-common-dir'],
      {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      },
    ).trim();
    return resolve(common, '..');
  } catch {
    return process.cwd();
  }
})();
const STATE = '.autopilot/';
const STATE_DIR = join(MAIN_ROOT, STATE);
const PROTECTED = join(STATE_DIR, 'protected.json');
const HASHES = join(STATE_DIR, 'protected.sha256');
const APPROVAL = join(STATE_DIR, 'spec-approved.json');
const RUN_STATE = join(STATE_DIR, 'RUN_STATE.md');
const CARDS = join(STATE_DIR, 'cards');
const SPEC = 'docs/SPEC.md';
const CORE_PKG = 'packages/core/package.json';
const DETECTORS_DIR = 'packages/core/src/detectors';
const REQUIRED_IGNORES = ['.autopilot/', '.worktrees/'];
// The only things .autopilot/ may hold (AUTOPILOT.md 1a). Everything about the run itself stays in memory.
const STATE_ALLOWED = new Set([
  'protected.json',
  'protected.sha256',
  'spec-approved.json',
  'RUN_STATE.md',
  'cards',
]);
const errors = [];

const git = (...a) =>
  execFileSync('git', a, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const gitOk = (...a) => {
  try {
    git(...a);
    return true;
  } catch {
    return false;
  }
};
const lines = (s) => s.split('\n').filter(Boolean);
const sha = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const die = (msg) => {
  console.error(`guard: ${msg}`);
  process.exit(2);
};
const loadJson = (p) => (existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : die(`missing ${p}`));
const readJsonAt = (ref, p) => JSON.parse(git('show', `${ref}:${p}`));
const need = (n) => opt(n) ?? die(`${n} <value> is required`);
const SEMVER = /^\d+\.\d+\.\d+$/;
const needVersion = () => {
  const v = need('--version');
  if (!SEMVER.test(v)) die(`--version must be x.y.z, got "${v}"`);
  return v;
};
const cmpVer = (a, b) => {
  const x = a.split('.').map(Number);
  const y = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
};
const branchExists = (b) => gitOk('rev-parse', '--verify', '--quiet', `refs/heads/${b}`);
const currentBranch = () => {
  try {
    return git('symbolic-ref', '--short', 'HEAD');
  } catch {
    return '';
  }
};
const cleanTree = () => !git('status', '--porcelain', '--untracked-files=no');

// Glob: "**/" matches zero or more directories, "**" anything, "*" one path segment.
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const segRe = (p) => p.split('*').map(esc).join('[^/]*');
const globRe = (g) =>
  new RegExp(
    '^' +
      g
        .split('**/')
        .map((part) => part.split('**').map(segRe).join('.*'))
        .join('(?:.*/)?') +
      '$',
  );
const matches = (f, p) => globRe(p).test(f);
const inAny = (f, ps) => ps.some((p) => matches(f, p));
const isTestFile = (f) => /(^|\/)test\/|\.test\.[cm]?[jt]s$/.test(f);

const loadCard = (id) => {
  if (!/^[\w.-]+$/.test(id)) die(`bad card id "${id}"`);
  const card = loadJson(`${CARDS}/${id}.json`);
  if (card.id !== id) die(`card file ${id}.json has id "${card.id}"`);
  return card;
};

// ---------------------------------------------------------------- commit-message policy
// run/* and main: task commits, the release commit, merges. release/<v>: exactly "release: <v>".
const TASK_RE = /^(feat|fix|perf|refactor|docs|test|chore)\([\w./-]+\): (T-\d+|#\d+) \S/;
const ALLOWED_RE = [TASK_RE, /^release: \d+\.\d+\.\d+$/, /^Merge /];
const NOISE_RE =
  /^(report|snapshot|wip|verify|spec: rev|checkpoint|fixup!|squash!|amend!|Revert ")/i;
function msgProblem(subject, branch = '') {
  if (branch.startsWith('release/')) {
    const want = `release: ${branch.slice('release/'.length)}`;
    return subject === want ? null : `release branch takes one commit "${want}", got "${subject}"`;
  }
  if (NOISE_RE.test(subject))
    return `bookkeeping/noise commit: "${subject}" (keep it in .autopilot/ or squash it)`;
  if (!ALLOWED_RE.some((re) => re.test(subject)))
    return `non-conforming subject: "${subject}" (want "feat(<area>): <T-n|#n> <title>")`;
  return null;
}
const taskId = (subject) => subject.match(TASK_RE)?.[2];

// ---------------------------------------------------------------- shared steps
function installHooks() {
  const dir = git('rev-parse', '--git-path', 'hooks');
  mkdirSync(dir, { recursive: true });
  const hook = join(dir, 'commit-msg');
  writeFileSync(
    hook,
    `#!/bin/sh\nexec node "$(git rev-parse --show-toplevel)/scripts/autopilot/guard.mjs" --commit-msg "$1"\n`,
  );
  chmodSync(hook, 0o755);
  console.log(`guard: installed ${hook}`);
}

function snapshot() {
  const prot = loadJson(PROTECTED);
  const out = prot.never.filter(existsSync).map((p) => `${sha(p)}  ${p}`);
  writeFileSync(HASHES, out.join('\n') + '\n');
  console.log(`guard: snapshot of ${out.length} protected files`);
}

function verifyProtected() {
  const prot = loadJson(PROTECTED);
  if (!existsSync(HASHES)) die(`missing ${HASHES} (run --init)`);
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
}

function verifyHistory(base, head = 'HEAD') {
  const commits = lines(
    git('log', '--first-parent', '--format=%H%x09%P%x09%s', `${base}..${head}`),
  );
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
    if (id && seenTask.has(id))
      errors.push(
        `${short} second commit for ${id} (first: ${seenTask.get(id)}). Fold fixes in with --fixup + autosquash`,
      );
    if (id && !seenTask.has(id)) seenTask.set(id, short);
  }
  return { commits: commits.length, tasks: seenTask.size };
}

function proposedLines(text) {
  return text
    .split('\n')
    .map((l, i) => [i + 1, l])
    .filter(([, l]) => /\[PROPOSED\b/.test(l));
}

function verifyApproval() {
  if (!existsSync(APPROVAL)) {
    errors.push('SPEC is not approved for this run (a person runs --approve-spec)');
    return;
  }
  const a = loadJson(APPROVAL);
  if (a.sha !== sha(SPEC))
    errors.push(
      `${SPEC} changed since approval at ${a.approvedAt}; build stops until a person re-approves`,
    );
}

// Card anchors: "### Heading" selects that section; any other string selects every SPEC line containing it.
function specHaystack(spec, anchors, cardId) {
  const L = spec.split('\n');
  const out = [];
  for (const a of anchors) {
    if (a.startsWith('#')) {
      const level = a.match(/^#+/)[0].length;
      const start = L.findIndex((l) => l.trim() === a.trim());
      if (start < 0) {
        errors.push(`${cardId}: SPEC anchor not found: ${a}`);
        continue;
      }
      const end = L.findIndex(
        (l, i) => i > start && /^#{1,6}\s/.test(l) && l.match(/^#+/)[0].length <= level,
      );
      out.push(...L.slice(start, end < 0 ? L.length : end));
    } else {
      const hit = L.filter((l) => l.includes(a));
      if (!hit.length) errors.push(`${cardId}: SPEC anchor not found: ${a}`);
      out.push(...hit);
    }
  }
  return out.join('\n');
}

function numberForms(n) {
  const s = String(n);
  if (!Number.isInteger(n)) return [s];
  const comma = n.toLocaleString('en-US');
  return [...new Set([s, comma, comma.replace(/,/g, ' ')])];
}

function checkCardNumbers(card, spec) {
  const anchors = card.spec ?? [];
  if (!anchors.length) {
    errors.push(`${card.id}: card.spec lists no SPEC anchors`);
    return;
  }
  const hay = specHaystack(spec, anchors, card.id);
  for (const [k, raw] of Object.entries(card.defaults ?? {})) {
    const entry = raw !== null && typeof raw === 'object' ? raw : { value: raw };
    if (typeof entry.value !== 'number' && entry.spec === undefined) continue;
    const forms = entry.spec !== undefined ? [String(entry.spec)] : numberForms(entry.value);
    const found = forms.some((f) => new RegExp(`(^|[^0-9.])${esc(f)}([^0-9]|$)`).test(hay));
    if (!found)
      errors.push(
        `${card.id}: default ${k}=${forms[0]} is not in its SPEC rows (${anchors.join(' | ')})`,
      );
  }
}

function verifyDocs() {
  const prot = existsSync(PROTECTED) ? loadJson(PROTECTED) : {};
  const cfg = prot.docs ?? {};
  const globs = cfg.files ?? ['README.md', 'docs/**/*.md', 'packages/*/README.md'];
  const files = lines(git('ls-files')).filter((f) => inAny(f, globs) && existsSync(f));
  const core = loadJson(CORE_PKG);
  const vre = new RegExp(`${esc(core.name)}@(\\d+\\.\\d+\\.\\d+)`, 'g');
  for (const f of files) {
    const L = readFileSync(f, 'utf8').split('\n');
    for (const s of cfg.staleNames ?? []) {
      if (inAny(f, s.allowIn ?? [])) continue;
      const re = new RegExp(`\\b${esc(s.name)}\\b`, 'i');
      L.forEach((l, i) => {
        if (re.test(l)) errors.push(`${f}:${i + 1} stale name "${s.name}"`);
      });
    }
    let notImplemented = false;
    L.forEach((l, i) => {
      for (const m of l.matchAll(vre))
        if (cmpVer(m[1], core.version) > 0)
          errors.push(`${f}:${i + 1} claims ${core.name}@${m[1]}; the package is ${core.version}`);
      if (/^#{1,6}\s/.test(l)) {
        notImplemented = /not (yet )?implemented/i.test(l);
        return;
      }
      if (!notImplemented) return;
      const m = l.match(/^\s*[-*]\s+`([a-z0-9]+(?:-[a-z0-9]+)+)`/);
      if (m && existsSync(join(DETECTORS_DIR, `${m[1]}.js`)))
        errors.push(
          `${f}:${i + 1} lists \`${m[1]}\` as not implemented; ${DETECTORS_DIR}/${m[1]}.js exists`,
        );
    });
  }
  for (const f of cfg.mustMentionVersion ?? []) {
    if (!existsSync(f)) errors.push(`missing ${f}`);
    else if (!readFileSync(f, 'utf8').includes(core.version))
      errors.push(`${f} does not mention the current core version ${core.version}`);
  }
  if (existsSync('docs/DETECTORS.md')) {
    const m = readFileSync('docs/DETECTORS.md', 'utf8').match(/Core (\d+\.\d+\.\d+)/);
    if (m && m[1] !== core.version)
      errors.push(
        `docs/DETECTORS.md was generated for core ${m[1]}; the package is ${core.version}. Re-run scripts/spec-coverage.mjs`,
      );
  }
}

function verifyNoLogs() {
  for (const f of existsSync(STATE_DIR) ? readdirSync(STATE_DIR) : [])
    if (!STATE_ALLOWED.has(f))
      errors.push(`${STATE}${f} is not guard state; run notes stay in memory (AUTOPILOT.md 1a)`);
  const cards = join(STATE_DIR, 'cards');
  for (const f of existsSync(cards) ? readdirSync(cards) : [])
    if (!f.endsWith('.json')) errors.push(`${STATE}cards/${f} is not a card`);
  if (existsSync(join(MAIN_ROOT, 'docs/proposals')))
    errors.push('docs/proposals/ exists; proposals stay in memory');
  const files = lines(git('-C', MAIN_ROOT, 'ls-files', '-co', '--exclude-standard'));
  for (const f of files) {
    if (!/\.log$/i.test(f)) continue;
    // Zeek and capture fixtures. They are inputs, not run logs (AUTOPILOT 1a).
    if (f.startsWith('eval/test/') || f.startsWith('eval/fixtures/')) continue;
    errors.push(`${f}: log file in the tree`);
  }
}

function verifyRelease(v) {
  const rel = `release/${v}`;
  if (!branchExists(rel)) {
    errors.push(`no branch ${rel} (run --squash)`);
    return;
  }
  if (!gitOk('merge-base', '--is-ancestor', 'main', rel))
    errors.push(
      `${rel} is not based on the current main; re-run --squash after rebasing the run branch`,
    );
  const n = lines(git('rev-list', `main..${rel}`)).length;
  if (n !== 1) errors.push(`${rel} has ${n} commits on top of main; want exactly 1`);
  const subject = git('log', '-1', '--format=%s', rel);
  if (subject !== `release: ${v}`)
    errors.push(`${rel} subject is "${subject}"; want "release: ${v}"`);
  if (
    /^Co-authored-by:.*\b(cursor|agent|bot|claude)\b/im.test(git('log', '-1', '--format=%b', rel))
  )
    errors.push(`${rel} carries an agent co-author trailer`);
  try {
    const coreV = readJsonAt(rel, CORE_PKG).version;
    if (coreV !== v) errors.push(`${CORE_PKG} on ${rel} is ${coreV}; want ${v}`);
  } catch {
    errors.push(`${CORE_PKG} missing on ${rel}`);
  }
  try {
    const lockV = readJsonAt(rel, 'package-lock.json').packages?.['packages/core']?.version;
    if (lockV !== v)
      errors.push(
        `package-lock.json has packages/core ${lockV}; want ${v} (npm install --package-lock-only)`,
      );
  } catch {
    errors.push(`package-lock.json missing on ${rel}`);
  }
  try {
    const cl = git('show', `${rel}:packages/core/CHANGELOG.md`);
    if (!new RegExp(`^##\\s*\\[?${esc(v)}\\]?`, 'm').test(cl))
      errors.push(`packages/core/CHANGELOG.md on ${rel} has no "## ${v}" entry`);
  } catch {
    errors.push(`packages/core/CHANGELOG.md missing on ${rel}`);
  }
  if (git('tag', '-l', `v${v}`)) errors.push(`tag v${v} already exists`);
}

function mutants(src) {
  const out = [];
  const fnRe = (name) => new RegExp(`\\b${name}\\s*\\([^)]*\\)\\s*\\{`);
  for (const name of ['check', 'onWindowClose']) {
    const m = src.match(fnRe(name));
    if (!m) continue;
    const at = m.index + m[0].length;
    out.push([`${name} returns nothing`, src.slice(0, at) + ' return undefined; ' + src.slice(at)]);
  }
  const flip = { '>': '<=', '>=': '<', '<': '>=', '<=': '>' };
  const start = Math.max(0, src.search(fnRe('check')));
  const re = /(\s)(>=|<=|>|<)(\s)/g;
  re.lastIndex = start;
  const m = re.exec(src);
  if (m) {
    const at = m.index + 1;
    out.push([
      `flip first "${m[2]}" after check`,
      src.slice(0, at) + flip[m[2]] + src.slice(at + m[2].length),
    ]);
  }
  return out;
}

function report(okMsg = 'guard: OK') {
  if (errors.length) {
    console.error(`guard: FAIL (${errors.length})\n  - ` + errors.join('\n  - '));
    process.exit(1);
  }
  console.log(okMsg);
  process.exit(0);
}

// ---------------------------------------------------------------- hook
if (flag('--install-hooks')) {
  installHooks();
  process.exit(0);
}

if (flag('--commit-msg')) {
  const branch = currentBranch();
  if (!branch) process.exit(0); // detached HEAD during a rebase: allow
  if (!/^(run\/|release\/|main$)/.test(branch)) process.exit(0); // wk/* is squashed away
  const msgFile = opt('--commit-msg');
  const msg = readFileSync(msgFile, 'utf8');
  const stripped = msg.replace(/^Co-authored-by:.*\b(cursor|agent|bot|claude)\b.*\n?/gim, '');
  if (stripped !== msg) writeFileSync(msgFile, stripped);
  const subject = stripped.split('\n')[0].trim();
  if (branch.startsWith('run/') && /^(fixup|amend)! /.test(subject)) process.exit(0);
  const p = msgProblem(subject, branch);
  if (p) {
    console.error(`guard: commit rejected on ${branch}: ${p}`);
    process.exit(1);
  }
  process.exit(0);
}

// ---------------------------------------------------------------- init
if (flag('--init')) {
  const run = need('--run');
  const v = needVersion();
  const ignored = existsSync('.gitignore')
    ? readFileSync('.gitignore', 'utf8')
        .split('\n')
        .map((s) => s.trim())
    : [];
  const missing = REQUIRED_IGNORES.filter((l) => !ignored.includes(l));
  if (missing.length)
    die(`.gitignore lacks ${missing.join(', ')}. A person adds and commits them first`);
  if (!cleanTree()) die('uncommitted changes; start from a clean main');
  if (!branchExists('main')) die('no local main branch');
  const coreV = loadJson(CORE_PKG).version;
  if (cmpVer(v, coreV) <= 0) die(`--version ${v} is not above the current core ${coreV}`);
  installHooks();
  snapshot();
  if (!branchExists(`run/${run}`)) git('branch', `run/${run}`, 'main');
  mkdirSync(CARDS, { recursive: true });
  rmSync(APPROVAL, { force: true });
  if (!existsSync(RUN_STATE))
    writeFileSync(
      RUN_STATE,
      [
        `RUN ${run}   VERSION ${v}   BASE ${git('rev-parse', '--short', 'main')}`,
        'PHASE spec',
        'SPEC APPROVED no',
        'TASKS',
        'OPEN QUESTIONS',
        'DECISIONS',
        'NEXT ACTION write the version scope into docs/SPEC.md',
        '',
      ].join('\n'),
    );
  console.log(`guard: run ${run} for ${v} initialised on run/${run}`);
  process.exit(0);
}

// ---------------------------------------------------------------- spec approval (person only)
if (flag('--approve-spec')) {
  const run = need('--run');
  if (!process.stdin.isTTY || !process.stdout.isTTY)
    die('--approve-spec must be run by a person in a terminal, not by an agent');
  const open = proposedLines(readFileSync(SPEC, 'utf8'));
  if (open.length)
    die(
      `SPEC still has ${open.length} [PROPOSED] mark(s). Accept, edit or delete each one:\n  ` +
        open.map(([n, l]) => `${SPEC}:${n} ${l.trim().slice(0, 100)}`).join('\n  '),
    );
  const h = sha(SPEC);
  process.stdout.write(`Approve ${SPEC} (sha ${h.slice(0, 12)}) for run ${run}? Type APPROVE: `);
  const buf = Buffer.alloc(1);
  let answer = '';
  for (;;) {
    let n;
    try {
      n = readSync(0, buf, 0, 1, null);
    } catch (e) {
      if (e.code === 'EAGAIN') continue;
      throw e;
    }
    if (!n || buf[0] === 10) break;
    answer += buf.toString();
  }
  if (answer.trim() !== 'APPROVE') die('not approved');
  writeFileSync(
    APPROVAL,
    JSON.stringify(
      { run, sha: h, approvedAt: new Date().toISOString(), by: process.env.USER ?? null },
      null,
      2,
    ) + '\n',
  );
  console.log(`guard: SPEC approved for run ${run}`);
  process.exit(0);
}

if (flag('--verify-spec')) {
  verifyApproval();
  const spec = readFileSync(SPEC, 'utf8');
  for (const [n, l] of proposedLines(spec))
    errors.push(`${SPEC}:${n} still [PROPOSED]: ${l.trim().slice(0, 80)}`);
  const id = opt('--card');
  const ids = id
    ? [id]
    : existsSync(CARDS)
      ? readdirSync(CARDS)
          .filter((f) => f.endsWith('.json'))
          .map((f) => f.slice(0, -5))
      : [];
  for (const c of ids) checkCardNumbers(loadCard(c), spec);
  report(`guard: spec OK (${ids.length} card(s) checked)`);
}

// ---------------------------------------------------------------- mutation check
if (flag('--mutate')) {
  const card = loadCard(need('--card'));
  if (!card.done_when) die(`${card.id}: card has no done_when`);
  const skip = new Set(card.mutantsSkip ?? []);
  const targets = (card.owns?.code ?? []).filter(
    (f) => !f.includes('*') && /\.[cm]?js$/.test(f) && existsSync(f),
  );
  if (!targets.length) die(`${card.id}: no code file to mutate`);
  for (const f of targets)
    if (git('status', '--porcelain', '--', f))
      die(`${f} has uncommitted changes; commit it on the code branch first`);
  const timeout = (card.timebox_min ?? 45) * 60e3;
  const passes = () => {
    try {
      execSync(card.done_when, { stdio: 'pipe', shell: '/bin/sh', timeout });
      return true;
    } catch {
      return false;
    }
  };
  const restore = () => targets.forEach((f) => gitOk('checkout', '--', f));
  process.on('SIGINT', () => {
    restore();
    process.exit(130);
  });
  if (!passes()) die(`${card.id}: done_when fails on the unmutated code; nothing to measure`);
  let killed = 0;
  let total = 0;
  try {
    for (const f of targets) {
      const src = readFileSync(f, 'utf8');
      for (const [label, mutant] of mutants(src)) {
        if (skip.has(label)) continue;
        total++;
        writeFileSync(f, mutant);
        const survived = passes();
        writeFileSync(f, src);
        if (survived)
          errors.push(`${f}: mutant "${label}" survived; the tests do not pin this behavior`);
        else killed++;
      }
    }
  } finally {
    restore();
  }
  if (!total)
    errors.push(`${card.id}: no mutant generated; the reviewer mutates by hand and records it`);
  report(`guard: mutants killed ${killed}/${total}`);
}

// ---------------------------------------------------------------- protected, history, docs
if (flag('--verify-protected')) {
  verifyProtected();
  report();
}

if (flag('--verify-history')) {
  const { commits, tasks } = verifyHistory(need('--base'));
  report(`guard: history OK (${commits} commits, ${tasks} tasks)`);
}

if (flag('--verify-no-logs')) {
  verifyNoLogs();
  report('guard: no run logs');
}

if (flag('--verify-docs')) {
  verifyDocs();
  report('guard: docs OK');
}

// ---------------------------------------------------------------- squash into one release commit
if (flag('--squash')) {
  const run = need('--run');
  const v = needVersion();
  const runBranch = `run/${run}`;
  const rel = `release/${v}`;
  if (!cleanTree()) die('uncommitted changes');
  if (!branchExists(runBranch)) die(`no branch ${runBranch}`);
  if (branchExists(rel)) die(`${rel} already exists; delete it first if this is a redo`);
  if (!gitOk('merge-base', '--is-ancestor', 'main', runBranch))
    die(`${runBranch} is not on top of main; rebase it and re-run the gate first`);
  verifyHistory('main', runBranch);
  verifyProtected();
  verifyApproval();
  verifyNoLogs();
  const coreV = readJsonAt(runBranch, CORE_PKG).version;
  if (coreV !== v) errors.push(`${CORE_PKG} on ${runBranch} is ${coreV}; want ${v}`);
  if (errors.length) report();
  const subjects = lines(
    git('log', '--reverse', '--first-parent', '--format=%s', `main..${runBranch}`),
  );
  if (!subjects.length) die(`${runBranch} has no commits on top of main`);
  git('checkout', '-b', rel, 'main');
  git('merge', '--squash', runBranch);
  const msgPath = join(STATE_DIR, 'release-msg.txt');
  writeFileSync(msgPath, `release: ${v}\n\n${subjects.map((s) => `- ${s}`).join('\n')}\n`);
  git('commit', '-F', msgPath);
  rmSync(msgPath, { force: true });
  if (git('rev-parse', `${rel}^{tree}`) !== git('rev-parse', `${runBranch}^{tree}`))
    errors.push(`${rel} tree differs from ${runBranch}`);
  verifyRelease(v);
  report(`guard: ${rel} holds one commit for ${subjects.length} task commit(s)`);
}

if (flag('--verify-release')) {
  verifyRelease(needVersion());
  report('guard: release branch OK');
}

// ---------------------------------------------------------------- release check (read-only)
if (flag('--release-check')) {
  const v = needVersion();
  verifyRelease(v);
  const blockers = errors.splice(0);
  for (const pj of lines(git('ls-files', 'packages/*/package.json'))) {
    const p = JSON.parse(readFileSync(pj, 'utf8'));
    if (p.private) continue;
    for (const k of ['repository', 'bugs', 'homepage', 'license'])
      if (!p[k]) blockers.push(`${pj}: no "${k}"`);
    if (p.dependencies && Object.keys(p.dependencies).length && pj === CORE_PKG)
      blockers.push(`${pj}: core has runtime dependencies`);
    const meta = JSON.stringify({ repository: p.repository, bugs: p.bugs, homepage: p.homepage });
    if (meta.includes('OWNER'))
      blockers.push(`${pj}: repository URL still uses the OWNER placeholder`);
  }
  const security = 'packages/core/SECURITY.md';
  if (!existsSync(security) || !/[\w.+-]+@[\w-]+\.[\w.-]+/.test(readFileSync(security, 'utf8')))
    blockers.push(`${security}: no disclosure email`);
  if (!gitOk('remote', 'get-url', 'origin')) blockers.push('no git remote "origin"');
  const wf = existsSync('.github/workflows')
    ? readdirSync('.github/workflows').map((f) =>
        readFileSync(join('.github/workflows', f), 'utf8'),
      )
    : [];
  if (!wf.some((t) => /id-token:\s*write/.test(t) && /npm publish/.test(t)))
    blockers.push(
      'no GitHub Actions workflow with "id-token: write" and "npm publish" (trusted publishing)',
    );
  const manual = [
    'USPTO and EUIPO search for "hubvik"',
    'npm org for the @hubvik scope exists',
    '2FA on the npm account',
  ];
  console.log(`guard: release check for ${v}`);
  if (blockers.length) console.log('BLOCKERS\n  - ' + blockers.join('\n  - '));
  console.log('MANUAL (cannot be checked here)\n  - ' + manual.join('\n  - '));
  console.log(
    [
      'ORDER (a person runs every step; this script runs none)',
      `  1. git push -u origin release/${v}`,
      `  2. open a PR release/${v} -> main; CI runs npm run gate; merge with "Create a merge commit"`,
      `  3. git fetch origin && git checkout main && git merge --ff-only origin/main`,
      `  4. git tag -s v${v} -m "v${v}" && git push origin v${v}`,
      '  5. the tag workflow publishes with provenance. First publish only: npm publish --provenance by hand, with 2FA',
      `  6. node scripts/autopilot/guard.mjs --cleanup --run <name> --version ${v}`,
    ].join('\n'),
  );
  process.exit(blockers.length ? 1 : 0);
}

// ---------------------------------------------------------------- cleanup
if (flag('--cleanup')) {
  const run = need('--run');
  const v = needVersion();
  const rel = `release/${v}`;
  const top = git('rev-parse', '--show-toplevel');
  if (!cleanTree()) die('uncommitted changes; nothing erased');
  if (/^(run|wk)\//.test(currentBranch())) die('check out main before cleanup');
  if (!branchExists(rel)) die(`no branch ${rel}; nothing erased`);
  if (!gitOk('rev-parse', '--verify', '--quiet', 'origin/main'))
    die('no origin/main; run git fetch first');
  if (!gitOk('merge-base', '--is-ancestor', rel, 'origin/main'))
    die(
      `${rel} is not merged into origin/main (fetch first; merge the PR with a merge commit). Nothing erased`,
    );
  if (
    branchExists(`run/${run}`) &&
    git('rev-parse', `${rel}^{tree}`) !== git('rev-parse', `run/${run}^{tree}`)
  )
    die(`${rel} tree differs from run/${run}; nothing erased`);

  const wtRoot = resolve(top, '.worktrees') + '/';
  for (const l of lines(git('worktree', 'list', '--porcelain')).filter((l) =>
    l.startsWith('worktree '),
  )) {
    const p = resolve(l.slice(9)) + '/';
    if (p.startsWith(wtRoot)) git('worktree', 'remove', '--force', p);
  }
  git('worktree', 'prune');
  const branches = lines(
    git('for-each-ref', '--format=%(refname:short)', 'refs/heads/wk/', 'refs/heads/run/'),
  );
  for (const b of branches) git('branch', '-D', b);
  if (currentBranch() !== rel) git('branch', '-D', rel);
  for (const f of existsSync(STATE_DIR) ? readdirSync(STATE_DIR) : [])
    if (f !== 'protected.json') rmSync(join(STATE_DIR, f), { recursive: true, force: true });
  for (const d of ['docs/proposals', '.worktrees'])
    rmSync(join(top, d), { recursive: true, force: true });
  git('reflog', 'expire', '--expire=now', '--expire-unreachable=now', '--all');
  git('gc', '--prune=now', '--quiet');
  console.log(
    `guard: run ${run} erased: ${branches.length + 1} branches, worktrees, run state, proposals, reflog`,
  );
  process.exit(0);
}

// ---------------------------------------------------------------- task branch
const id = opt('--card');
const role = opt('--role');
if (!id || !['test', 'code'].includes(role))
  die('unknown command. See the header of scripts/autopilot/guard.mjs for usage');

const prot = loadJson(PROTECTED);
const card = loadCard(id);
verifyApproval();
const base = opt('--base', role === 'code' ? `wk/test/${id}` : card.base);
if (!base) die('pass --base or set "base" (e.g. "run/<name>") in the card');

const changed = lines(git('diff', '--name-only', `${base}...HEAD`)).filter(
  (f) => !f.startsWith(STATE),
);
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
