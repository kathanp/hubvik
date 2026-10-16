#!/usr/bin/env node
'use strict';

/**
 * Check npm, scope, and GitHub availability for one or more package-name candidates.
 * Node built-ins only. Requires Node >= 22 (global fetch).
 *
 * Usage:
 *   node scripts/check-name.mjs [--github-user=<login>] <name> [name...]
 *
 * Verdicts:
 *   CLEAR    — exact name free, no punctuation clash, no same-brand hit in search
 *   CONFLICT — exact name taken, or an existing package differs only by - _ .
 *   RISKY    — name is free, but search shows an existing product using the same brand
 */

const USER_AGENT = 'cybershield-name-check (node)';
const PUNCT = /[-_.]/g;
const SUFFIXES = ['shield', 'warden', 'guard', 'watch', 'sensor', 'gateway', 'net'];

/**
 * @param {string[]} argv
 * @returns {{ githubUser: string | null, names: string[] }}
 */
function parseArgs(argv) {
  let githubUser = process.env.GITHUB_USER || process.env.GH_USER || null;
  const names = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--github-user') {
      githubUser = argv[++i] || githubUser;
    } else if (arg.startsWith('--github-user=')) {
      githubUser = arg.slice('--github-user='.length);
    } else if (arg.startsWith('-')) {
      throw new Error(`unknown flag: ${arg}`);
    } else {
      names.push(arg.toLowerCase());
    }
  }
  return { githubUser, names };
}

/**
 * Split a name into words so punctuation variants can be generated.
 * Existing - _ . are boundaries. A known suffix (shield, warden, …) is a boundary too.
 * @param {string} name
 * @returns {string[]}
 */
function wordParts(name) {
  const punctSplit = name.split(/[-_.]+/).filter(Boolean);
  if (punctSplit.length > 1) return punctSplit;
  for (const suffix of SUFFIXES) {
    if (name.endsWith(suffix) && name.length > suffix.length) {
      return [name.slice(0, -suffix.length), suffix];
    }
  }
  return [name];
}

/**
 * Exact name, punctuation-stripped form, and each - _ . insertion at word boundaries.
 * @param {string} name
 * @returns {string[]}
 */
function punctuationVariants(name) {
  const parts = wordParts(name);
  const out = new Set([name, name.replace(PUNCT, '')]);
  if (parts.length < 2) return [...out];

  const seps = ['', '-', '_', '.'];
  /**
   * @param {number} index
   * @param {string} acc
   */
  function walk(index, acc) {
    if (index === parts.length) {
      out.add(acc);
      return;
    }
    if (index === 0) {
      walk(1, parts[0]);
      return;
    }
    for (const sep of seps) walk(index + 1, acc + sep + parts[index]);
  }
  walk(0, '');
  return [...out];
}

/**
 * @param {string} name
 * @returns {string}
 */
function stripPunct(name) {
  return name.toLowerCase().replace(PUNCT, '');
}

/**
 * @param {string} url
 * @param {number} [attempt]
 * @returns {Promise<{ status: number, json: any, text: string }>}
 */
async function getJson(url, attempt = 0) {
  const res = await fetch(url, {
    headers: {
      accept: 'application/json',
      'user-agent': USER_AGENT,
    },
    redirect: 'follow',
  });
  if ((res.status === 429 || res.status >= 500) && attempt < 3) {
    const wait = 400 * (attempt + 1);
    await new Promise((r) => setTimeout(r, wait));
    return getJson(url, attempt + 1);
  }
  const text = await res.text();
  let json = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
  }
  return { status: res.status, json, text };
}

/**
 * @param {string} name
 * @returns {Promise<{ name: string, status: number, exists: boolean, description: string, error: string | null }>}
 */
async function lookupNpm(name) {
  const { status, json } = await getJson(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
  const exists = status === 200 && json && !json.error;
  return {
    name,
    status,
    exists,
    description: exists ? String(json.description || '') : '',
    error: status >= 400 && status !== 404 ? `HTTP ${status}` : null,
  };
}

/**
 * @param {string} name
 * @returns {Promise<{ name: string, description: string, maintainers: string }[]>}
 */
async function searchNpm(name) {
  const url = `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(name)}&size=20`;
  const { status, json } = await getJson(url);
  if (status !== 200 || !json || !Array.isArray(json.objects)) {
    throw new Error(`npm search failed for ${name}: HTTP ${status}`);
  }
  return json.objects.map((obj) => {
    const pkg = obj.package || {};
    const maintainers = Array.isArray(pkg.maintainers)
      ? pkg.maintainers
          .map((m) => m.username || m.name || '')
          .filter(Boolean)
          .join(', ')
      : '';
    return {
      name: String(pkg.name || ''),
      description: String(pkg.description || ''),
      maintainers,
    };
  });
}

/**
 * @param {string} user
 * @param {string} name
 * @returns {Promise<{ status: number, exists: boolean, error: string | null }>}
 */
async function lookupGithub(user, name) {
  const { status, json } = await getJson(
    `https://api.github.com/repos/${encodeURIComponent(user)}/${encodeURIComponent(name)}`,
  );
  if (status === 404) return { status, exists: false, error: null };
  if (status === 200) return { status, exists: true, error: null };
  const msg = json && json.message ? String(json.message) : `HTTP ${status}`;
  return { status, exists: false, error: msg };
}

/**
 * @param {string[]} cells
 * @param {number[]} widths
 * @returns {string}
 */
function row(cells, widths) {
  return cells.map((cell, i) => String(cell).padEnd(widths[i])).join('  ');
}

/**
 * @param {string} name
 * @param {string | null} githubUser
 */
async function checkOne(name, githubUser) {
  const variants = punctuationVariants(name);
  const lookups = await Promise.all(variants.map((v) => lookupNpm(v)));
  const exact = lookups.find((hit) => hit.name === name) || lookups[0];
  const clashes = lookups.filter((hit) => hit.exists && hit.name !== name);
  const exactTaken = exact.exists;

  const [search, scope, github] = await Promise.all([
    searchNpm(name),
    lookupNpm(`@${name}/core`),
    githubUser ? lookupGithub(githubUser, name) : Promise.resolve(null),
  ]);

  const needle = stripPunct(name);
  const brandHits = search.filter((hit) => {
    const bare = hit.name.startsWith('@') ? hit.name.slice(hit.name.indexOf('/') + 1) : hit.name;
    return stripPunct(bare).includes(needle) || stripPunct(hit.name).includes(needle);
  });

  const punctFromSearch = brandHits.filter(
    (hit) => stripPunct(hit.name.replace(/^@[^/]+\//, '')) === needle && hit.name !== name,
  );

  let verdict = 'CLEAR';
  if (exactTaken || clashes.length > 0 || punctFromSearch.length > 0) verdict = 'CONFLICT';
  else if (brandHits.length > 0 || scope.exists) verdict = 'RISKY';

  return {
    name,
    verdict,
    exact,
    clashes,
    punctFromSearch,
    brandHits,
    scope,
    github,
    variants,
  };
}

/**
 * @param {Awaited<ReturnType<typeof checkOne>>} result
 * @param {string | null} githubUser
 */
function printResult(result, githubUser) {
  const { name, verdict, exact, brandHits, scope, github } = result;
  console.log('');
  console.log(`${name}  →  ${verdict}`);
  console.log('-'.repeat(72));

  const lines = [
    ['check', 'result', 'detail'],
    [
      'exact npm',
      exact.exists ? 'TAKEN' : exact.error ? 'ERROR' : 'free',
      exact.error || exact.description || `HTTP ${exact.status}`,
    ],
  ];
  if (result.clashes.length === 0 && result.punctFromSearch.length === 0) {
    lines.push([
      'punctuation',
      'none',
      result.variants.filter((v) => v !== name).join(', ') || '(no word boundary)',
    ]);
  } else {
    for (const clash of result.clashes) {
      lines.push(['punctuation', 'CLASH', `${clash.name} — ${clash.description}`]);
    }
    for (const clash of result.punctFromSearch) {
      if (!result.clashes.some((c) => c.name === clash.name)) {
        lines.push(['punctuation', 'CLASH', `${clash.name} — ${clash.description}`]);
      }
    }
  }
  lines.push([
    `@${name}/core`,
    scope.exists ? 'TAKEN' : scope.error ? 'ERROR' : 'free',
    scope.exists
      ? scope.description
      : 'org itself is not proven free — create it at https://www.npmjs.com/org/create',
  ]);
  if (!githubUser) {
    lines.push(['github', 'skipped', 'pass --github-user=<login>']);
  } else if (github && github.error) {
    lines.push(['github', 'ERROR', `${githubUser}/${name}: ${github.error}`]);
  } else if (github) {
    lines.push([
      'github',
      github.exists ? 'TAKEN' : 'free',
      `https://github.com/${githubUser}/${name}`,
    ]);
  }

  const widths = [14, 10, 64];
  console.log(row(lines[0], widths));
  console.log(
    row(
      lines[0].map((_, i) => '-'.repeat(widths[i])),
      widths,
    ),
  );
  for (const line of lines.slice(1)) console.log(row(line, widths));

  if (brandHits.length === 0) {
    console.log('');
    console.log('similar (name contains candidate): none');
  } else {
    console.log('');
    console.log('similar (name contains candidate):');
    for (const hit of brandHits) {
      const who = hit.maintainers ? ` [${hit.maintainers}]` : '';
      console.log(`  - ${hit.name}${who}`);
      if (hit.description) console.log(`      ${hit.description}`);
    }
  }
}

async function main() {
  const { githubUser, names } = parseArgs(process.argv.slice(2));
  if (names.length === 0) {
    console.error('usage: node scripts/check-name.mjs [--github-user=<login>] <name> [name...]');
    process.exit(2);
  }

  console.log(
    `npm name check — ${names.length} candidate(s)${githubUser ? `, github user ${githubUser}` : ''}`,
  );

  /** @type {Awaited<ReturnType<typeof checkOne>>[]} */
  const results = [];
  for (const name of names) {
    results.push(await checkOne(name, githubUser));
  }

  for (const result of results) printResult(result, githubUser);

  console.log('');
  console.log('summary');
  console.log('-'.repeat(72));
  const widths = [20, 10];
  console.log(row(['candidate', 'verdict'], widths));
  console.log(row(['--------------------', '----------'], widths));
  for (const result of results) console.log(row([result.name, result.verdict], widths));

  console.log('');
  console.log('trademark (search by hand, not automated):');
  console.log('  USPTO  https://tmsearch.uspto.gov/');
  console.log('  EUIPO  https://euipo.europa.eu/eSearch/');
  for (const name of names) {
    console.log(`  search "${name}" on both before publishing`);
  }

  const bad = results.filter((r) => r.exact.error || r.scope.error || (r.github && r.github.error));
  if (bad.length > 0) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
});
