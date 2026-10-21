'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

/**
 * Files under a Zeek directory, or the file itself. Sorted, so the cache key is stable.
 * @param {string} source
 * @returns {string[]}
 */
function sourceFiles(source) {
  const stat = fs.statSync(source);
  if (stat.isFile()) return [source];
  /** @type {string[]} */
  const out = [];
  for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
    const full = path.join(source, entry.name);
    if (entry.isDirectory()) out.push(...sourceFiles(full));
    else if (entry.isFile()) out.push(full);
  }
  return out.sort();
}

/**
 * Identity of a parsed capture: joiner name, path, and each file's size and mtime.
 * @param {string} namespace
 * @param {string} source
 * @returns {string}
 */
function cacheKey(namespace, source) {
  const resolved = path.resolve(source);
  const hash = crypto.createHash('sha256');
  hash.update(namespace);
  hash.update('\0');
  hash.update(resolved);
  for (const file of sourceFiles(resolved)) {
    const stat = fs.statSync(file);
    hash.update('\0');
    hash.update(file);
    hash.update('\0');
    hash.update(String(stat.size));
    hash.update('\0');
    hash.update(String(stat.mtimeMs));
  }
  return hash.digest('hex');
}

/**
 * Return parsed rows from `eval/.cache/`, or run `loader` once and store them.
 * A sweep replays many points and must not parse the logs again.
 * @param {string} cacheDir
 * @param {string} namespace
 * @param {string} source
 * @param {() => { rows: object[], tiers: string[], dataset: string }} loader
 * @returns {{ rows: object[], tiers: string[], dataset: string }}
 */
function loadCached(cacheDir, namespace, source, loader) {
  const file = path.join(cacheDir, `${cacheKey(namespace, source)}.json`);
  if (fs.existsSync(file)) {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (parsed && Array.isArray(parsed.rows) && Array.isArray(parsed.tiers)) return parsed;
  }
  const loaded = loader();
  fs.mkdirSync(cacheDir, { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(loaded)}\n`);
  return loaded;
}

module.exports = { loadCached, cacheKey };
