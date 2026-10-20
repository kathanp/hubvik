#!/usr/bin/env node
'use strict';

/**
 * Snapshot the public API of every publishable package under packages/.
 * Default mode compares each snapshot with api/<directory>.api.json and exits 1
 * when a file is missing or different. `--write` replaces those files and exits 0.
 */

import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const PACKAGES = join(ROOT, 'packages');
const API_DIR = join(ROOT, 'api');
const SKIP_EXPORTS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * @returns {void}
 */
function main() {
  const write = process.argv.slice(2).includes('--write');
  const packages = publicPackages();
  if (write) mkdirSync(API_DIR, { recursive: true });
  let failed = false;
  for (const row of packages) {
    const text = `${JSON.stringify(snapshotPackage(row), null, 2)}\n`;
    const out = join(API_DIR, `${row.dirName}.api.json`);
    if (write) {
      writeFileSync(out, text);
      console.log(`${row.dirName}: wrote`);
      continue;
    }
    const differs = !existsSync(out) || readFileSync(out, 'utf8') !== text;
    console.log(`${row.dirName}: ${differs ? 'diff' : 'ok'}`);
    if (differs) failed = true;
  }
  if (failed) process.exit(1);
}

/**
 * Directories under packages/ whose package.json is not private.
 * @returns {{ dirName: string, abs: string, pkg: { name?: string, main?: string, private?: boolean } }[]}
 */
function publicPackages() {
  return readdirSync(PACKAGES)
    .filter((name) => {
      const abs = join(PACKAGES, name);
      return statSync(abs).isDirectory() && existsSync(join(abs, 'package.json'));
    })
    .sort()
    .map((dirName) => {
      const abs = join(PACKAGES, dirName);
      const pkg = JSON.parse(readFileSync(join(abs, 'package.json'), 'utf8'));
      return { dirName, abs, pkg };
    })
    .filter((row) => row.pkg.private !== true);
}

/**
 * @param {{ dirName: string, abs: string, pkg: { name?: string, main?: string } }} row
 * @returns {{ name: string, exports: string[], methods: Record<string, string[]>, dts: string }}
 */
function snapshotPackage(row) {
  const name = row.pkg.name;
  if (typeof name !== 'string' || name.length === 0) {
    throw new TypeError(`${row.dirName} package.json is missing name`);
  }
  const main =
    typeof row.pkg.main === 'string' && row.pkg.main.length > 0 ? row.pkg.main : './src/index.js';
  const require = createRequire(join(row.abs, 'package.json'));
  const loaded = require(main);
  if (loaded == null || (typeof loaded !== 'object' && typeof loaded !== 'function')) {
    throw new TypeError(`${row.dirName} main export is not an object`);
  }
  const exports = Object.keys(loaded)
    .filter((key) => !SKIP_EXPORTS.has(key))
    .sort();
  /** @type {Record<string, string[]>} */
  const methods = {};
  for (const key of exports) {
    const value = loaded[key];
    if (typeof value === 'function') methods[key] = prototypeMethods(value);
    else if (isPlainObject(value)) methods[key] = [];
  }
  return { name, exports, methods, dts: declarationText(row.abs) };
}

/**
 * Own prototype methods, excluding constructor.
 * @param {Function} fn
 * @returns {string[]}
 */
function prototypeMethods(fn) {
  const proto = fn.prototype;
  if (proto == null) return [];
  /** @type {string[]} */
  const names = [];
  for (const name of Object.getOwnPropertyNames(proto)) {
    if (name === 'constructor') continue;
    const desc = Object.getOwnPropertyDescriptor(proto, name);
    if (desc && typeof desc.value === 'function') names.push(name);
  }
  names.sort();
  return names;
}

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Comment-stripped src/index.d.ts, or an empty string when the file is absent.
 * @param {string} packageDir
 * @returns {string}
 */
function declarationText(packageDir) {
  const path = join(packageDir, 'src/index.d.ts');
  if (!existsSync(path)) return '';
  return stripComments(readFileSync(path, 'utf8'));
}

/**
 * Remove block and line comments. Text inside strings is kept.
 * The result is the remaining source text.
 * @param {string} source
 * @returns {string}
 */
function stripComments(source) {
  /** @type {string[]} */
  const out = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i];
    if (ch === "'" || ch === '"' || ch === '`') {
      i = copyString(source, i, out);
      continue;
    }
    if (ch === '/' && source[i + 1] === '/') {
      i += 2;
      while (i < source.length && source[i] !== '\n' && source[i] !== '\r') i += 1;
      continue;
    }
    if (ch === '/' && source[i + 1] === '*') {
      i += 2;
      while (i < source.length && !(source[i] === '*' && source[i + 1] === '/')) i += 1;
      if (i < source.length) i += 2;
      continue;
    }
    out.push(ch);
    i += 1;
  }
  return out.join('');
}

/**
 * Copy one quoted string, including a template literal and its expressions.
 * @param {string} source
 * @param {number} i
 * @param {string[]} out
 * @returns {number}
 */
function copyString(source, i, out) {
  const quote = source[i];
  out.push(quote);
  i += 1;
  while (i < source.length) {
    const ch = source[i];
    if (ch === '\\') {
      out.push(ch);
      i += 1;
      if (i < source.length) {
        out.push(source[i]);
        i += 1;
      }
      continue;
    }
    if (quote === '`' && ch === '$' && source[i + 1] === '{') {
      out.push('${');
      i += 2;
      i = copyTemplateExpr(source, i, out);
      continue;
    }
    out.push(ch);
    i += 1;
    if (ch === quote) return i;
  }
  return i;
}

/**
 * Copy a template ${ expression }, stripping comments inside it.
 * @param {string} source
 * @param {number} i index of the first character inside the braces
 * @param {string[]} out
 * @returns {number}
 */
function copyTemplateExpr(source, i, out) {
  let depth = 1;
  while (i < source.length && depth > 0) {
    const ch = source[i];
    if (ch === "'" || ch === '"' || ch === '`') {
      i = copyString(source, i, out);
      continue;
    }
    if (ch === '/' && source[i + 1] === '/') {
      i += 2;
      while (i < source.length && source[i] !== '\n' && source[i] !== '\r') i += 1;
      continue;
    }
    if (ch === '/' && source[i + 1] === '*') {
      i += 2;
      while (i < source.length && !(source[i] === '*' && source[i + 1] === '/')) i += 1;
      if (i < source.length) i += 2;
      continue;
    }
    if (ch === '{') depth += 1;
    else if (ch === '}') depth -= 1;
    out.push(ch);
    i += 1;
  }
  return i;
}

main();
