#!/usr/bin/env node
'use strict';

/**
 * Refresh packages/core/src/data/suffixes.json from the Public Suffix List.
 * Keeps multi-label ICANN suffixes only, so the package stays small.
 * https://publicsuffix.org/list/
 */

import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, '../packages/core/src/data/suffixes.json');
const URL = 'https://publicsuffix.org/list/public_suffix_list.dat';

const response = await fetch(URL);
if (!response.ok) throw new Error(`public suffix list HTTP ${response.status}`);
const text = await response.text();
const suffixes = [];
let icann = false;
for (const raw of text.split('\n')) {
  const line = raw.trim();
  if (line.startsWith('// ===BEGIN ICANN DOMAINS===')) icann = true;
  if (line.startsWith('// ===END ICANN DOMAINS===')) icann = false;
  if (!icann || !line || line.startsWith('//')) continue;
  if (line.includes('*') || line.startsWith('!') || !line.includes('.')) continue;
  suffixes.push(line.toLowerCase());
}
suffixes.sort();
writeFileSync(OUT, `${JSON.stringify(suffixes, null, 2)}\n`);
console.log(`wrote ${suffixes.length} suffixes`);
