'use strict';

const { parseArgs } = require('node:util');
const { readFileSync, writeFileSync } = require('node:fs');
const { checkRule, replay, doctor, reportHtml, diffBaseline, verifyBaseline } = require('./lib.js');

/**
 * @param {string[]} argv
 */
function main(argv) {
  const parsed = parseArgs({
    args: argv.slice(2),
    allowPositionals: true,
    options: {
      html: { type: 'string' },
      out: { type: 'string' },
      tiers: { type: 'string' },
      learn: { type: 'string' },
      lock: { type: 'boolean' },
      'key-file': { type: 'string' },
    },
  });
  const [command, sub, file] = parsed.positionals;
  if (command === 'rules' && sub === 'check') {
    const rules = JSON.parse(readFileSync(file, 'utf8'));
    const list = Array.isArray(rules) ? rules : [rules];
    const errors = list.flatMap((rule, index) => checkRule(rule, `$[${index}]`));
    process.stdout.write(errors.length ? `${errors.join('\n')}\n` : 'ok\n');
    return errors.length ? 1 : 0;
  }
  if (command === 'report') {
    const html = reportHtml(readFileSync(parsed.positionals[1], 'utf8'));
    if (parsed.values.html) writeFileSync(parsed.values.html, html);
    else process.stdout.write(html);
    return 0;
  }
  if (command === 'doctor') {
    let createEngine;
    try {
      createEngine = require('iotwarden').createEngine;
    } catch {
      process.stderr.write('iotwarden is not installed\n');
      return 1;
    }
    const report = doctor(readFileSync(sub, 'utf8'), {
      createEngine,
      tiers: parsed.values.tiers ? parsed.values.tiers.split(',') : undefined,
      learnMs: learnMs(parsed.values.learn),
    });
    process.stdout.write(`${JSON.stringify(report)}\n`);
    return 0;
  }
  if (command === 'replay') {
    let createEngine;
    try {
      createEngine = require('iotwarden').createEngine;
    } catch {
      process.stderr.write('iotwarden is not installed\n');
      return 1;
    }
    const rows = replay(readFileSync(sub, 'utf8'), {
      createEngine,
      tiers: parsed.values.tiers ? parsed.values.tiers.split(',') : ['T0'],
      learnMs: learnMs(parsed.values.learn),
      lock: parsed.values.lock === true,
    });
    const text = rows.map((row) => JSON.stringify(row)).join('\n');
    if (parsed.values.out) writeFileSync(parsed.values.out, text);
    else process.stdout.write(`${text}\n`);
    return 0;
  }
  if (command === 'baseline' && sub === 'verify') {
    const key = readFileSync(String(parsed.values['key-file'] || ''), 'utf8').trim();
    const ok = verifyBaseline(JSON.parse(readFileSync(file, 'utf8')), key);
    process.stdout.write(ok ? 'ok\n' : 'bad signature\n');
    return ok ? 0 : 1;
  }
  if (command === 'baseline' && sub === 'diff') {
    const changes = diffBaseline(
      JSON.parse(readFileSync(parsed.positionals[2], 'utf8')),
      JSON.parse(readFileSync(parsed.positionals[3], 'utf8')),
    );
    process.stdout.write(`${changes.join('\n')}\n`);
    return 0;
  }
  process.stderr.write('usage: iotwarden replay|report|doctor|baseline|rules\n');
  return 1;
}

/**
 * @param {string | boolean | undefined} text
 */
function learnMs(text) {
  if (typeof text !== 'string' || text.length === 0) return 0;
  const match = /^(\d+)(ms|s|m|h|d)$/.exec(text);
  if (!match) throw new TypeError('learn duration is invalid');
  const unit = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };
  return Number(match[1]) * unit[match[2]];
}

if (require.main === module) process.exit(main(process.argv));

module.exports = { main };
