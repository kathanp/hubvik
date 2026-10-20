'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { createEngine } = require('../src/index.js');
const { flow } = require('../../../test/fixtures/flow');

const RULES = join(__dirname, '../../../examples/rules');

/**
 * @param {string} name
 */
function rule(name) {
  return JSON.parse(readFileSync(join(RULES, name), 'utf8'));
}

/**
 * @param {any} engine
 * @param {string} id
 */
function listen(engine, id) {
  /** @type {any[]} */
  const hits = [];
  engine.on('anomaly', (row) => {
    if (row.detector === id) hits.push(row);
  });
  engine.on('shadow-anomaly', (row) => {
    if (row.detector === id) hits.push(row);
  });
  return hits;
}

test('a telnet scan rule fires on the same hosts as horizontal-scan', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T0', 'T1'] });
  engine.loadRules([rule('telnet-scan.json')]);
  const builtin = listen(engine, 'horizontal-scan');
  const custom = listen(engine, 'rule:telnet-scan');
  for (let i = 0; i < 21; i += 1) {
    engine.feed(flow({ ts: 1000 + i, dstPort: 23, dstIp: `9.9.0.${i}`, direction: 'out' }));
  }
  assert.equal(builtin.length > 0, true);
  assert.equal(custom.length, 1);
  assert.equal(custom[0].severity, 'critical');
});

test('an smtp rule fires on the same burst as spam-relay', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  engine.feed(flow({ ts: 1, dstPort: 443 }));
  const saved = engine.exportBaseline({ createdAt: 1 });
  saved.devices.d.detectors['spam-relay'].state = { learned: true };
  engine.importBaseline(saved);
  engine.loadRules([rule('smtp-relay.json')]);
  const builtin = listen(engine, 'spam-relay');
  const custom = listen(engine, 'rule:smtp-relay');
  for (let i = 0; i < 11; i += 1) {
    engine.feed(flow({ ts: 1000 + i * 1000, dstPort: 25, direction: 'out' }));
  }
  assert.equal(builtin.length, 1);
  assert.equal(custom.length, 1);
});

test('tftp, adb, and a dangerous OT op fire with the built-in detectors', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T0', 'T1', 'T5'] });
  engine.loadRules([rule('tftp-out.json'), rule('adb-in.json'), rule('ot-stop.json')]);
  const tftp = listen(engine, 'tftp-activity');
  const tftpRule = listen(engine, 'rule:tftp-out');
  const adb = listen(engine, 'adb-exposure');
  const adbRule = listen(engine, 'rule:adb-in');
  const ot = listen(engine, 'ot-dangerous-op');
  const otRule = listen(engine, 'rule:ot-stop');
  engine.feed(flow({ ts: 1000, proto: 'udp', dstPort: 69, direction: 'out', dstIp: '9.9.9.9' }));
  engine.feed(
    flow({
      ts: 2000,
      proto: 'tcp',
      dstPort: 5555,
      direction: 'in',
      srcIp: '1.2.3.4',
      dstIp: '10.0.0.8',
    }),
  );
  engine.feed({
    type: 'app',
    device: 'd',
    ts: 3000,
    proto: 'bacnet',
    role: 'client',
    peerIp: '10.0.0.9',
    op: 'STOP',
  });
  assert.equal(tftp.length, 1);
  assert.equal(tftpRule.length, 1);
  assert.equal(adb.length, 1);
  assert.equal(adbRule.length, 1);
  assert.equal(ot.length, 1);
  assert.equal(otRule.length, 1);
});

test('loadRules keeps the previous set when a later rule is invalid', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  engine.loadRules([rule('tftp-out.json')]);
  assert.throws(
    () =>
      engine.loadRules([
        { id: 'bad', severity: 'high', on: 'flow', where: { dstPort: { regex: 'x' } } },
      ]),
    /invalid/,
  );
  const hits = listen(engine, 'rule:tftp-out');
  engine.feed(flow({ ts: 1000, proto: 'udp', dstPort: 69, direction: 'out' }));
  assert.equal(hits.length, 1);
});

test('a sequence fires only when the later step is inside the window', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  engine.loadRules([
    {
      id: 'short-then-long',
      severity: 'high',
      by: 'srcIp',
      within: '10m',
      sequence: [
        { on: 'flow', where: { dstPort: { eq: 22 }, durationMs: { lte: 3000 } } },
        { on: 'flow', where: { dstPort: { eq: 22 }, durationMs: { gte: 60000 } } },
      ],
    },
  ]);
  const hits = listen(engine, 'rule:short-then-long');
  engine.feed(flow({ ts: 1000, dstPort: 22, direction: 'in', srcIp: '1.2.3.4', durationMs: 200 }));
  engine.feed(
    flow({
      ts: 1000 + 11 * 60 * 1000,
      dstPort: 22,
      direction: 'in',
      srcIp: '1.2.3.4',
      durationMs: 60000,
    }),
  );
  assert.equal(hits.length, 0);
  engine.feed(
    flow({ ts: 2_000_000, dstPort: 22, direction: 'in', srcIp: '1.2.3.4', durationMs: 200 }),
  );
  engine.feed(
    flow({ ts: 2_100_000, dstPort: 22, direction: 'in', srcIp: '1.2.3.4', durationMs: 60000 }),
  );
  assert.equal(hits.length, 1);
});

test('baseline:true learns a port and alerts on a new one', () => {
  const engine = createEngine({ shadow: true, learnMs: 5000, tiers: ['T1'] });
  engine.loadRules([
    {
      id: 'new-in-port',
      severity: 'high',
      on: 'flow',
      window: '1m',
      where: { direction: { eq: 'in' }, dstPort: { baseline: true } },
    },
  ]);
  const hits = listen(engine, 'rule:new-in-port');
  engine.feed(
    flow({ ts: 1000, direction: 'in', dstPort: 80, srcIp: '1.2.3.4', dstIp: '10.0.0.8' }),
  );
  engine.feed(
    flow({ ts: 7000, direction: 'in', dstPort: 80, srcIp: '1.2.3.4', dstIp: '10.0.0.8' }),
  );
  engine.feed(
    flow({ ts: 8000, direction: 'in', dstPort: 22, srcIp: '1.2.3.4', dstIp: '10.0.0.8' }),
  );
  assert.equal(hits.length, 1);
});

test('257 rules are rejected and an oversize group list cannot be imported', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const rules = [];
  for (let i = 0; i < 257; i += 1) {
    rules.push({ id: `r${i}`, severity: 'low', on: 'flow', window: '1m' });
  }
  assert.throws(() => engine.loadRules(rules), /exceeds cap/);
  engine.loadRules([rule('tftp-out.json')]);
  engine.feed(flow({ ts: 1 }));
  const saved = engine.exportBaseline({ createdAt: 1 });
  const groups = [];
  for (let i = 0; i < 10001; i += 1) groups.push([`k${i}`, { start: 0, fired: false }]);
  saved.devices.d.detectors['rule:tftp-out'] = {
    v: 1,
    state: { groups, partials: [], learned: {} },
  };
  assert.throws(() => engine.importBaseline(saved), /exceeds cap/);
});
