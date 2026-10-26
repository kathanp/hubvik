'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createParser } = require('../src/index.js');
const { createEngine } = require('hubvik');

test('nftables counter JSON becomes a flow', () => {
  const parser = createParser({ now: () => 3 });
  const events = parser.write(
    JSON.stringify({
      nftables: [
        {
          counter: {
            saddr: '192.0.2.10',
            daddr: '198.51.100.1',
            sport: 1,
            dport: 443,
            protocol: 'tcp',
            packets: 4,
            bytes: 200,
          },
        },
      ],
    }),
  );
  assert.strictEqual(events[0].dstPort, 443);
  assert.strictEqual(events[0].bytesOut, 200);
  assert.strictEqual(events[0].bytesIn, 0);
  assert.strictEqual(events[0].pktsIn, 0);
  assert.strictEqual(events[0].durationMs, 0);
  const engine = createEngine({ learnMs: 0, tiers: ['T1'] });
  assert.doesNotThrow(() => engine.feed(events[0]));
  const icmp = parser.write(
    JSON.stringify({
      counter: { saddr: '192.0.2.10', daddr: '198.51.100.1', protocol: 'icmp', bytes: 20 },
    }),
  );
  assert.strictEqual(icmp[0].proto, 'icmp');
  assert.deepStrictEqual(parser.write('{"nftables":[]}'), []);
});
