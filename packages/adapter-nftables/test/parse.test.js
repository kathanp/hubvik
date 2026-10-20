'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createParser } = require('../src/index.js');

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
  assert.deepStrictEqual(parser.write('{"nftables":[]}'), []);
});
