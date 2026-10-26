'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { format } = require('../src/index.js');

test('formats RFC 5424 with a CEF message', () => {
  const line = format(
    {
      id: '1',
      device: 'cam-1',
      detector: 'cert-change',
      severity: 'high',
      ts: Date.UTC(2026, 0, 5),
      actual: 'Unexpected CA',
      expected: 'Vendor CA',
    },
    { host: 'gateway' },
  );
  assert.ok(
    line.startsWith('<131>1 2026-01-05T00:00:00.000Z gateway hubvik - cert-change - CEF:0|'),
  );
  assert.ok(line.includes('cs1=cam-1'));
  assert.ok(line.includes('msg=Vendor CA'));
});

test('a host cannot break the syslog header', () => {
  const line = format(
    { detector: 'cert-change', device: 'cam', actual: 'a<b>', expected: 'c>d' },
    { host: 'gw\n<0>1', app: 'hub vik' },
  );
  assert.strictEqual(line.split('\n').length, 1);
  assert.ok(line.includes(' gw01 hubvik '));
  assert.ok(!line.includes('<0>'));
  assert.ok(line.includes('a b '));
});

test('uses info defaults and strips CEF separators', () => {
  const line = format({ detector: 'x', actual: 'a|b\nc', device: 'cam' });
  assert.ok(line.startsWith('<134>1 '));
  assert.ok(line.includes('a b c'));
  assert.ok(line.includes('hubvik'));
  const bare = format(null);
  assert.ok(bare.includes('CEF:0|hubvik|hubvik|0.1.0|-|-|1|'));
});
