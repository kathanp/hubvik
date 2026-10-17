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
    line.startsWith('<131>1 2026-01-05T00:00:00.000Z gateway iotwarden - cert-change - CEF:0|'),
  );
  assert.ok(line.includes('cs1=cam-1'));
  assert.ok(line.includes('msg=Vendor CA'));
});
