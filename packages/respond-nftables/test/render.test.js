'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { render } = require('../src/index.js');

test('nftables text is a comment for review and a drop for an ip block', () => {
  const review = render({ action: 'review', fingerprint: 'abc', expiryMs: 10 });
  assert.match(review, /comment "hubvik abc exp 10"/);
  assert.doesNotMatch(review, /drop/);
  const block = render({ action: 'block-destination', target: '198.51.100.9', fingerprint: 'abc' });
  assert.match(block, /ip saddr 198.51.100.9 drop/);
  assert.throws(() => render({ action: 'block-destination', target: '1.2.3.4; drop' }), /invalid/);
});
