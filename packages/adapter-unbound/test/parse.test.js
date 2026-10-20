'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createParser } = require('../src/index.js');

test('unbound query and reply lines become dns events', () => {
  const parser = createParser({ now: () => 5, client: '10.0.0.2' });
  const query = parser.write('info: query: www.example.com. A IN');
  assert.strictEqual(query[0].qname, 'www.example.com');
  assert.strictEqual(query[0].qtype, 'A');
  const reply = parser.write('info: reply: www.example.com. A IN NOERROR 1.2.3.4');
  assert.strictEqual(reply[0].rcode, 'NOERROR');
  assert.strictEqual(reply[0].answers[0].value, '1.2.3.4');
  assert.deepStrictEqual(parser.write('noise'), []);
});
