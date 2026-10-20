'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createParser } = require('../src/index.js');

test('a netflow v9 template and data set become a flow', () => {
  const header = Buffer.alloc(20);
  header.writeUInt16BE(9, 0);
  const template = Buffer.alloc(4 + 4 + 7 * 4);
  template.writeUInt16BE(0, 0);
  template.writeUInt16BE(template.length, 2);
  template.writeUInt16BE(256, 4);
  template.writeUInt16BE(7, 6);
  const fields = [
    [8, 4],
    [12, 4],
    [7, 2],
    [11, 2],
    [4, 1],
    [1, 4],
    [2, 4],
  ];
  fields.forEach((field, index) => {
    template.writeUInt16BE(field[0], 8 + index * 4);
    template.writeUInt16BE(field[1], 10 + index * 4);
  });
  const data = Buffer.alloc(4 + 4 + 4 + 2 + 2 + 1 + 4 + 4);
  data.writeUInt16BE(256, 0);
  data.writeUInt16BE(data.length, 2);
  data.writeUInt8(192, 4);
  data.writeUInt8(0, 5);
  data.writeUInt8(2, 6);
  data.writeUInt8(10, 7);
  data.writeUInt8(198, 8);
  data.writeUInt8(51, 9);
  data.writeUInt8(100, 10);
  data.writeUInt8(1, 11);
  data.writeUInt16BE(40000, 12);
  data.writeUInt16BE(443, 14);
  data.writeUInt8(6, 16);
  data.writeUInt32BE(1000, 17);
  data.writeUInt32BE(8, 21);
  const parser = createParser();
  const events = parser.write(Buffer.concat([header, template, data]));
  assert.strictEqual(events.length, 1);
  assert.strictEqual(events[0].srcIp, '192.0.2.10');
  assert.strictEqual(events[0].dstIp, '198.51.100.1');
  assert.strictEqual(events[0].dstPort, 443);
  assert.strictEqual(events[0].bytesOut, 1000);
  assert.deepStrictEqual(parser.write(Buffer.from('nope')), []);
});
