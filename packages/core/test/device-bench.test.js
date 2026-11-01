'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { formatBlock } = require('../../../bench/device.js');

const host = { node: 'v22.0.0', platform: 'linux', arch: 'x64', cpu: 'test', memory: '1' };

test('a non-ARM host prints the Raspberry Pi sentence', () => {
  const text = formatBlock(host, ['one', 'two', 'three']);
  assert.match(text, /This is not a Raspberry Pi measurement\./);
  assert.match(text, /one/);
});

test('an ARM host does not print the Raspberry Pi sentence', () => {
  const text = formatBlock({ ...host, arch: 'arm64' }, ['one']);
  assert.doesNotMatch(text, /Raspberry Pi/);
});
