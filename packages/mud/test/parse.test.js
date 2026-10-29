'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { parseMud, loadMudFile } = require('../src/index.js');

const FILE = {
  'ietf-mud:mud': {
    'mud-version': 1,
    'from-device-policy': { 'access-lists': { 'access-list': [{ name: 'from-ipv4' }] } },
    'to-device-policy': { 'access-lists': { 'access-list': [{ name: 'to-ipv4' }] } },
  },
  'ietf-access-control-list:acls': {
    acl: [
      {
        name: 'from-ipv4',
        aces: {
          ace: [
            {
              name: 'dns',
              matches: {
                ipv4: { protocol: 17 },
                udp: { 'destination-port': { port: 53 } },
                'ietf-acldns:dst-dnsname': 'DNS.Example',
              },
              actions: { forwarding: 'accept' },
            },
            {
              name: 'telnet',
              matches: { ipv4: { protocol: 6 }, tcp: { 'destination-port': { port: 23 } } },
              actions: { forwarding: 'drop' },
            },
          ],
        },
      },
      {
        name: 'to-ipv4',
        aces: {
          ace: [
            {
              name: 'ntp',
              matches: { ipv4: { protocol: 17 }, udp: { 'destination-port': { port: 123 } } },
              actions: { forwarding: 'accept' },
            },
          ],
        },
      },
    ],
  },
};

test('a MUD file becomes allows and does not install an ACL', () => {
  const acl = parseMud(JSON.stringify(FILE));
  assert.deepStrictEqual(acl.allows, [
    { direction: 'out', proto: 'udp', dstPort: 53, domain: 'dns.example' },
    { direction: 'in', proto: 'udp', dstPort: 123 },
  ]);
  assert.throws(() => parseMud('{"constructor":{}}'), /invalid/);
  assert.throws(() => parseMud('not json'), /invalid/);
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'index.js'), 'utf8');
  assert.doesNotMatch(src, /child_process/);
  assert.doesNotMatch(src, /nftables/);
});

test('loadMudFile reads a local file', () => {
  const file = path.join(os.tmpdir(), `hubvik-mud-${process.pid}.json`);
  fs.writeFileSync(file, JSON.stringify(FILE));
  try {
    const acl = loadMudFile(file);
    assert.strictEqual(acl.allows.length, 2);
  } finally {
    fs.unlinkSync(file);
  }
});
