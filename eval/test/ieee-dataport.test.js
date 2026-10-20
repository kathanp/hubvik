'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { loadIeeeDataport } = require('../ieee-dataport.js');

const FIXTURE = path.join(__dirname, 'ieee');

test('IEEE DataPort labels host-extracted ARP and DHCP by the PCAP category directory', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'ieee-dataport.js'), 'utf8');
  const readme = fs.readFileSync(path.join(__dirname, '..', 'README.md'), 'utf8');
  assert.match(source, /UNVERIFIED: written from documentation, not run on real data/);
  assert.match(readme, /ieee-dataport/);
  assert.match(readme, /UNVERIFIED: written from documentation, not run on real data/);
  const rows = loadIeeeDataport(FIXTURE);
  const benign = rows.filter((row) => row.label === 'Benign');
  const attack = rows.filter((row) => row.detailedLabel === 'MITM-ArpSpoofing');
  assert.ok(benign.some((row) => row.event.type === 'flow' && row.malicious === false));
  assert.ok(
    benign.some(
      (row) =>
        row.event.type === 'arp' &&
        row.event.op === 'reply' &&
        row.event.mac === 'aa:bb:cc:dd:ee:01',
    ),
  );
  assert.ok(
    benign.some(
      (row) =>
        row.event.type === 'dhcp' &&
        row.event.msg === 'ack' &&
        row.event.requestedIp === '10.0.0.8',
    ),
  );
  assert.ok(attack.some((row) => row.event.type === 'arp' && row.malicious === true));
  assert.strictEqual(attack[0].event.device, 'attacker');
});
