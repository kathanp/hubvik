'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { loadCiciot2023 } = require('../ciciot2023.js');

const FIXTURE = path.join(__dirname, 'ciciot');

test('CICIoT2023 labels hand-written Zeek logs by the PCAP category directory', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'ciciot2023.js'), 'utf8');
  const readme = fs.readFileSync(path.join(__dirname, '..', 'README.md'), 'utf8');
  assert.match(source, /UNVERIFIED: written from documentation, not run on real data/);
  assert.match(readme, /UNVERIFIED: written from documentation, not run on real data/);
  assert.match(readme, /zeek -C -r capture\.pcap/);
  const rows = loadCiciot2023(FIXTURE);
  const benign = rows.filter((row) => row.label === 'Benign');
  const attack = rows.filter((row) => row.detailedLabel === 'Recon-PortScan');
  assert.ok(benign.some((row) => row.event.type === 'flow' && row.malicious === false));
  assert.ok(
    benign.some((row) => row.event.type === 'dns' && row.event.qname === 'video.vendor.com'),
  );
  assert.ok(attack.some((row) => row.event.type === 'flow' && row.malicious === true));
  assert.ok(attack.some((row) => row.event.type === 'tls' && row.event.sni === 'scan.example'));
});
