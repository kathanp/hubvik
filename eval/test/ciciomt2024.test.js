'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { loadCiciomt2024 } = require('../ciciomt2024.js');

const FIXTURE = path.join(__dirname, 'ciciomt');

test('CICIoMT2024 labels Zeek MQTT logs by the PCAP category directory', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'ciciomt2024.js'), 'utf8');
  const readme = fs.readFileSync(path.join(__dirname, '..', 'README.md'), 'utf8');
  assert.match(source, /UNVERIFIED: written from documentation, not run on real data/);
  assert.match(readme, /ciciomt2024/);
  assert.match(readme, /UNVERIFIED: written from documentation, not run on real data/);
  const rows = loadCiciomt2024(FIXTURE);
  const benign = rows.filter((row) => row.label === 'Benign');
  const attack = rows.filter((row) => row.detailedLabel === 'MQTT-DDoS-Connect_Flood');
  assert.ok(benign.some((row) => row.event.type === 'flow' && row.malicious === false));
  assert.ok(
    benign.some(
      (row) =>
        row.event.type === 'app' &&
        row.event.proto === 'mqtt' &&
        row.event.op === 'PUBLISH' &&
        row.device === '10.0.0.20',
    ),
  );
  assert.ok(
    attack.some(
      (row) =>
        row.event.type === 'app' &&
        row.event.op === 'CONNECT' &&
        row.malicious === true &&
        row.device === '10.0.0.21',
    ),
  );
});
