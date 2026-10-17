import { createRequire } from 'node:module';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { mulberry32, range } = require('../../test/fixtures/prng.js');

const DAY = 86400;
const T0 = 2 * DAY;
const BENIGN_SEC = Math.round(0.6 * DAY);
const GAP = 600;
const rng = mulberry32(20261017);

/**
 * Zeek seconds. Five devices, two days of benign before the first Malicious row,
 * then a post-lock span whose benign remainder is 0.6 day each (3 device-days).
 * Twenty-five attack instances: horizontal scan, slow vertical scan, C2 beacon, UDP flood.
 * @param {string} [outFile]
 * @returns {string}
 */
function generate(outFile) {
  const dest = outFile || join(dirname(fileURLToPath(import.meta.url)), 'conn.log.labeled');
  /** @type {string[]} */
  const rows = [];
  const header = [
    '#separator \\x09',
    '#empty_field (empty)',
    '#unset_field -',
    [
      '#fields',
      'ts',
      'uid',
      'id.orig_h',
      'id.orig_p',
      'id.resp_h',
      'id.resp_p',
      'proto',
      'duration',
      'orig_bytes',
      'resp_bytes',
      'orig_pkts',
      'resp_pkts',
      'local_orig',
      'local_resp',
      'tunnel_parents',
      'label',
      'detailed-label',
    ].join('\t'),
    [
      '#types',
      'time',
      'string',
      'addr',
      'port',
      'addr',
      'port',
      'enum',
      'interval',
      'count',
      'count',
      'count',
      'count',
      'bool',
      'bool',
      'set[string]',
      'string',
      'string',
    ].join('\t'),
  ];
  let uid = 0;
  /**
   * @param {number} ts
   * @param {string} device
   * @param {string} dst
   * @param {number} port
   * @param {string} proto
   * @param {number} bytes
   * @param {number} pkts
   * @param {string} label
   * @param {string} detail
   */
  function line(ts, device, dst, port, proto, bytes, pkts, label, detail) {
    uid += 1;
    const srcPort = Math.floor(range(rng, 40000, 40100));
    rows.push(
      [
        ts.toFixed(3),
        `C${uid}`,
        device,
        String(srcPort),
        dst,
        String(port),
        proto,
        '0.010',
        String(bytes),
        '0',
        String(pkts),
        '0',
        'T',
        'F',
        '-',
        label,
        detail,
      ].join('\t'),
    );
  }

  const devices = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5'];
  for (const device of devices) {
    line(0, device, '1.2.3.4', 443, 'tcp', 80, 1, 'Benign', '-');
    line(10, device, '1.2.3.4', 443, 'tcp', 80, 1, 'Benign', '-');
    line(20, device, '1.2.3.4', 9, 'tcp', 60, 1, 'Benign', '-');
    line(30, device, '1.2.3.4', 80, 'tcp', 60, 1, 'Benign', '-');
    for (let port = 0; port < 6; port += 1) {
      line(100 + port * 120, device, '1.2.3.10', 2000 + port, 'tcp', 60, 1, 'Benign', '-');
    }
    line(T0 - 1, device, '1.2.3.4', 443, 'tcp', 80, 1, 'Benign', '-');
  }

  for (let i = 0; i < 6; i += 1) {
    const ts = T0 + i * GAP;
    for (let host = 1; host <= 21; host += 1) {
      line(ts, '10.0.0.1', `45.1.1.${host}`, 9, 'tcp', 60, 1, 'Malicious', 'HorizontalScan');
    }
  }
  line(T0 + BENIGN_SEC, '10.0.0.1', '1.2.3.4', 443, 'tcp', 80, 1, 'Benign', '-');

  for (let i = 0; i < 6; i += 1) {
    line(
      T0 + i * GAP,
      '10.0.0.2',
      '1.2.3.10',
      2000 + i,
      'tcp',
      60,
      1,
      'Malicious',
      'SlowVerticalScan',
    );
  }
  line(T0 + BENIGN_SEC, '10.0.0.2', '1.2.3.4', 443, 'tcp', 80, 1, 'Benign', '-');

  const beaconSpan = 19 * 60;
  for (let i = 0; i < 6; i += 1) {
    const start = T0 + i * (beaconSpan + GAP);
    for (let step = 0; step < 20; step += 1) {
      line(
        start + step * 60,
        '10.0.0.3',
        `45.4.1.${i + 1}`,
        443,
        'tcp',
        120,
        1,
        'Malicious',
        'C2Beacon',
      );
    }
  }
  line(T0 + BENIGN_SEC + 6 * beaconSpan, '10.0.0.3', '1.2.3.4', 443, 'tcp', 80, 1, 'Benign', '-');

  for (let i = 0; i < 6; i += 1) {
    line(T0 + i * GAP, '10.0.0.4', '45.9.1.1', 80, 'udp', 20000, 500, 'Malicious', 'UdpFlood');
  }
  line(T0 + BENIGN_SEC, '10.0.0.4', '1.2.3.4', 443, 'tcp', 80, 1, 'Benign', '-');

  line(T0, '10.0.0.5', '45.1.1.1', 9, 'tcp', 60, 1, 'Malicious', 'HorizontalScan');
  for (let host = 2; host <= 21; host += 1) {
    line(T0, '10.0.0.5', `45.1.1.${host}`, 9, 'tcp', 60, 1, 'Malicious', 'HorizontalScan');
  }
  line(T0 + BENIGN_SEC, '10.0.0.5', '1.2.3.4', 443, 'tcp', 80, 1, 'Benign', '-');

  mkdirSync(dirname(dest), { recursive: true });
  writeFileSync(dest, `${header.concat(rows).join('\n')}\n`);
  return dest;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  generate(process.argv[2]);
}

export { generate };
