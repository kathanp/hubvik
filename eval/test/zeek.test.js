'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadIot23 } = require('../iot23.js');
const { attackIntervals } = require('../protocol.js');

const HEADER = [
  '#separator \\x09',
  '#empty_field (empty)',
  '#unset_field -',
  '#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tlocal_orig\tlocal_resp\ttunnel_parents\tlabel\tdetailed-label',
  '#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tbool\tbool\tset[string]\tstring\tstring',
].join('\n');

test('tab-separated and space-separated label columns both parse', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'iotwarden-zeek-'));
  const tabbed = path.join(dir, 'conn.log.labeled');
  fs.writeFileSync(
    tabbed,
    `${HEADER}
1.000\tC1\t10.0.0.8\t40000\t1.2.3.4\t80\ttcp\tT\tF\t-\tBenign\t-
2.000\tC2\t1.2.3.4\t80\t10.0.0.9\t40000\ttcp\tF\tT\t-\tMalicious\tC&C
3.000\tC3\t10.0.0.8\t40000\t1.2.3.4\t9\ttcp\tT\tF\t(empty)\tMalicious\t-
`,
  );
  const spaced = path.join(dir, 'spaced.log.labeled');
  fs.writeFileSync(
    spaced,
    `${HEADER}
4.000\tC4\t10.0.0.7\t40000\t1.2.3.4\t23\ttcp\tT\tF\t- Malicious PartOfAHorizontalPortScan
`,
  );
  const tabbedRows = loadIot23(tabbed);
  assert.strictEqual(tabbedRows[0].device, '10.0.0.8');
  assert.strictEqual(tabbedRows[0].malicious, false);
  assert.strictEqual(tabbedRows[1].device, '10.0.0.9');
  assert.strictEqual(tabbedRows[1].detailedLabel, 'C&C');
  assert.strictEqual(tabbedRows.length, 3);
  assert.strictEqual(tabbedRows[2].label, 'Malicious');
  assert.strictEqual(tabbedRows[2].detailedLabel, '');
  const spacedRows = loadIot23(spaced);
  assert.strictEqual(spacedRows.length, 1);
  assert.strictEqual(spacedRows[0].device, '10.0.0.7');
  assert.strictEqual(spacedRows[0].label, 'Malicious');
  assert.strictEqual(spacedRows[0].detailedLabel, 'PartOfAHorizontalPortScan');
});

test('two malicious runs are one instance at 2 minutes and two at 10 minutes', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'iotwarden-gap-'));
  function write(name, secondTs) {
    const file = path.join(dir, name);
    fs.writeFileSync(
      file,
      `${HEADER}
100.000\tC1\t10.0.0.5\t1\t1.2.3.4\t9\ttcp\tT\tF\t-\tMalicious\tC&C
${secondTs}\tC2\t10.0.0.5\t1\t1.2.3.4\t9\ttcp\tT\tF\t-\tMalicious\tC&C
`,
    );
    return attackIntervals('10.0.0.5', loadIot23(file)).length;
  }
  assert.strictEqual(write('conn.log.two', '220.000'), 1);
  assert.strictEqual(write('conn.log.ten', '700.000'), 2);
});
