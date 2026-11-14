'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, createShardedEngine, HubvikError } = require('../src/index.js');

const DNS =
  '{"type":"dns","device":"cam","ts":1000,"qname":"cdn.vendor.example","qtype":"A","rcode":"NOERROR","resolver":"192.0.2.53"}\n';

test('doctor names the sample types and leaves the live engine alone', () => {
  const live = createEngine({ learnMs: 0, tiers: ['T0'] });
  live.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1000 });
  const before = live.anomalyCount;
  const plan = live.doctor(DNS);
  assert.strictEqual(live.anomalyCount, before);
  assert.strictEqual(live.devices.has('cam'), false);
  assert.deepStrictEqual(plan.eventTypes, ['dns']);
  assert.deepStrictEqual(plan.adapters, ['@hubvik/adapter-dnsmasq']);
  assert.deepStrictEqual(plan.options, { tiers: ['T2'], classSuggest: true });
  assert.ok(plan.coverage && plan.coverage.summary);
  assert.ok(
    plan.blind.some(
      (row) => row.behavior === 'matter-fabric-join' && row.reason === 'no matter app event',
    ),
  );
  assert.ok(
    plan.blind.some(
      (row) => row.behavior === 'thread-network-change' && row.reason === 'no thread event',
    ),
  );
  assert.ok(!plan.blind.some((row) => row.behavior === 'fleet-resolver-change'));
  assert.deepStrictEqual(plan.suggestions, []);
});

test('a later sample with a new event type rewrites the plan', () => {
  const engine = createEngine({ learnMs: 0 });
  const first = engine.doctor(DNS);
  const second = engine.doctor(
    `${DNS}${JSON.stringify(flow('cam', 554, { dstName: 'cam.vendor.example' }))}\n`,
  );
  assert.deepStrictEqual(second.eventTypes, ['dns', 'flow']);
  assert.notDeepStrictEqual(first.adapters, second.adapters);
  assert.deepStrictEqual(second.adapters, ['@hubvik/adapter-suricata-eve']);
  assert.deepStrictEqual(second.options.tiers, ['T1', 'T2']);
  assert.ok(first.blind.some((row) => row.behavior === 'doorbell-clip-burst'));
  assert.ok(!second.blind.some((row) => row.behavior === 'doorbell-clip-burst'));
  assert.ok(second.blind.some((row) => row.behavior === 'thread-network-change'));
  const cam = second.suggestions.find((row) => row.device === 'cam');
  assert.ok(cam);
  assert.strictEqual(cam.rows[0].class, 'camera');
  assert.deepStrictEqual(cam.names, ['vendor.example']);
  assert.deepStrictEqual(cam.ports, [554]);
  assert.strictEqual(cam.assigned, null);
});

test('a listen port suggests a class and does not assign it', () => {
  const plan = createEngine().doctor([flow('printer-1', 631)]);
  const row = plan.suggestions.find((item) => item.device === 'printer-1');
  assert.ok(row);
  assert.strictEqual(row.rows[0].class, 'printer');
  assert.deepStrictEqual(row.rows[0].reasons, ['listen']);
  assert.deepStrictEqual(row.ports, [631]);
  assert.deepStrictEqual(row.schedule, { hour: 0, bytes: 200 });
  assert.strictEqual(row.assigned, null);
  assert.ok(plan.blind.some((item) => item.behavior === 'local-control-relay'));
});

test('matter, peers, presence, and dhcp change which behaviors stay blind', () => {
  const matter = createEngine().doctor([
    {
      type: 'app',
      device: 'bulb',
      ts: 1000,
      proto: 'matter',
      role: 'server',
      peerIp: '192.0.2.20',
      op: 'AddNOC',
    },
  ]);
  assert.deepStrictEqual(matter.adapters, []);
  assert.deepStrictEqual(matter.options.tiers, ['T5']);
  assert.ok(!matter.blind.some((row) => row.behavior === 'matter-fabric-join'));
  assert.ok(matter.blind.some((row) => row.behavior === 'thread-network-change'));

  const peers = createEngine().doctor([
    { type: 'summary', device: 'a', ts: 1000, dst: 'one.example', bytes: 1 },
    { type: 'summary', device: 'b', ts: 1000, dst: 'two.example', bytes: 1, presence: 'away' },
  ]);
  assert.ok(!peers.blind.some((row) => row.behavior === 'sensor-silent-while-peers-talk'));
  assert.ok(!peers.blind.some((row) => row.behavior === 'occupancy-dark-traffic'));

  const dhcp = createEngine().doctor([
    { type: 'dhcp', ts: 1000, mac: 'aa:bb:cc:dd:ee:ff', msg: 'ack', device: 'cam' },
    flow('cam', 443, { direction: 'out', tcpOutcome: 'established' }),
  ]);
  assert.deepStrictEqual(dhcp.adapters, ['@hubvik/adapter-conntrack', '@hubvik/adapter-openwrt']);
  assert.ok(!dhcp.blind.some((row) => row.behavior === 'reboot-connection-burst'));
  assert.ok(!dhcp.blind.some((row) => row.behavior === 'repeated-failure-then-success'));
  assert.ok(!dhcp.blind.some((row) => row.behavior === 'synchronized-outbound'));
});

test('an empty sample leaves every 4.0.0 behavior blind', () => {
  const plan = createEngine().doctor('');
  assert.strictEqual(plan.blind.length, 20);
  assert.deepStrictEqual(plan.eventTypes, []);
  assert.deepStrictEqual(plan.adapters, []);
  assert.deepStrictEqual(plan.options, { tiers: ['T0'], classSuggest: true });
});

test('a forbidden key is skipped and a bad sample throws', () => {
  const plan = createEngine().doctor('{"__proto__":1,"device":"d","type":"dns"}\n' + DNS);
  assert.deepStrictEqual(plan.eventTypes, ['dns']);
  const engine = createEngine();
  assert.throws(
    () => engine.doctor(1),
    (err) => err instanceof HubvikError && err.code === 'DOCTOR_SAMPLE_IS_INVALID',
  );
});

test('a sharded engine doctor does not feed the shards', () => {
  const box = createShardedEngine({ shards: 2, inline: true, learnMs: 0, tiers: ['T0'] });
  box.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1000 });
  const before = box.anomalyCount;
  const plan = box.doctor(DNS);
  assert.strictEqual(box.anomalyCount, before);
  assert.deepStrictEqual(plan.eventTypes, ['dns']);
});

/**
 * @param {string} device
 * @param {number} dstPort
 * @param {{ direction?: string, dstName?: string, tcpOutcome?: string }} [extra]
 */
function flow(device, dstPort, extra = {}) {
  /** @type {Record<string, any>} */
  const event = {
    type: 'flow',
    device,
    ts: 1000,
    srcIp: '192.0.2.20',
    srcPort: 40000,
    dstIp: '192.0.2.10',
    dstPort,
    proto: 'tcp',
    direction: extra.direction || 'in',
    bytesOut: 100,
    bytesIn: 100,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 10,
  };
  if (extra.dstName) event.dstName = extra.dstName;
  if (extra.tcpOutcome) event.tcpOutcome = extra.tcpOutcome;
  return event;
}
