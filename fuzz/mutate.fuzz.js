'use strict';

const { createEngine } = require('../packages/core/src/index.js');
const { mulberry32 } = require('../test/fixtures/prng.js');

const N = 100_000;

/**
 * @param {any} value
 * @returns {any}
 */
function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

/**
 * @param {any} value
 * @param {object[]} out
 */
function nodesOf(value, out) {
  if (!value || typeof value !== 'object') return;
  out.push(value);
  const children = Array.isArray(value) ? value : Object.values(value);
  for (const child of children) nodesOf(child, out);
}

/**
 * @param {any} root
 * @param {() => number} rng
 */
function mutate(root, rng) {
  /** @type {object[]} */
  const nodes = [];
  nodesOf(root, nodes);
  const node = nodes[Math.floor(rng() * nodes.length)];
  const keys = Object.keys(node);
  const kind = Math.floor(rng() * 6);
  if (kind === 0) {
    Object.assign(node, JSON.parse(`{"__proto__":{"x":${Math.floor(rng() * 10)}}}`));
    return;
  }
  if (keys.length === 0) {
    node.extra = Math.floor(rng() * 5);
    return;
  }
  const key = keys[Math.floor(rng() * keys.length)];
  if (kind === 1) {
    delete node[key];
    return;
  }
  if (kind === 2) {
    node[key] = null;
    return;
  }
  if (kind === 3) {
    node[key] = typeof node[key] === 'number' ? node[key] + 1 : 1;
    return;
  }
  if (kind === 4) {
    node[key] = typeof node[key] === 'string' ? `${node[key]}x` : 'x';
    return;
  }
  node[key] = node[key] === true ? false : true;
}

/**
 * @param {any} value
 * @param {number} max
 * @param {Set<any>} seen
 * @param {string} label
 */
function bound(value, max, seen, label) {
  if (!value || typeof value !== 'object') return;
  if (seen.has(value)) return;
  seen.add(value);
  if (value instanceof Map || value instanceof Set) {
    if (value.size > max) throw new Error(`${label} collection exceeds cap`);
    for (const item of value.values()) bound(item, max, seen, label);
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > max) throw new Error(`${label} array exceeds cap`);
    for (const item of value) bound(item, max, seen, label);
    return;
  }
  for (const item of Object.values(value)) bound(item, max, seen, label);
}

/**
 * Device, allow, suppress, and scratch collections stay inside their caps.
 * @param {any} engine
 * @param {string} label
 */
function assertCaps(engine, label) {
  const opts = engine.opts;
  if (engine.devices.size > opts.maxDevices) throw new Error(`${label} device cap`);
  const collection = Math.max(opts.maxWindows, opts.maxDestinations, opts.maxAlertKeys);
  for (const device of engine.devices.values()) {
    if (device.suppress) {
      for (const list of device.suppress.values()) {
        if (list.length > opts.maxSuppress) throw new Error(`${label} suppress cap`);
      }
    }
    if (device.allows) {
      for (const set of device.allows.values()) {
        if (set.size > opts.maxDestinations) throw new Error(`${label} allow cap`);
      }
    }
    if (device.states) {
      for (const state of device.states.values()) bound(state, collection, new Set(), label);
    }
  }
  const scratch = engine.scratch;
  const identity = scratch.get('identity-change');
  if (identity) {
    if (identity.macs && identity.macs.size > 5000) throw new Error(`${label} identity-change cap`);
    if (identity.fired && identity.fired.size > 5000)
      throw new Error(`${label} identity-change cap`);
  }
  const dhcp = scratch.get('dhcp-starvation');
  if (dhcp && dhcp.macs && dhcp.macs.size > 5000) throw new Error(`${label} dhcp-starvation cap`);
  const wave = scratch.get('fleet-wave');
  if (wave) bound(wave, 5000, new Set(), label);
  const arp = scratch.get('arp-spoof');
  if (arp) bound(arp, 5000, new Set(), label);
  if (engine.indicators && engine.indicators.length > opts.maxIndicators) {
    throw new Error(`${label} indicator cap`);
  }
}

/**
 * @param {any} engine
 * @param {'baseline' | 'checkpoint'} label
 */
function assertRoundTrip(engine, label) {
  const createdAt = 1;
  const first =
    label === 'baseline' ? engine.exportBaseline({ createdAt }) : engine.checkpoint({ createdAt });
  const next = createEngine({ learnMs: 0, tiers: ['T0'] });
  if (label === 'baseline') next.importBaseline(first);
  else next.restore(first);
  const second =
    label === 'baseline' ? next.exportBaseline({ createdAt }) : next.checkpoint({ createdAt });
  if (JSON.stringify(first) !== JSON.stringify(second)) {
    throw new Error(`${label} export/import/export mismatch`);
  }
}

/**
 * @param {string} label
 * @param {(engine: import('../packages/core/src/index.js').Engine, value: any) => void} apply
 * @param {any} valid
 * @param {number} seed
 */
function run(label, apply, valid, seed) {
  const engine = createEngine({ learnMs: 0, tiers: ['T0'] });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 0 });
  apply(engine, clone(valid));
  const rng = mulberry32(seed);
  let accepted = 0;
  let rejected = 0;
  for (let i = 0; i < N; i++) {
    const before = engine.stats().devices;
    const sample = clone(valid);
    mutate(sample, rng);
    try {
      apply(engine, sample);
    } catch (err) {
      if (engine.stats().devices !== before) {
        throw new Error(`${label} mutation changed state`, { cause: err });
      }
      if (Object.hasOwn(Object.prototype, 'x')) {
        throw new Error('prototype polluted', { cause: err });
      }
      if (!(err instanceof Error)) throw err;
      rejected += 1;
      continue;
    }
    if (Object.hasOwn(Object.prototype, 'x')) throw new Error('prototype polluted');
    try {
      engine.feed({ device: 'd', dst: 'still.example', bytes: 1, ts: 10_000 + i });
    } catch (err) {
      throw new Error(`${label} accepted a value that broke feed`, { cause: err });
    }
    assertCaps(engine, label);
    assertRoundTrip(engine, /** @type {'baseline' | 'checkpoint'} */ (label));
    accepted += 1;
  }
  console.log(
    `${label} mutation fuzz: ${N} inputs, ${accepted} accepted, ${rejected} rejected, caps held, round-trip matched`,
  );
}

const source = createEngine({ learnMs: 0, tiers: ['T0'] });
source.feed({ device: 'd', dst: 'a.example', bytes: 100, ts: 0 });
source.feed({ device: 'd', dst: 'b.example', bytes: 50, ts: 60_000 });
const baseline = source.exportBaseline({ createdAt: 1 });
const checkpoint = source.checkpoint({ createdAt: 1 });

run('baseline', (engine, value) => engine.importBaseline(value), baseline, 20261020);
run('checkpoint', (engine, value) => engine.restore(value), checkpoint, 20261021);
