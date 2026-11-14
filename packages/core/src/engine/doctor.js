'use strict';

const { HubvikError } = require('../errors');

const { FORBIDDEN_KEYS } = require('./constants');

/**
 * Shipped adapters and the event tokens each one emits.
 * A token no adapter emits does not add a package.
 */
const ADAPTERS = [
  { name: '@hubvik/adapter-conntrack', covers: ['flow'] },
  { name: '@hubvik/adapter-dnsmasq', covers: ['dns'] },
  { name: '@hubvik/adapter-ipfix', covers: ['flow'] },
  { name: '@hubvik/adapter-nftables', covers: ['flow'] },
  { name: '@hubvik/adapter-openwrt', covers: ['dhcp', 'nd', 'wifi'] },
  { name: '@hubvik/adapter-ssdp', covers: ['discovery:ssdp', 'app:upnp'] },
  {
    name: '@hubvik/adapter-suricata-eve',
    covers: ['flow', 'dns', 'tls', 'http'],
  },
  { name: '@hubvik/adapter-unbound', covers: ['dns'] },
  {
    name: '@hubvik/adapter-zeek',
    covers: [
      'flow',
      'dns',
      'tls',
      'http',
      'app:bacnet',
      'app:dnp3',
      'app:enip',
      'app:modbus',
      'app:mqtt',
      'app:s7',
    ],
  },
];

const TIER_ORDER = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];

/** @type {Record<string, string>} */
const TIER_OF = {
  summary: 'T0',
  flow: 'T1',
  mapping: 'T1',
  dns: 'T2',
  tls: 'T3',
  http: 'T3',
  arp: 'T4',
  dhcp: 'T4',
  ra: 'T4',
  discovery: 'T4',
  nd: 'T4',
  wifi: 'T4',
  app: 'T5',
};

const ZEEK_APP = new Set(['bacnet', 'dnp3', 'enip', 'modbus', 'mqtt', 's7']);

const doctorMethods = {
  /**
   * Read a log sample the host already has. The live engine is not fed.
   * The throwaway engine does not assign a class.
   * @param {string | object[]} sample
   */
  doctor(sample) {
    return report(sample);
  },
};

/**
 * @param {string | object[]} sample
 */
function report(sample) {
  const rows = parseSample(sample);
  const facts = collect(rows);
  const options = {
    tiers: tiersOf(facts),
    classSuggest: true,
  };
  const { createEngine } = require('./engine');
  const box = /** @type {any} */ (createEngine(options));
  /** @type {Map<string, Set<number>>} */
  const ports = new Map();
  let last = 0;
  let sawTs = false;
  for (const row of rows) {
    try {
      box.feed(row.raw);
    } catch {
      continue;
    }
    if (typeof row.raw.ts === 'number' && Number.isFinite(row.raw.ts)) {
      last = sawTs ? Math.max(last, row.raw.ts) : row.raw.ts;
      sawTs = true;
    }
    if (
      row.type === 'flow' &&
      Number.isInteger(row.raw.dstPort) &&
      typeof row.raw.device === 'string'
    ) {
      const set = ports.get(row.raw.device) || new Set();
      set.add(row.raw.dstPort);
      ports.set(row.raw.device, set);
    }
  }
  if (sawTs) box.flush(last);
  return {
    eventTypes: [...facts.types].sort(),
    blind: blindOf(facts),
    adapters: adaptersOf(facts),
    options,
    coverage: box.coverage(sawTs ? last : 0),
    suggestions: suggestionsOf(box, ports),
  };
}

/**
 * @param {string | object[]} sample
 * @returns {{ type: string, raw: any }[]}
 */
function parseSample(sample) {
  /** @type {any[]} */
  let list;
  if (typeof sample === 'string') {
    list = [];
    for (const line of sample.split('\n')) {
      if (!line.trim()) continue;
      try {
        list.push(JSON.parse(line));
      } catch {
        /* a bad line is not an event */
      }
    }
  } else if (Array.isArray(sample)) {
    list = sample;
  } else {
    throw new HubvikError('DOCTOR_SAMPLE_IS_INVALID', 'doctor sample is invalid');
  }
  /** @type {{ type: string, raw: any }[]} */
  const rows = [];
  for (const raw of list) {
    const row = eventRow(raw);
    if (row) rows.push(row);
  }
  return rows;
}

/**
 * @param {any} raw
 * @returns {{ type: string, raw: any } | null}
 */
function eventRow(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  for (const key of Object.keys(raw)) {
    if (FORBIDDEN_KEYS.has(key)) return null;
  }
  if (typeof raw.device === 'string' && FORBIDDEN_KEYS.has(raw.device)) return null;
  const type = raw.type == null ? 'summary' : raw.type;
  if (typeof type !== 'string' || type.length === 0) return null;
  return { type, raw };
}

/**
 * @param {{ type: string, raw: any }[]} rows
 */
function collect(rows) {
  const types = new Set();
  const tiers = new Set();
  const app = new Set();
  const discovery = new Set();
  const directions = new Set();
  const presence = new Set();
  const devices = new Set();
  let outcomes = false;
  for (const row of rows) {
    types.add(row.type);
    const tier = TIER_OF[row.type];
    if (tier) tiers.add(tier);
    if (typeof row.raw.device === 'string' && row.raw.device.length > 0)
      devices.add(row.raw.device);
    if (row.raw.presence === 'home' || row.raw.presence === 'away') presence.add(row.raw.presence);
    if (row.type === 'app' && typeof row.raw.proto === 'string') app.add(row.raw.proto);
    if (row.type === 'discovery' && typeof row.raw.proto === 'string') discovery.add(row.raw.proto);
    if (row.type === 'flow' && typeof row.raw.direction === 'string')
      directions.add(row.raw.direction);
    if (
      row.type === 'flow' &&
      typeof row.raw.tcpOutcome === 'string' &&
      row.raw.tcpOutcome.length > 0
    ) {
      outcomes = true;
    }
  }
  return { types, tiers, app, discovery, directions, presence, devices, outcomes };
}

/**
 * @param {ReturnType<typeof collect>} facts
 * @returns {string[]}
 */
function tiersOf(facts) {
  const tiers = TIER_ORDER.filter((tier) => facts.tiers.has(tier));
  if (tiers.length === 0) tiers.push('T0');
  return tiers;
}

/**
 * @param {ReturnType<typeof collect>} facts
 * @returns {{ behavior: string, reason: string }[]}
 */
function blindOf(facts) {
  const flow = facts.types.has('flow');
  const traffic = flow || facts.types.has('summary');
  const update = flow || facts.types.has('http') || facts.types.has('tls');
  /** @type {{ behavior: string, reason: string }[]} */
  const blind = [];
  /**
   * @param {string} behavior
   * @param {boolean} seen
   * @param {string} reason
   */
  const add = (behavior, seen, reason) => {
    if (!seen) blind.push({ behavior, reason });
  };
  add('matter-fabric-join', facts.app.has('matter'), 'no matter app event');
  add('thread-network-change', false, 'no thread event');
  add('mdns-name-takeover', facts.discovery.has('mdns'), 'no mdns discovery event');
  add('local-control-relay', facts.directions.has('lan'), 'no lan flow');
  add('camera-talkback-new', flow || facts.app.has('rtsp'), 'no flow event');
  add('onvif-user-add', facts.app.has('onvif'), 'no onvif app event');
  add('voice-stream-new', flow || facts.types.has('tls'), 'no flow or tls event');
  add('doorbell-clip-burst', flow, 'no flow event');
  add('plug-duty-change', flow, 'no flow event');
  add(
    'occupancy-dark-traffic',
    traffic && facts.presence.has('away'),
    traffic ? 'no presence hint' : 'no flow event',
  );
  add('sensor-silent-while-peers-talk', facts.devices.size >= 2, 'no peer device');
  add('hvac-call-spike', facts.app.has('bacnet') || facts.app.has('modbus'), 'no hvac app event');
  add(
    'shared-new-destination',
    flow ||
      facts.types.has('dns') ||
      facts.types.has('summary') ||
      facts.types.has('tls') ||
      facts.types.has('http'),
    'no destination event',
  );
  add('synchronized-outbound', facts.directions.has('out'), 'no outbound flow');
  add('fleet-resolver-change', facts.types.has('dns'), 'no dns event');
  add(
    'repeated-failure-then-success',
    flow && facts.outcomes,
    flow ? 'no flow outcome' : 'no flow event',
  );
  add('firmware-skipped', update, 'no update event');
  add(
    'update-rollback',
    facts.types.has('http') || facts.types.has('tls') || facts.types.has('file-fetched'),
    'no update event',
  );
  add(
    'reboot-connection-burst',
    facts.types.has('dhcp') && flow,
    facts.types.has('dhcp') ? 'no flow event' : 'no dhcp event',
  );
  add('crash-loop-outbound', facts.directions.has('out'), 'no outbound flow');
  return blind;
}

/**
 * Fewest adapters that emit the sample's covered tokens.
 * A tie prefers fewer extra tokens, then the lexicographically first names.
 * @param {ReturnType<typeof collect>} facts
 * @returns {string[]}
 */
function adaptersOf(facts) {
  /** @type {Set<string>} */
  const needs = new Set();
  /**
   * @param {string} token
   */
  const want = (token) => {
    if (ADAPTERS.some((row) => row.covers.includes(token))) needs.add(token);
  };
  if (facts.types.has('flow')) want('flow');
  if (facts.types.has('dns')) want('dns');
  if (facts.types.has('tls')) want('tls');
  if (facts.types.has('http')) want('http');
  if (facts.types.has('dhcp')) want('dhcp');
  if (facts.types.has('nd')) want('nd');
  if (facts.types.has('wifi')) want('wifi');
  if (facts.discovery.has('ssdp')) want('discovery:ssdp');
  for (const proto of facts.app) {
    if (proto === 'upnp' || ZEEK_APP.has(proto)) want(`app:${proto}`);
  }
  if (needs.size === 0) return [];
  /** @type {{ names: string[], extra: number, key: string } | null} */
  let best = null;
  const n = ADAPTERS.length;
  for (let mask = 1; mask < 2 ** n; mask += 1) {
    /** @type {string[]} */
    const names = [];
    /** @type {Set<string>} */
    const covered = new Set();
    let extra = 0;
    for (let i = 0; i < n; i += 1) {
      if ((mask & (2 ** i)) === 0) continue;
      names.push(ADAPTERS[i].name);
      for (const token of ADAPTERS[i].covers) {
        if (needs.has(token)) covered.add(token);
        else extra += 1;
      }
    }
    if (covered.size !== needs.size) continue;
    names.sort();
    const key = names.join(',');
    if (
      !best ||
      names.length < best.names.length ||
      (names.length === best.names.length && extra < best.extra) ||
      (names.length === best.names.length && extra === best.extra && key < best.key)
    ) {
      best = { names, extra, key };
    }
  }
  return best ? best.names : [];
}

/**
 * @param {any} box
 * @param {Map<string, Set<number>>} ports
 */
function suggestionsOf(box, ports) {
  /** @type {any[]} */
  const out = [];
  for (const device of box.devices.values()) {
    if (!device.classScores) continue;
    const rows = Object.keys(device.classScores)
      .map((classId) => ({
        class: classId,
        score: device.classScores[classId],
        reasons: (device.classReasons && device.classReasons[classId]) || [],
      }))
      .sort((a, b) => b.score - a.score || (a.class < b.class ? -1 : 1));
    if (rows.length === 0) continue;
    const names = device.classFam && device.classFam.names ? [...device.classFam.names].sort() : [];
    const hour = device.classHour;
    out.push({
      device: device.id,
      rows,
      ports: [...(ports.get(device.id) || [])].sort((a, b) => a - b),
      names,
      schedule: hour && Number.isInteger(hour.hour) ? { hour: hour.hour, bytes: hour.bytes } : null,
      assigned: device.deviceClass || null,
    });
  }
  out.sort((a, b) => (a.device < b.device ? -1 : 1));
  return out;
}

module.exports = { doctorMethods };
