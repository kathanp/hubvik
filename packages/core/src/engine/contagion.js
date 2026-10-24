'use strict';

const STAGES = require('../data/stages.json');

/**
 * Record one live anomaly on each LAN neighbor. The neighbor alerts when the
 * Hawkes intensity for that stage crosses the H2 threshold.
 * @param {any} engine
 * @param {any} device
 * @param {any} anomaly
 * @returns {void}
 */
function spread(engine, device, anomaly) {
  const status = engine.detectorStatus['graph-contagion'];
  if (!status || !status.active) return;
  const stage = /** @type {Record<string, string>} */ (STAGES)[anomaly.detector];
  if (!stage) return;
  const det = engine.byId.get('graph-contagion');
  if (!det || typeof det.observe !== 'function') return;
  const options = engine._optionsFor(det);
  for (const id of neighborsOf(device)) {
    const peer = engine.devices.get(id);
    if (!peer || peer === device) continue;
    const draft = det.observe(engine._state(peer, det), stage, anomaly.ts, options);
    if (draft) engine._take(peer, det, draft, false, null);
  }
}

/**
 * @param {any} device
 * @returns {Set<string>}
 */
function neighborsOf(device) {
  /** @type {Set<string>} */
  const ids = new Set();
  if (device.lanEdges) {
    for (const row of device.lanEdges.values()) {
      if (row && row.dst) ids.add(row.dst);
    }
  }
  if (device.lanPeers) {
    for (const id of device.lanPeers) ids.add(id);
  }
  return ids;
}

module.exports = { spread };
