'use strict';

/**
 * @param {{ events: number, anomalies: number, warnings: number, devices: number, indicators: number, detectors: object, memoryBytes: number, allows: number, suppresses: number, acks: number }} snap
 */
function buildStats(snap) {
  return {
    events: snap.events,
    anomalies: snap.anomalies,
    warnings: snap.warnings,
    devices: snap.devices,
    indicators: snap.indicators,
    allows: snap.allows,
    suppresses: snap.suppresses,
    acks: snap.acks,
    detectors: snap.detectors,
    memoryBytes: snap.memoryBytes,
  };
}

module.exports = { buildStats };
