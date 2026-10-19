'use strict';

/**
 * @param {{ events: number, anomalies: number, warnings: number, devices: number, indicators: number, detectors: object, memoryBytes: number, watermark: number | null, learningQuality: object, allows: number, suppresses: number, acks: number, shadow: object, canary: object, identity: { rows: number, rekeyed: number, unresolved: number }, precision: object }} snap
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
    watermark: snap.watermark,
    learningQuality: snap.learningQuality,
    shadow: snap.shadow,
    canary: snap.canary,
    identity: snap.identity,
    precision: snap.precision,
  };
}

module.exports = { buildStats };
