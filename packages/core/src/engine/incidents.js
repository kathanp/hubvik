'use strict';

const STAGES = require('../data/stages.json');

const HOUR = 3600e3;
const HALF_LIFE = 6 * HOUR;
/** @type {Record<string, number>} */
const WEIGHT = { info: 5, low: 10, medium: 25, high: 50, critical: 80 };

/**
 * @param {any} anomaly
 * @returns {number}
 */
function weightOf(anomaly) {
  return (WEIGHT[anomaly.severity] || 10) * (anomaly.confidence || 0);
}

/**
 * @param {any} incident
 * @param {number} elapsed
 */
function decay(incident, elapsed) {
  const factor = 0.5 ** (elapsed / HALF_LIFE);
  incident.raw *= factor;
  if (!incident.groupWeight) return;
  for (const key of incident.groupWeight.keys()) {
    incident.groupWeight.set(key, incident.groupWeight.get(key) * factor);
  }
}

/**
 * Same dedupGroup on one device inside the incident window counts once.
 * @param {any} incident
 * @param {any} anomaly
 */
function addWeight(incident, anomaly) {
  const weight = weightOf(anomaly);
  const group = anomaly.dedupGroup;
  if (!group) {
    incident.raw += weight;
    return;
  }
  if (!incident.groupWeight) incident.groupWeight = new Map();
  const prev = incident.groupWeight.get(group) || 0;
  if (weight > prev) {
    incident.raw += weight - prev;
    incident.groupWeight.set(group, weight);
  }
}

/**
 * @param {any} incident
 */
function scoreOf(incident) {
  const mult = incident.stages.size <= 1 ? 1 : 1.5 ** (incident.stages.size - 1);
  incident.score = Math.round(Math.min(100, incident.raw * mult));
  incident.severity =
    incident.stages.size >= 2 || incident.score >= 70
      ? 'critical'
      : incident.score >= 40
        ? 'high'
        : 'medium';
}

/**
 * @param {any} incident
 */
function payload(incident) {
  return {
    id: incident.id,
    device: incident.device,
    stages: [...incident.stages],
    score: incident.score,
    severity: incident.severity,
    anomalyIds: incident.anomalyIds.slice(),
    firstTs: incident.firstTs,
    lastTs: incident.lastTs,
    summary: `${incident.device} ${incident.lines.join(', then ')}`,
  };
}

/**
 * Group one anomaly into the device's open incident and emit `incident`.
 * @param {any} engine
 * @param {any} device
 * @param {any} anomaly
 */
function noteIncident(engine, device, anomaly) {
  const windowMs = engine.opts.incidentWindowMs;
  let incident = device.incident;
  if (!incident || anomaly.ts - incident.lastTs > windowMs) {
    engine.incidentSeq += 1;
    incident = {
      id: `i${engine.incidentSeq}`,
      device: device.id,
      stages: new Set(),
      raw: 0,
      score: 0,
      severity: 'medium',
      anomalyIds: [],
      detectors: [],
      firstTs: anomaly.ts,
      lastTs: anomaly.ts,
      lines: [],
      groupWeight: new Map(),
    };
    device.incident = incident;
  } else {
    decay(incident, Math.max(0, anomaly.ts - incident.lastTs));
  }
  const stage = /** @type {Record<string, string>} */ (STAGES)[anomaly.detector];
  if (stage) incident.stages.add(stage);
  addWeight(incident, anomaly);
  incident.lastTs = anomaly.ts;
  incident.anomalyIds.push(anomaly.id);
  incident.detectors.push(anomaly.detector);
  if (incident.lines.length < 8) incident.lines.push(`${anomaly.detector}: ${anomaly.actual}`);
  scoreOf(incident);
  anomaly.incidentId = incident.id;
  engine.emit('incident', payload(incident));
}

/**
 * Halve the score of the incident that contains this anomaly.
 * @param {any} engine
 * @param {string} anomalyId
 */
function ackIncident(engine, anomalyId) {
  for (const device of engine.devices.values()) {
    const incident = device.incident;
    if (!incident || !incident.anomalyIds.includes(anomalyId)) continue;
    incident.raw *= 0.5;
    scoreOf(incident);
    engine.emit('incident', payload(incident));
    return;
  }
}

module.exports = { noteIncident, ackIncident };
