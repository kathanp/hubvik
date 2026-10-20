'use strict';

/**
 * Prometheus text for an engine stats() object.
 * @param {any} stats
 */
function toText(stats) {
  const snap = stats || {};
  const lines = [
    '# HELP hubvik_events_total Events fed to the engine',
    '# TYPE hubvik_events_total counter',
    `hubvik_events_total ${num(snap.events)}`,
    `hubvik_anomalies_total ${num(snap.anomalies)}`,
    `hubvik_warnings_total ${num(snap.warnings)}`,
    `hubvik_devices ${num(snap.devices)}`,
    `hubvik_memory_bytes ${num(snap.memoryBytes)}`,
    `hubvik_watermark_lag_ms 0`,
  ];
  const learning = snap.learningQuality || {};
  let learningN = 0;
  let watchingN = 0;
  for (const row of Object.values(learning)) {
    if (row && row.ready) watchingN += 1;
    else learningN += 1;
  }
  lines.push(`hubvik_devices_learning ${learningN}`);
  lines.push(`hubvik_devices_watching ${watchingN}`);
  const shed = Array.isArray(snap.shed) ? snap.shed.length : 0;
  lines.push(`hubvik_shed_tiers ${shed}`);
  return `${lines.join('\n')}\n`;
}

/**
 * @param {unknown} value
 */
function num(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

module.exports = { toText };
