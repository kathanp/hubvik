'use strict';

/**
 * A complete flow event. Extra fields override the defaults.
 * @param {Record<string, unknown>} [extra]
 */
function flow(extra = {}) {
  return {
    type: 'flow',
    device: 'd',
    ts: 1000,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '1.2.3.4',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 100,
    bytesIn: 80,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 40,
    ...extra,
  };
}

module.exports = { flow };
