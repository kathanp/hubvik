'use strict';

const SEVERITY = {
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

/**
 * Map one anomaly to an OCSF Detection Finding (class_uid 2004).
 * @param {{ id?: string, device?: string, detector?: string, severity?: string, confidence?: number, ts?: number, actual?: string, expected?: string, attack?: string[] }} anomaly
 */
function toFinding(anomaly) {
  const severity = anomaly && SEVERITY[anomaly.severity] ? anomaly.severity : 'info';
  const ts = anomaly && typeof anomaly.ts === 'number' ? anomaly.ts : 0;
  return {
    class_uid: 2004,
    class_name: 'Detection Finding',
    category_uid: 2,
    category_name: 'Findings',
    activity_id: 1,
    activity_name: 'Create',
    type_uid: 200401,
    type_name: 'Detection Finding: Create',
    severity_id: SEVERITY[severity],
    severity,
    time: ts,
    confidence: anomaly && typeof anomaly.confidence === 'number' ? anomaly.confidence : 0,
    message: anomaly && anomaly.actual ? String(anomaly.actual) : '',
    finding_info: {
      uid: anomaly && anomaly.id ? String(anomaly.id) : '',
      title: anomaly && anomaly.detector ? String(anomaly.detector) : '',
      desc: anomaly && anomaly.expected ? String(anomaly.expected) : '',
    },
    device: { uid: anomaly && anomaly.device ? String(anomaly.device) : '' },
    attacks: Array.isArray(anomaly && anomaly.attack) ? anomaly.attack.map(String) : [],
    metadata: { product: { name: 'iotwarden', vendor_name: 'iotwarden' }, version: '1.1.0' },
  };
}

module.exports = { toFinding };
