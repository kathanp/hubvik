'use strict';

const SEVERITY = {
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

/**
 * Map one anomaly or an escalated incident to an OCSF Detection Finding.
 * @param {any} record
 * @param {{ ocsfVersion?: string }} [opts]
 */
function toFinding(record, opts = {}) {
  const version = opts && opts.ocsfVersion ? String(opts.ocsfVersion) : '1.4.0';
  const update = Boolean(
    record &&
    (Array.isArray(record.anomalyIds) ||
      (Array.isArray(record.devices) && Array.isArray(record.edges))),
  );
  const severity = record && SEVERITY[record.severity] ? record.severity : 'info';
  const ts = record && typeof record.ts === 'number' ? record.ts : 0;
  const attacks = Array.isArray(record && record.attack) ? record.attack.map(String) : [];
  const uid =
    record && record.fingerprint
      ? String(record.fingerprint)
      : record && record.id
        ? String(record.id)
        : '';
  /** @type {Record<string, unknown>} */
  const finding = {
    class_uid: 2004,
    class_name: 'Detection Finding',
    category_uid: 2,
    category_name: 'Findings',
    activity_id: update ? 2 : 1,
    activity_name: update ? 'Update' : 'Create',
    type_uid: update ? 200402 : 200401,
    type_name: update ? 'Detection Finding: Update' : 'Detection Finding: Create',
    severity_id: SEVERITY[severity],
    severity,
    time: ts,
    confidence: record && typeof record.confidence === 'number' ? record.confidence : 0,
    message: update
      ? record && record.summary
        ? String(record.summary)
        : ''
      : record && record.actual
        ? String(record.actual)
        : '',
    finding_info: {
      uid,
      title: record && record.detector ? String(record.detector) : '',
      desc:
        record && typeof record.explain === 'string'
          ? record.explain
          : record && record.expected
            ? String(record.expected)
            : '',
      attacks: attacks.map((technique) => ({ technique: { uid: technique } })),
    },
    device: { uid: record && record.device ? String(record.device) : '' },
    attacks,
    metadata: {
      version,
      product: { name: 'iotwarden', vendor_name: 'iotwarden' },
    },
  };
  if (record && record.evidence && Array.isArray(record.evidence.sample)) {
    finding.evidences = record.evidence.sample.map((item) => ({ data: item }));
  }
  return finding;
}

module.exports = { toFinding };
