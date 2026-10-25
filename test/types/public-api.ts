/**
 * Compile-only use of every public method and event.
 * Removing or renaming one fails `tsc --noEmit`.
 */
import {
  createEngine,
  createShardedEngine,
  detectors,
  HubvikError,
  SEVERITY,
  type Anomaly,
  type Engine,
  type Incident,
} from 'hubvik';

const engine: Engine = createEngine({
  learnMs: 0,
  tiers: ['T0'],
  outlier: false,
  sequence: false,
  flowShape: false,
  fdr: false,
  correlate: false,
});
engine.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: 1 });
engine.feedBatch([{ device: 'd', dst: 'b.example', bytes: 1, ts: 2 }]);
engine.flush(3);
engine.tick(4);
engine.lock('d');
engine.relearn('d', { detectors: ['new-destination'] });
engine.allow('d', 'dst', 'a.example');
engine.suppress('d', 'new-destination', { untilTs: 5 });
engine.ack('1');
engine.forget('d');
engine.setPeerGroup('d', 'g');
engine.setDeviceClass('d', 'camera');
engine.use(detectors['new-destination']);
engine.loadIndicators([{ value: 'tracker.test', type: 'tracker', source: 'test', confidence: 1 }]);
engine.loadRules([]);
engine.annotate('d', { kind: 'maintenance', fromTs: 1, untilTs: 2 });
engine.removeAnnotation('a1');
engine.annotations({ device: 'd' });
engine.setDeviceCriticality('d', 'safety');
engine.loadTemplates([]);
engine.auditLog();
engine.verifyAudit();
engine.exportBaseline({ createdAt: 1 });
engine.importBaseline({ version: 3, devices: {} });
engine.checkpoint({ createdAt: 1 });
engine.restore({});
engine.checkpointDelta(0);
engine.applyDelta({});
engine.setDeviceTimezone('d', 'UTC');
engine.loadMud('d', null);
engine.exportSummary({ key: 'k', gatewayId: 'gw' });
engine.importPeerSummaries([]);
engine.stats();
engine.resolve('10.0.0.1');
engine.feedback('1', 'tp', { operator: 'op' });
engine.exportLabels();
engine.explain('1');

engine.on('anomaly', (row: Anomaly) => {
  row.detector;
});
engine.on('shadow-anomaly', (row: Anomaly) => {
  row.shadow;
});
engine.on('incident', (row: Incident) => {
  row.id;
});
engine.on('learned', (row: { device: string; ts: number }) => {
  row.device;
});
engine.on('device-new', (row: { device: string; ts: number }) => {
  row.device;
});
engine.on('warning', (row: { code: string; message: string }) => {
  row.code;
});

const sharded: Engine = createShardedEngine({ shards: 2, inline: true, learnMs: 0 });
sharded.feed({ device: 'd', bytes: 1, ts: 1 });
sharded.flush();

const err: HubvikError = new HubvikError('DEVICE_ID_IS_INVALID', 'device id is invalid');
err.code;
SEVERITY.medium;
