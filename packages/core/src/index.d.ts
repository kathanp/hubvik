import { EventEmitter } from 'node:events';

export const SEVERITY: {
  readonly info: 0;
  readonly low: 1;
  readonly medium: 2;
  readonly high: 3;
  readonly critical: 4;
};

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Tier = 'T0' | 'T1' | 'T2' | 'T3' | 'T4' | 'T5';
export type AllowKind =
  'dst' | 'port' | 'asn' | 'country' | 'ja4' | 'certIssuer' | 'resolver' | 'peer' | 'fingerprint';

export interface SummaryEvent {
  device: string;
  dst?: string;
  bytes?: number;
  ts?: number;
}

export interface FlowEvent {
  type: 'flow';
  device: string;
  ts?: number;
  srcIp?: string;
  srcPort?: number;
  dstIp?: string;
  dstPort?: number;
  proto?: string;
  direction?: 'out' | 'in' | 'lan';
  bytesOut?: number;
  bytesIn?: number;
  pktsOut?: number;
  pktsIn?: number;
  durationMs?: number;
  tcpOutcome?: 'established' | 'rejected' | 'no-response' | 'reset';
  /** Sensor connection id. With `correlate: true`, a stored DNS or TLS name is copied here. */
  uid?: string;
  icmpType?: number;
  ttl?: number;
  dstName?: string;
  dst?: string;
  bytes?: number;
}

export interface DnsAnswer {
  type: string;
  value: string;
  ttl?: number;
}

export interface DnsEvent {
  type: 'dns';
  device: string;
  ts?: number;
  qname: string;
  qtype?: string;
  rcode?: string;
  resolver?: string;
  answers?: DnsAnswer[];
  /** Sensor connection id shared with the flow this query belongs to. */
  uid?: string;
}

export interface DhcpEvent {
  type: 'dhcp';
  device: string;
  ts?: number;
  mac: string;
  msg: string;
  serverIp?: string;
  requestedIp?: string;
  fingerprint?: string;
  v6?: boolean;
  duid?: string;
  iaid?: number;
}

export interface NdEvent {
  type: 'nd';
  device: string;
  ts?: number;
  ip: string;
  mac: string;
  op: 'na' | 'ns' | 'rs' | 'ra';
  router?: boolean;
}

export interface DiscoveryEvent {
  type: 'discovery';
  device: string;
  ts?: number;
  proto?: 'mdns' | 'ssdp' | 'ws-discovery' | 'coap';
  srcIp: string;
  direction: 'out' | 'in' | 'lan';
}

export interface MappingEvent {
  type: 'mapping';
  device: string;
  ts?: number;
  proto: 'upnp' | 'nat-pmp' | 'pcp';
  port: number;
  externalPort?: number;
}

export interface TlsCert {
  issuer?: string;
  subject?: string;
  sha256?: string;
  selfSigned?: boolean;
  notBefore?: number;
  notAfter?: number;
}

export interface TlsEvent {
  type: 'tls';
  device: string;
  ts?: number;
  dstIp: string;
  dstPort: number;
  sni?: string;
  ja4?: string;
  version?: string;
  alpn?: string[];
  cert?: TlsCert;
  /** Sensor connection id shared with the flow this handshake belongs to. */
  uid?: string;
}

export interface HttpEvent {
  type: 'http';
  device: string;
  ts?: number;
  dstIp: string;
  dstPort: number;
  method: string;
  host?: string;
  path?: string;
  status?: number;
  direction?: 'out' | 'in';
}

export interface AppEvent {
  type: 'app';
  device: string;
  ts?: number;
  proto:
    | 'bacnet'
    | 'modbus'
    | 'dnp3'
    | 'knx'
    | 's7'
    | 'enip'
    | 'mqtt'
    | 'coap'
    | 'rtsp'
    | 'onvif'
    | 'stratum'
    | 'smtp'
    | 'upnp'
    | 'matter';
  role: 'client' | 'server';
  peerIp: string;
  op: string;
  target?: string;
  value?: number | string;
  result?: 'ok' | 'error' | 'reject';
}

export interface WifiEvent {
  type: 'wifi';
  device: string;
  ts?: number;
  mac: string;
  bssid?: string;
  ssid?: string;
  op: 'assoc' | 'disassoc' | 'deauth' | 'auth-fail';
  reason?: number;
}

export type FeedEvent =
  | SummaryEvent
  | FlowEvent
  | DnsEvent
  | MappingEvent
  | TlsEvent
  | HttpEvent
  | AppEvent
  | DiscoveryEvent
  | DhcpEvent
  | NdEvent
  | WifiEvent;

export interface PolicyRule {
  id: string;
  severity?: Severity;
  match: {
    direction?: 'out' | 'in' | 'lan';
    proto?: string;
    port?: number | number[];
    hour?: number | number[];
    dst?: string | string[];
  };
}

export interface Indicator {
  value: string;
  type: 'ip' | 'cidr' | 'domain' | 'ja4' | 'tor' | 'ad' | 'tracker' | 'proxy-sdk' | 'young-domain';
  source: string;
  confidence?: number;
  expiresTs?: number | null;
}

export interface Anomaly {
  id: string;
  device: string;
  detector: string;
  category: string;
  severity: Severity;
  confidence: number;
  ts: number;
  actual: string;
  expected: string;
  data: Record<string, unknown>;
  attack?: string[];
  hardRule: boolean;
  incidentId?: string;
  shadow?: boolean;
  schema: 1;
  fingerprint: string;
  dedupGroup?: string;
  context?: { annotationId: string; kind: string }[];
  llr?: number;
  criticality?: 'low' | 'normal' | 'high' | 'safety';
  evidence?: {
    events: number;
    sample: Record<string, unknown>[];
    window?: { start: number; end: number };
    baseline?: string;
  };
}

export interface Incident {
  id: string;
  device: string;
  stages: string[];
  score: number;
  severity: Severity;
  anomalyIds: string[];
  firstTs: number;
  lastTs: number;
  summary: string;
  posterior?: number;
  contributions?: { detector: string; llr: number; anomalyId: string }[];
}

export interface EngineOptions {
  learnMs?: number;
  windowMs?: number;
  tiers?: Tier[];
  sigma?: number;
  minBytes?: number;
  minFanout?: number;
  fanoutFactor?: number;
  peakFactor?: number;
  maxNewDstPerWindow?: number;
  maxDevices?: number;
  maxDestinations?: number;
  maxAlertKeys?: number;
  maxWindows?: number;
  maxWindowDestinations?: number;
  maxIndicators?: number;
  hourOf?: (ts: number) => number;
  dayOf?: (ts: number) => number;
  detectors?: Record<
    string,
    {
      enabled?: boolean;
      severity?: Severity;
      mode?: 'live' | 'shadow';
      canary?: Record<string, unknown>;
      [key: string]: unknown;
    }
  >;
  policy?: PolicyRule[];
  lookup?: (ip: string) => { asn?: string | null; country?: string | null } | null;
  gatewayIp?: string;
  dhcpServers?: string[];
  routers?: string[];
  zones?: { id: string; cidr: string }[];
  incidentWindowMs?: number;
  browserJa4?: string[];
  reorderMs?: number;
  maxBuffered?: number;
  minLearnWindows?: number;
  tierSilentMs?: number;
  tierSilentByTier?: Partial<Record<'T0' | 'T1' | 'T2' | 'T3' | 'T4' | 'T5', number>>;
  evidence?: boolean;
  explainCap?: number;
  identity?: 'off' | 'auto';
  promote?: false | { afterDays?: number; minHits?: number };
  horizons?: boolean;
  graph?: boolean;
  campaigns?: boolean;
  /** false: shadow detectors stay off. true: all of them. An array runs only those ids. */
  shadow?: boolean | string[];
  linkMs?: number;
  ownBssids?: string[];
  budget?:
    | false
    | {
        perEventUs?: number;
        sampleEvery?: number;
        recoverWindows?: number;
        clock?: () => bigint;
      };
  calibratedConfidence?: boolean;
  classSuggest?: boolean;
  responseHints?: boolean;
  /** Default `additive`. `lr` scores incidents with the likelihood-ratio posterior. */
  scoring?: 'additive' | 'lr';
  /** Default false. When true, the engine also emits `alert`. */
  alerts?: boolean;
  /** Default false. Per-device baseline drift warnings. */
  drift?: boolean;
  /** Default false. Hash-chained log of operator actions. */
  audit?: boolean;
  /** Default false. Suggest peer groups. Never calls setPeerGroup. */
  peerSuggest?: boolean;
  /** Default false. Per-class half-space-tree model. */
  outlier?: boolean;
  /** Default false. Per-device behavior sequence model. */
  sequence?: boolean;
  /** Default false. First-packet flow-shape histograms. */
  flowShape?: boolean;
  /**
   * Default false. Alpha-investing on live anomalies. Holds `alert` when the
   * discovered weight is under the bar. Adds `data.fdr` only while true.
   */
  fdr?: boolean;
  /**
   * Default false. Join DNS and TLS names onto a later flow that carries the
   * same `uid`. The anomaly stream is unchanged while this is false.
   */
  correlate?: boolean;
  redact?:
    | {
        key: string | Buffer;
        fields?: string[];
        redactMap?: (token: string, value: string) => void;
      }
    | false;
}

export interface Baseline {
  version: 2;
  createdAt: number;
  engine: { windowMs: number; pkg: string };
  devices: Record<
    string,
    { peerGroup: string | null; detectors: Record<string, { v: number; state: unknown }> }
  >;
  sig?: { alg: 'HMAC-SHA256'; mac: string };
}

export interface Detector {
  id: string;
  version: number;
  requires: Tier[];
  defaults: Record<string, unknown>;
  hardRule?: boolean;
  category?: string;
  meta?: {
    rel?: string;
    mode?: 'live' | 'shadow';
    explains?: boolean;
    fpRisk?: string;
    consumes?: Array<
      | 'summary'
      | 'flow'
      | 'dns'
      | 'tls'
      | 'http'
      | 'arp'
      | 'dhcp'
      | 'ra'
      | 'discovery'
      | 'mapping'
      | 'app'
    >;
  };
}

export interface EngineStats {
  events: number;
  anomalies: number;
  warnings: number;
  devices: number;
  indicators: number;
  allows: number;
  suppresses: number;
  acks: number;
  memoryBytes: number;
  watermark: number | null;
  learningQuality: Record<
    string,
    { windowsActive: number; families: number; suspicious: string[]; ready: boolean }
  >;
  detectors: Record<string, { active: boolean; reason: string | null }>;
  shadow: Record<
    string,
    {
      fired: number;
      devices: number;
      bySeverity: Record<string, number>;
      wouldJoinIncident: number;
    }
  >;
  canary: Record<string, { liveOnly: number; canaryOnly: number; both: number }>;
  identity: { rows: number; rekeyed: number; unresolved: number };
  peerSuggestions?: { groupId: string; devices: string[]; meanJaccard: number }[];
  precision: Record<
    string,
    {
      tp: number;
      fp: number;
      benign: number;
      unknown: number;
      fpRate: number;
      interval: { low: number; high: number };
    }
  >;
}

export class Engine extends EventEmitter {
  constructor(opts?: EngineOptions);
  feed(event: FeedEvent): void;
  feedBatch(events: FeedEvent[]): void;
  flush(now?: number): void;
  tick(now?: number): void;
  lock(device?: string): void;
  relearn(device: string, opts?: { detectors?: string[] }): void;
  allow(device: string, kind: AllowKind, value: string): void;
  suppress(device: string, detector: string, opts?: { untilTs?: number; match?: string }): void;
  ack(anomalyId: string): void;
  forget(device: string): void;
  setPeerGroup(device: string, groupId: string | null): void;
  setDeviceClass(device: string, classId: string): void;
  use(detector: Detector): void;
  loadIndicators(indicators: Indicator[]): void;
  loadRules(rules: object[]): void;
  annotate(
    target: string,
    spec: {
      kind: 'maintenance' | 'firmware-update' | 'user-action' | 'network-change';
      fromTs: number;
      untilTs: number;
      detectors?: string[];
      note?: string;
      operator?: string;
    },
  ): string;
  removeAnnotation(id: string): boolean;
  annotations(query?: { device?: string; activeAt?: number }): object[];
  setDeviceCriticality(device: string, level: 'low' | 'normal' | 'high' | 'safety'): void;
  loadTemplates(list: object[]): void;
  auditLog(opts?: { sinceSeq?: number }): object[];
  verifyAudit(): { ok: boolean; brokenAt?: number };
  exportBaseline(opts?: {
    devices?: string[];
    createdAt?: number;
    sign?: string | Buffer;
  }): Baseline;
  importBaseline(baseline: object, opts?: { merge?: boolean; verify?: string | Buffer }): void;
  checkpoint(opts?: { devices?: string[]; createdAt?: number; sign?: string | Buffer }): object;
  restore(checkpoint: object, opts?: { verify?: string | Buffer }): void;
  checkpointDelta(sinceSeq: number, opts?: { sign?: string | Buffer }): object;
  applyDelta(delta: object, opts?: { sign?: string | Buffer }): void;
  setDeviceTimezone(device: string, ianaZone: string): void;
  loadMud(device: string, acl: { allows: object[] } | null): void;
  exportSummary(opts: { key: string | Buffer; gatewayId: string }): object;
  importPeerSummaries(list: object[], opts?: { verify?: string | Buffer }): void;
  stats(): EngineStats;
  resolve(ip: string): string | null;
  feedback(
    key: string,
    verdict: 'tp' | 'fp' | 'benign-true' | 'unknown',
    opts?: { operator?: string; note?: string },
  ): void;
  exportLabels(): string;
  digest(sinceTs: number): {
    sinceTs: number;
    devices: Array<{ device: string; count: number; text: string }>;
  };
  inventory(): Array<{
    device: string;
    lastSeen: number | null;
    class: string | null;
    addresses: string[];
    ports: number[];
    protocols: string[];
    apps: string[];
    suggestions?: Array<{ class: string; score: number; reasons: string[] }>;
  }>;
  exportDecisions(): string;
  counts(sinceTs: number): {
    sinceTs: number;
    detectors: Array<{ detector: string; count: number; devices: number }>;
  };
  hints(sinceTs: number): {
    sinceTs: number;
    hints: Array<{
      device: string;
      detector: string;
      ts: number;
      action: 'review' | 'relearn' | 'isolate-device' | 'block-destination' | 'rate-limit';
      target: string;
      reversible: true;
      minConfidence: number;
    }>;
  };
  noisy(): Array<{ detector: string; fpRate: number; n: number }>;
  quiet(
    now: number,
    quietMs: number,
  ): { now: number; quietMs: number; devices: Array<{ device: string; lastSeen: number }> };
  attacks(sinceTs: number): {
    sinceTs: number;
    devices: Array<{
      device: string;
      count: number;
      firstTs: number;
      lastTs: number;
      detectors: string[];
      stages: string[];
      techniques: string[];
      destinations: string[];
      progressing: boolean;
    }>;
  };
  shadow(sinceTs: number): {
    sinceTs: number;
    devices: Array<{
      device: string;
      count: number;
      firstTs: number;
      lastTs: number;
      detectors: string[];
      stages: string[];
      techniques: string[];
      destinations: string[];
      progressing: boolean;
    }>;
  };
  campaigns(now: number): {
    now: number;
    campaigns: Array<{
      id: string;
      devices: string[];
      edges: Array<{ from: string; to: string; via: string; ts: number }>;
      stages: string[];
      score: number;
      severity: string;
      firstTs: number;
      lastTs: number;
    }>;
  };
  overview(
    now: number,
    sinceTs?: number,
  ): {
    now: number;
    sinceTs: number;
    attacks: Array<{
      device: string;
      count: number;
      firstTs: number;
      lastTs: number;
      detectors: string[];
      stages: string[];
      techniques: string[];
      destinations: string[];
      progressing: boolean;
    }>;
    waves: Array<{ detector: string; stage: string | null; devices: number; count: number }>;
    incidents: Array<{
      id: string;
      device: string;
      stages: string[];
      score: number;
      severity: string;
      detectors: string[];
      firstTs: number;
      lastTs: number;
    }>;
    campaigns: Array<{
      id: string;
      devices: string[];
      edges: Array<{ from: string; to: string; via: string; ts: number }>;
      stages: string[];
      score: number;
      severity: string;
      firstTs: number;
      lastTs: number;
    }>;
    shadow: Array<{
      device: string;
      count: number;
      firstTs: number;
      lastTs: number;
      detectors: string[];
      stages: string[];
      techniques: string[];
      destinations: string[];
      progressing: boolean;
    }>;
    counts: Array<{ detector: string; count: number; devices: number }>;
  };
  waves(sinceTs: number): {
    sinceTs: number;
    waves: Array<{ detector: string; stage: string | null; devices: number; count: number }>;
  };
  openIncidents(now: number): {
    now: number;
    incidents: Array<{
      id: string;
      device: string;
      stages: string[];
      score: number;
      severity: string;
      detectors: string[];
      firstTs: number;
      lastTs: number;
    }>;
  };
  explain(anomalyId: string): {
    anomalyId: string;
    detector: string;
    device: string;
    ts: number;
    test: 'gt' | 'gte' | 'lt' | 'new-member' | 'changed' | 'match' | 'sequence';
    observed: number | string;
    threshold?: number;
    formula?: string;
    learned?: Record<string, number | string>;
    margin?: number;
    evidence: unknown;
    suppressWith: Array<{ method: 'allow' | 'suppress' | 'relearn'; args: unknown[] }>;
  } | null;
  on(event: 'anomaly', listener: (anomaly: Anomaly) => void): this;
  on(event: 'shadow-anomaly', listener: (anomaly: Anomaly) => void): this;
  on(event: 'incident', listener: (incident: Incident) => void): this;
  on(event: 'learned', listener: (payload: { device: string; ts: number }) => void): this;
  on(
    event: 'device-new',
    listener: (payload: { device: string; ts: number; firstEvent: { ts: number } }) => void,
  ): this;
  on(
    event: 'warning',
    listener: (payload: {
      code: string;
      message: string;
      device?: string;
      reason?: string;
      ts?: number;
      detector?: string;
      value?: string;
    }) => void,
  ): this;
  on(event: string | symbol, listener: (...args: unknown[]) => void): this;
}

export function createEngine(opts?: EngineOptions): Engine;
export function createShardedEngine(opts: EngineOptions & { shards: number; inline: true }): Engine;
export const detectors: Record<string, Detector>;

export class HubvikError extends Error {
  readonly code: string;
  constructor(code: string, message: string, options?: ErrorOptions);
}
