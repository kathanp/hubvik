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
  type: 'ip' | 'cidr' | 'domain' | 'ja4' | 'tor' | 'ad' | 'proxy-sdk' | 'young-domain';
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
  exportBaseline(opts?: {
    devices?: string[];
    createdAt?: number;
    sign?: string | Buffer;
  }): Baseline;
  importBaseline(baseline: object, opts?: { merge?: boolean; verify?: string | Buffer }): void;
  checkpoint(opts?: { devices?: string[]; createdAt?: number; sign?: string | Buffer }): object;
  restore(checkpoint: object, opts?: { verify?: string | Buffer }): void;
  stats(): EngineStats;
  resolve(ip: string): string | null;
  feedback(
    key: string,
    verdict: 'tp' | 'fp' | 'benign-true' | 'unknown',
    opts?: { operator?: string; note?: string },
  ): void;
  exportLabels(): string;
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
export const detectors: Record<string, Detector>;
