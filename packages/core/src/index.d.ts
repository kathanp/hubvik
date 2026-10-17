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
  'dst' | 'port' | 'asn' | 'country' | 'ja4' | 'certIssuer' | 'resolver' | 'peer';

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
    | 'smtp';
  role: 'client' | 'server';
  peerIp: string;
  op: string;
  target?: string;
  value?: number | string;
  result?: 'ok' | 'error' | 'reject';
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
  | DhcpEvent;

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
  type: 'ip' | 'cidr' | 'domain' | 'ja4' | 'tor' | 'ad' | 'proxy-sdk';
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
  detectors?: Record<string, { enabled?: boolean; severity?: Severity; [key: string]: unknown }>;
  policy?: PolicyRule[];
  lookup?: (ip: string) => { asn?: string | null; country?: string | null } | null;
  gatewayIp?: string;
  dhcpServers?: string[];
  routers?: string[];
  zones?: { id: string; cidr: string }[];
  incidentWindowMs?: number;
  browserJa4?: string[];
  reorderMs?: number;
  minLearnWindows?: number;
  tierSilentMs?: number;
  evidence?: boolean;
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
  exportBaseline(opts?: {
    devices?: string[];
    createdAt?: number;
    sign?: string | Buffer;
  }): Baseline;
  importBaseline(baseline: object, opts?: { merge?: boolean; verify?: string | Buffer }): void;
  checkpoint(opts?: { devices?: string[]; createdAt?: number; sign?: string | Buffer }): object;
  restore(checkpoint: object, opts?: { verify?: string | Buffer }): void;
  stats(): EngineStats;
  on(event: 'anomaly', listener: (anomaly: Anomaly) => void): this;
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
    }) => void,
  ): this;
  on(event: string | symbol, listener: (...args: unknown[]) => void): this;
}

export function createEngine(opts?: EngineOptions): Engine;
export const detectors: Record<string, Detector>;
