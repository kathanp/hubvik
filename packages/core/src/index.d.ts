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
  detectors: Record<string, { active: boolean; reason: string | null }>;
}

export class Engine extends EventEmitter {
  constructor(opts?: EngineOptions);
  feed(event: SummaryEvent): void;
  feedBatch(events: SummaryEvent[]): void;
  flush(now?: number): void;
  lock(device?: string): void;
  relearn(device: string, opts?: { detectors?: string[] }): void;
  allow(device: string, kind: AllowKind, value: string): void;
  suppress(device: string, detector: string, opts?: { untilTs?: number; match?: string }): void;
  ack(anomalyId: string): void;
  forget(device: string): void;
  setPeerGroup(device: string, groupId: string | null): void;
  use(detector: Detector): void;
  loadIndicators(indicators: object[]): void;
  exportBaseline(opts?: {
    devices?: string[];
    createdAt?: number;
    sign?: string | Buffer;
  }): Baseline;
  importBaseline(baseline: object, opts?: { merge?: boolean; verify?: string | Buffer }): void;
  stats(): EngineStats;
  on(event: 'anomaly', listener: (anomaly: Anomaly) => void): this;
  on(event: 'learned', listener: (payload: { device: string; ts: number }) => void): this;
  on(
    event: 'device-new',
    listener: (payload: { device: string; ts: number; firstEvent: { ts: number } }) => void,
  ): this;
  on(
    event: 'warning',
    listener: (payload: { code: string; message: string; device?: string }) => void,
  ): this;
  on(event: string | symbol, listener: (...args: unknown[]) => void): this;
}

export function createEngine(opts?: EngineOptions): Engine;
export const detectors: Record<string, Detector>;
