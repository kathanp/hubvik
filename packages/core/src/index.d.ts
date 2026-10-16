import { EventEmitter } from 'node:events';

/** Severity labels the 0.0.1 prototype emits. Phase 1 adds info and critical. */
export type Severity = 'low' | 'medium' | 'high';

/** Connection summary. Tier T0. */
export interface SummaryEvent {
  device: string;
  dst?: string;
  bytes?: number;
  ts?: number;
}

/** Anomaly emitted on the `anomaly` event by the 0.0.1 prototype. */
export interface Anomaly {
  device: string;
  detector: string;
  severity: Severity;
  ts: number;
  actual: string;
  expected: string;
}

/** Options for {@link createEngine}. */
export interface EngineOptions {
  learnMs?: number;
  windowMs?: number;
  sigma?: number;
  minFanout?: number;
  minBytes?: number;
  maxNewDstPerWindow?: number;
  hourOf?: (ts: number) => number;
}

/** Per-device slice of a version-1 baseline. */
export interface DeviceBaseline {
  dsts: string[];
  hours: number[];
  winBytes: number[];
  winFanout: number[];
}

/** Version-1 baseline written by the 0.0.1 prototype. */
export interface Baseline {
  version: 1;
  devices: Record<string, DeviceBaseline>;
}

/**
 * Per-device learning engine. Reports anomalies. Never blocks traffic.
 */
export class Engine extends EventEmitter {
  constructor(opts?: EngineOptions);
  learnMs: number;
  windowMs: number;
  sigma: number;
  minFanout: number;
  minBytes: number;
  maxNewDstPerWindow: number;
  hourOf: (ts: number) => number;
  feed(event: SummaryEvent): void;
  flush(): void;
  lock(): void;
  exportBaseline(): Baseline;
  importBaseline(baseline: Baseline): void;
  on(event: 'anomaly', listener: (anomaly: Anomaly) => void): this;
  on(event: string | symbol, listener: (...args: any[]) => void): this;
}

/**
 * Create an engine. Same as `new Engine(opts)`.
 * @param opts Learning window, thresholds, and the hour function.
 */
export function createEngine(opts?: EngineOptions): Engine;
