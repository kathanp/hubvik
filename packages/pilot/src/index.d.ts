export function createRunner(opts: { stateDir: string; conntrack?: string; dnsmasq?: string }): {
  engine: { feed: (event: object) => void; flush: (now: number) => void; stats: () => object };
  step: (now: number) => void;
  stop: (now: number) => void;
};

export function writeReport(opts: {
  stateDir: string;
  weekStart: number;
  weekEnd: number;
  out: string;
}): void;

export function queueLabel(
  stateDir: string,
  row: { key: string; verdict: string; note?: string; detector?: string },
): void;
