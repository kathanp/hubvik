export function parseDecisions(
  text: string,
  opts?: { now?: number; source?: string; max?: number },
): Array<{
  value: string;
  type: string;
  source: string;
  confidence: number;
  expiresTs: number | null;
}>;
export function loadDecisionsFile(
  file: string,
  opts?: { now?: number; source?: string; max?: number },
): Array<{
  value: string;
  type: string;
  source: string;
  confidence: number;
  expiresTs: number | null;
}>;
