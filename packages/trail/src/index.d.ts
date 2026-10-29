export function parseTrail(
  text: string,
  opts?: { source?: string; max?: number },
): Array<{
  value: string;
  type: string;
  source: string;
  confidence: number;
  expiresTs: null;
}>;
export function loadTrailFile(
  file: string,
  opts?: { source?: string; max?: number },
): Array<{
  value: string;
  type: string;
  source: string;
  confidence: number;
  expiresTs: null;
}>;
