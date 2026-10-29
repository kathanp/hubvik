export function parseIndicators(
  text: string,
  opts?: { source?: string; expiresTs?: number; max?: number },
): Array<{
  value: string;
  type: string;
  source: string;
  confidence: number;
  expiresTs: number | null;
}>;
export function loadIndicatorFile(
  file: string,
  opts?: { source?: string; expiresTs?: number; max?: number },
): Array<{
  value: string;
  type: string;
  source: string;
  confidence: number;
  expiresTs: number | null;
}>;
