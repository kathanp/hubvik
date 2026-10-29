export function parseMud(text: string): {
  allows: Array<{
    dstPort?: number;
    proto?: string;
    domain?: string;
    direction?: 'out' | 'in';
  }>;
};
export function loadMudFile(file: string): {
  allows: Array<{
    dstPort?: number;
    proto?: string;
    domain?: string;
    direction?: 'out' | 'in';
  }>;
};
