export type Severity = "high" | "medium" | "low";

export const severityRank: Record<Severity, number> = { high: 3, medium: 2, low: 1 };

export interface Finding {
  ruleId: string;
  severity: Severity;
  file: string;
  line: number;
  /** 1-based column, when the finding points into a line (e.g. at an expression). */
  column?: number;
  message: string;
  /** How to fix it by hand; set when no automatic fix exists. */
  help?: string;
  /** True when `--fix` can rewrite the file. */
  fixable?: boolean;
}

export interface Rule {
  id: string;
  severity: Severity;
  title: string;
  description: string;
}
