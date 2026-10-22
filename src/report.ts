import type { Finding, Rule, Severity } from "./types.js";

export type Format = "text" | "json" | "markdown" | "sarif";

export const formats: Format[] = ["text", "json", "markdown", "sarif"];

function counts(findings: Finding[]): Record<Severity, number> {
  const c: Record<Severity, number> = { high: 0, medium: 0, low: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}

function summary(findings: Finding[], files: number): string {
  const c = counts(findings);
  return `${String(files)} file(s), ${String(findings.length)} finding(s): ${String(c.high)} high, ${String(c.medium)} medium, ${String(c.low)} low`;
}

export function render(
  findings: Finding[],
  format: Format,
  opts: { files: number; rules: Rule[]; version: string },
): string {
  switch (format) {
    case "json":
      return JSON.stringify({ findings, summary: counts(findings) }, null, 2) + "\n";
    case "markdown":
      return markdown(findings, opts.files);
    case "sarif":
      return JSON.stringify(sarif(findings, opts.rules, opts.version), null, 2) + "\n";
    case "text":
      return text(findings, opts.files);
  }
}

function text(findings: Finding[], files: number): string {
  const lines = findings.map((f) => {
    const fix = f.fixable ? " [fixable]" : "";
    return `${f.file}:${String(f.line)}  ${f.severity.toUpperCase().padEnd(6)} ${f.ruleId}  ${f.message}${fix}`;
  });
  return [...lines, lines.length ? "" : "No problems found.", summary(findings, files), ""].join("\n");
}

function markdown(findings: Finding[], files: number): string {
  const icon = findings.some((f) => f.severity === "high") ? "🛑" : findings.length ? "⚠️" : "✅";
  const out = [`### ${icon} gha-guard`, "", summary(findings, files), ""];
  if (findings.length) {
    out.push("| Severity | Rule | Location | Problem | How to fix |", "|---|---|---|---|---|");
    for (const f of findings) {
      const esc = (s: string | undefined) => (s ?? "").replaceAll("|", "\\|");
      out.push(
        `| ${f.severity} | ${f.ruleId} | \`${f.file}:${String(f.line)}\` | ${esc(f.message)} | ${esc(f.help)} |`,
      );
    }
  }
  return out.join("\n") + "\n";
}

const sarifLevel: Record<Severity, string> = { high: "error", medium: "warning", low: "note" };
const securitySeverity: Record<Severity, string> = { high: "8.0", medium: "5.0", low: "2.0" };

function sarif(findings: Finding[], rules: Rule[], version: string) {
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "gha-guard",
            version,
            informationUri: "https://github.com/OTA-EITA/gha-guard",
            rules: rules.map((r) => ({
              id: r.id,
              name: r.title,
              shortDescription: { text: r.title },
              fullDescription: { text: r.description },
              defaultConfiguration: { level: sarifLevel[r.severity] },
              properties: {
                tags: ["security", "github-actions"],
                "security-severity": securitySeverity[r.severity],
              },
            })),
          },
        },
        results: findings.map((f) => ({
          ruleId: f.ruleId,
          level: sarifLevel[f.severity],
          message: { text: f.help ? `${f.message}. ${f.help}` : f.message },
          locations: [
            { physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line } } },
          ],
        })),
      },
    ],
  };
}
