import { describe, expect, it } from "vitest";
import { render } from "../src/report.js";
import { rules } from "../src/rules/index.js";
import type { Finding } from "../src/types.js";

const findings: Finding[] = [
  {
    ruleId: "GHA001",
    severity: "high",
    file: ".github/workflows/a.yml",
    line: 7,
    message: "bad | input",
    help: "use env",
    fixable: true,
  },
  { ruleId: "GHA006", severity: "low", file: ".github/workflows/a.yml", line: 3, message: "creds" },
];
const opts = { files: 1, rules, version: "1.2.3" };

describe("render", () => {
  it("text", () => {
    const out = render(findings, "text", opts);
    expect(out).toContain(".github/workflows/a.yml:7  HIGH   GHA001  bad | input [fixable]");
    expect(out).toContain("1 file(s), 2 finding(s): 1 high, 0 medium, 1 low");
    expect(render([], "text", opts)).toContain("No problems found.");
  });

  it("markdown escapes pipes", () => {
    const out = render(findings, "markdown", opts);
    expect(out).toContain("### 🛑 gha-guard");
    expect(out).toContain("bad \\| input");
    expect(render([], "markdown", opts)).toContain("### ✅ gha-guard");
    expect(render(findings.slice(1), "markdown", opts)).toContain("### ⚠️ gha-guard");
  });

  it("json", () => {
    const out = JSON.parse(render(findings, "json", opts)) as { summary: Record<string, number> };
    expect(out.summary).toEqual({ high: 1, medium: 0, low: 1 });
  });

  it("sarif", () => {
    const out = JSON.parse(render(findings, "sarif", opts)) as {
      version: string;
      runs: {
        tool: { driver: { version: string; rules: unknown[] } };
        results: { level: string; locations: { physicalLocation: { region: { startLine: number } } }[] }[];
      }[];
    };
    const run = out.runs[0];
    expect(out.version).toBe("2.1.0");
    expect(run?.tool.driver.version).toBe("1.2.3");
    expect(run?.tool.driver.rules).toHaveLength(rules.length);
    expect(run?.results[0]?.level).toBe("error");
    expect(run?.results[0]?.locations[0]?.physicalLocation.region.startLine).toBe(7);
  });
});
