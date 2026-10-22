// GitHub Action entry point. Inputs arrive as INPUT_* environment variables;
// outputs and the job summary are written to the files GitHub provides.
import { appendFileSync, writeFileSync } from "node:fs";
import { render } from "./report.js";
import { rules } from "./rules/index.js";
import { scan } from "./run.js";
import { severityRank } from "./types.js";
import type { Severity } from "./types.js";

function input(name: string, fallback: string): string {
  const v = process.env[`INPUT_${name.toUpperCase()}`];
  return v === undefined || v === "" ? fallback : v.trim();
}

async function run(): Promise<void> {
  const paths = input("path", ".").split(/\s+/).filter(Boolean);
  const failOn = input("fail-on", "high");
  const sarifFile = input("sarif-file", "gha-guard.sarif");
  const result = await scan(paths, { fix: false, cwd: process.cwd() });

  writeFileSync(
    sarifFile,
    render(result.findings, "sarif", { files: result.files, rules, version: "action" }),
  );
  const summary = process.env.GITHUB_STEP_SUMMARY;
  if (summary)
    appendFileSync(
      summary,
      render(result.findings, "markdown", { files: result.files, rules, version: "action" }),
    );
  const output = process.env.GITHUB_OUTPUT;
  if (output) appendFileSync(output, `sarif-file=${sarifFile}\nfindings=${String(result.findings.length)}\n`);

  for (const f of result.findings) {
    const level = f.severity === "high" ? "error" : f.severity === "medium" ? "warning" : "notice";
    process.stdout.write(
      `::${level} file=${f.file},line=${String(f.line)},title=${f.ruleId}::${f.message}\n`,
    );
  }
  if (
    failOn !== "none" &&
    result.findings.some((f) => severityRank[f.severity] >= severityRank[failOn as Severity])
  ) {
    process.exitCode = 1;
  }
}

run().catch((err: unknown) => {
  process.stdout.write(`::error::${String(err)}\n`);
  process.exitCode = 1;
});
