import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { findFiles } from "./files.js";
import { fix } from "./fix.js";
import { analyze } from "./rules/index.js";
import type { Finding } from "./types.js";
import { parseWorkflow, WorkflowParseError } from "./workflow.js";
import type { Workflow } from "./workflow.js";

/** Parses a file, turning a YAML error into a GHA000 finding instead of stopping the scan. */
function load(file: string, source: string, findings: Finding[]): Workflow | null {
  try {
    return parseWorkflow(file, source);
  } catch (err) {
    if (!(err instanceof WorkflowParseError)) throw err;
    findings.push({
      ruleId: "GHA000",
      severity: "low",
      file,
      line: err.line,
      message: `could not parse the file, so it was not checked: ${err.reason}`,
      help: "Fix the YAML error; GitHub rejects the workflow as well.",
    });
    return null;
  }
}

export interface RunResult {
  findings: Finding[];
  files: number;
  fixed: string[];
}

/** Scans paths, optionally fixing files in place, and returns the remaining findings. */
export async function scan(paths: string[], opts: { fix: boolean; cwd: string }): Promise<RunResult> {
  const result: RunResult = { findings: [], files: 0, fixed: [] };
  for (const p of paths) {
    for (const file of await findFiles(p)) {
      const rel = path.relative(opts.cwd, file).split(path.sep).join("/") || file;
      const source = await readFile(file, "utf8");
      const before = result.findings.length;
      let wf = load(rel, source, result.findings);
      if (wf || result.findings.length > before) result.files++;
      if (!wf) continue;
      if (opts.fix) {
        const r = fix(wf);
        if (r.source !== null) {
          await writeFile(file, r.source);
          result.fixed.push(...r.fixed);
          wf = parseWorkflow(rel, r.source);
          if (!wf) continue;
        }
      }
      result.findings.push(...analyze(wf));
    }
  }
  return result;
}
