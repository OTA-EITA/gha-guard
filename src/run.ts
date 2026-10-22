import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { findFiles } from "./files.js";
import { fix } from "./fix.js";
import { analyze } from "./rules/index.js";
import type { Finding } from "./types.js";
import { parseWorkflow } from "./workflow.js";

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
      let wf = parseWorkflow(rel, source);
      if (!wf) continue;
      result.files++;
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
