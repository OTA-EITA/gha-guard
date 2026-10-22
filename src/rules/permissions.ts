import type { Finding } from "../types.js";
import type { Workflow } from "../workflow.js";

export function checkPermissions(wf: Workflow): Finding[] {
  if (wf.kind !== "workflow") return [];
  const findings: Finding[] = [];
  if (wf.permissions === "write-all") {
    findings.push({
      ruleId: "GHA004",
      severity: "high",
      file: wf.file,
      line: 1,
      message: "permissions: write-all gives every job write access to the repository, packages and more",
      help: "List only the scopes each job needs, e.g. permissions: { contents: read }.",
    });
  }
  for (const job of wf.jobs) {
    if (job.permissions === "write-all") {
      findings.push({
        ruleId: "GHA004",
        severity: "high",
        file: wf.file,
        line: job.line,
        message: `job ${job.id} uses permissions: write-all`,
        help: "List only the scopes this job needs.",
      });
    }
  }
  // Without a permissions block the token gets the repository default, which
  // is read/write for older repositories and organizations.
  const unscoped = wf.jobs.filter((j) => !j.hasPermissions && j.uses === undefined);
  if (!wf.hasPermissions && unscoped.length > 0) {
    findings.push({
      ruleId: "GHA003",
      severity: "medium",
      file: wf.file,
      line: 1,
      message: `no permissions block; job(s) ${unscoped.map((j) => j.id).join(", ")} get the repository's default token permissions`,
      help: "Add a top-level permissions: { contents: read } and grant more per job where needed.",
      fixable: true,
    });
  }
  return findings;
}
