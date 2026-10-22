import type { Finding } from "../types.js";
import type { Workflow } from "../workflow.js";

/** Triggers that run with the base repository's secrets and write token. */
const privileged = ["pull_request_target", "workflow_run"];

/** Refs that point at code from the pull request author. */
const untrustedRef =
  /github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|github\.event\.workflow_run\.head_(sha|branch)|refs\/pull\//;

export function checkPwnRequest(wf: Workflow): Finding[] {
  const triggers = wf.triggers.filter((t) => privileged.includes(t));
  if (triggers.length === 0) return [];
  const findings: Finding[] = [];
  for (const job of wf.jobs) {
    for (const step of job.steps) {
      if (!step.uses?.startsWith("actions/checkout@")) continue;
      const ref = step.with.ref ?? "";
      const repo = step.with.repository ?? "";
      if (untrustedRef.test(ref) || repo.includes("github.event.pull_request.head.repo")) {
        findings.push({
          ruleId: "GHA002",
          severity: "high",
          file: wf.file,
          line: step.line,
          message: `checks out pull request code in a ${triggers.join("/")} workflow, which has secrets and a write token ("pwn request")`,
          help: "Use the pull_request trigger to build untrusted code, or split into an unprivileged build workflow and a privileged workflow that only consumes artifacts.",
        });
      }
    }
  }
  return findings;
}
