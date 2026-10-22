import type { Finding } from "../types.js";
import type { Workflow } from "../workflow.js";

const sha = /^[0-9a-f]{40}$/;

/** Actions published by GitHub; a moved tag there is less likely but still possible. */
function firstParty(owner: string): boolean {
  return owner === "actions" || owner === "github";
}

export function checkPinning(wf: Workflow): Finding[] {
  const findings: Finding[] = [];
  const refs: { uses: string; line: number }[] = [];
  for (const job of wf.jobs) {
    if (job.uses && !job.uses.startsWith("./")) refs.push({ uses: job.uses, line: job.line });
    for (const step of job.steps) {
      if (step.uses) refs.push({ uses: step.uses, line: step.line });
    }
  }
  for (const { uses, line } of refs) {
    if (uses.startsWith("./")) continue;
    if (uses.startsWith("docker://")) {
      if (!uses.includes("@sha256:")) {
        findings.push({
          ruleId: "GHA005",
          severity: "low",
          file: wf.file,
          line,
          message: `${uses} is not pinned to an image digest`,
          help: "Pin the image with @sha256:<digest>.",
        });
      }
      continue;
    }
    const at = uses.lastIndexOf("@");
    const ref = at >= 0 ? uses.slice(at + 1) : "";
    if (sha.test(ref)) continue;
    const owner = uses.split("/")[0] ?? "";
    findings.push({
      ruleId: "GHA005",
      severity: firstParty(owner) ? "low" : "medium",
      file: wf.file,
      line,
      message: `${uses} is pinned to a mutable ref; whoever controls the tag controls what runs`,
      help: "Pin to a full commit SHA with the version in a comment, e.g. with `depbot update --ecosystem github-actions --pin-only`.",
    });
  }
  return findings;
}
