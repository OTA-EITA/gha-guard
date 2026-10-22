import type { Finding } from "../types.js";
import type { Workflow } from "../workflow.js";

const prTriggers = ["pull_request", "pull_request_target"];

/** Smaller issues: leftover credentials, insecure commands, runners and secrets. */
export function checkHygiene(wf: Workflow): Finding[] {
  const findings: Finding[] = [];
  const push = (f: Omit<Finding, "file">) => findings.push({ ...f, file: wf.file });

  const insecure = (env: Record<string, string>) =>
    env.ACTIONS_ALLOW_UNSECURE_COMMANDS?.toLowerCase() === "true";
  if (insecure(wf.env)) {
    push({
      ruleId: "GHA007",
      severity: "high",
      line: 1,
      message:
        "ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables set-env/add-path, which allow environment injection",
      help: "Remove it and write to $GITHUB_ENV / $GITHUB_PATH instead.",
    });
  }

  for (const job of wf.jobs) {
    const selfHosted = job.runsOn.some((l) => l === "self-hosted");
    if (selfHosted && wf.triggers.some((t) => prTriggers.includes(t))) {
      push({
        ruleId: "GHA008",
        severity: "medium",
        line: job.line,
        message: `job ${job.id} runs pull request workflows on a self-hosted runner, which can persist an attacker's changes`,
        help: "Use GitHub-hosted or ephemeral (just-in-time) runners for pull requests.",
      });
    }
    if (job.secretsInherit) {
      push({
        ruleId: "GHA009",
        severity: "low",
        line: job.line,
        message: `job ${job.id} passes every secret to ${job.uses ?? "the reusable workflow"} with secrets: inherit`,
        help: "Pass only the secrets the reusable workflow needs.",
      });
    }
    for (const step of job.steps) {
      if (insecure(step.env)) {
        push({
          ruleId: "GHA007",
          severity: "high",
          line: step.line,
          message:
            "ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables set-env/add-path, which allow environment injection",
          help: "Remove it and write to $GITHUB_ENV / $GITHUB_PATH instead.",
        });
      }
      if (step.uses?.startsWith("actions/checkout@") && step.with["persist-credentials"] !== "false") {
        push({
          ruleId: "GHA006",
          severity: "low",
          line: step.line,
          message:
            "actions/checkout keeps the token in .git/config, where later steps (and uploaded artifacts) can read it",
          help: "Set persist-credentials: false unless a later step pushes with git.",
        });
      }
    }
  }
  return findings;
}
