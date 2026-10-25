import { stepRunsCode, scriptRunsCode } from "../exec.js";
import { exposures, withEnvironment, withUpstream, worst } from "../exposure.js";
import type { Context, Rating } from "../exposure.js";
import { artifactTaint } from "../taint.js";
import type { Taint } from "../taint.js";
import type { Finding } from "../types.js";
import type { Job, Step, Workflow } from "../workflow.js";

/** Triggers that run with the base repository's secrets and write token, and know about a pull request. */
const privileged = ["pull_request_target", "workflow_run", "issue_comment"];

// github.event.pull_request and github.head_ref are only set for pull request events.
const prEvents = ["pull_request_target"];

/** Refs that point at code from the pull request author. */
const untrustedRef =
  /github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|github\.event\.workflow_run\.head_(sha|branch)|refs\/pull\//;
/** Refs that name a branch rather than a commit, so they move when the author pushes. */
const branchRef =
  /github\.event\.pull_request\.head\.ref|github\.head_ref|workflow_run\.head_branch|refs\/pull\//;

/** Actions that resolve the pull request behind an issue_comment. */
const commentBranch = /^(xt0rted|alessbell)\/pull-request-comment-branch@/;

const ghCheckout = /\b(?:gh|hub)\s+pr\s+checkout\b/;
const fetchPull = /\bgit\s+fetch\b[^\n]*\bpull\/(?:\$\{\{[^}]*\}\}|[^\s/]+)\/(?:head|merge)\b/;
const switchTree = /\bgit\s+(?:checkout|switch|reset\s+--hard|merge|rebase|worktree\s+add)(?=\s|$)/;

interface Checkout {
  /** What is checked out, when it is not plainly pull request code, and why it is untrusted. */
  what?: string;
  why?: string;
  /** The events that set the ref; undefined when it is pull request code under any of them. */
  events?: string[];
  /** Where in a run: script the checkout happens, to look for commands after it. */
  scriptRest?: string;
  /** True when the checked-out ref is a branch, which can move after a maintainer looked at it. */
  branch: boolean;
}

/** Whether a step puts pull request code into the working tree. */
function untrustedCheckout(job: Job, step: Step, taint: Taint): Checkout | undefined {
  if (step.uses?.startsWith("actions/checkout@")) {
    const ref = step.with.ref ?? "";
    const repo = step.with.repository ?? "";
    const tainted = taint.find(`${repo} ${ref}`, job);
    if (tainted) {
      return {
        branch: false,
        events: ["workflow_run"],
        what: `the ref given by ${tainted.ref}`,
        why: `; ${tainted.ref} comes from ${tainted.chain}, so whoever started that run (for example a fork pull request) chooses what is checked out`,
      };
    }
    if (untrustedRef.test(ref) || repo.includes("github.event.pull_request.head.repo")) {
      const checkout: Checkout = { branch: branchRef.test(ref) };
      // github.event.pull_request is empty under workflow_run and the other way round.
      if (!ref.includes("refs/pull/")) {
        checkout.events = [`${ref} ${repo}`.includes("workflow_run.head") ? "workflow_run" : ""]
          .concat(/pull_request\.head|head_ref/.test(`${ref} ${repo}`) ? prEvents : [])
          .filter(Boolean);
      }
      return checkout;
    }
    // steps.<id>.outputs.head_sha of an action that looks up the commented pull request.
    const m = /steps\.([\w-]+)\.outputs\.(head_\w+)/.exec(`${ref} ${repo}`);
    const source = m && job.steps.find((s) => s.id === m[1]);
    if (source?.uses && commentBranch.test(source.uses)) {
      return { branch: !ref.includes("head_sha") };
    }
    return undefined;
  }
  const run = step.run;
  if (run === undefined) return undefined;
  const gh = ghCheckout.exec(run);
  if (gh) return { branch: true, scriptRest: run.slice(gh.index + gh[0].length) };
  const fetch = fetchPull.exec(run);
  const sw = fetch ? switchTree.exec(run.slice(fetch.index)) : null;
  if (fetch && sw) return { branch: true, scriptRest: run.slice(fetch.index + sw.index + sw[0].length) };
  return undefined;
}

/** pull_request_target types under which a label check can be passed again later. */
function labelRecheckable(wf: Workflow): boolean {
  const config = wf.on.pull_request_target;
  const types = config && typeof config === "object" ? (config as { types?: unknown }).types : undefined;
  const list = typeof types === "string" ? [types] : Array.isArray(types) ? types : undefined;
  // The default types are opened, synchronize and reopened.
  if (!list) return true;
  return list.some((t) => ["labeled", "unlabeled", "synchronize", "edited"].includes(String(t)));
}

function rate(
  wf: Workflow,
  job: Job,
  index: number,
  checkout: Checkout,
  exec: string | undefined,
  ctx: Context,
): Rating | undefined {
  const events = wf.triggers.filter((t) => privileged.includes(t) && (checkout.events ?? [t]).includes(t));
  const ratings: Rating[] = [];
  for (const { event, verdict } of exposures(wf, job, index, events)) {
    const where = `in ${/^[aeiou]/.test(event) ? "an" : "a"} ${event} workflow`;
    const what = checkout.what ?? "pull request code";
    let rating: Rating;
    if (!exec) {
      rating = {
        severity: "low",
        note: `checks out ${what} ${where} but doesn't appear to execute it; a later build or test step would make it a pwn request`,
      };
    } else if (verdict.kind === "open") {
      rating = {
        severity: "high",
        note: `checks out ${what} ${where} and runs it (${exec}) with the workflow's secrets and write token ("pwn request")`,
      };
    } else if (verdict.strength === "label") {
      const later = event === "issue_comment" || (event === "pull_request_target" && labelRecheckable(wf));
      rating = later
        ? {
            severity: "high",
            note: `checks out ${what} ${where} and runs it (${exec}) when ${verdict.reason}; the label stays on the pull request, so any later label event runs newer commits once the label is present`,
          }
        : {
            severity: "medium",
            note: `checks out ${what} ${where} and runs it (${exec}) when ${verdict.reason}`,
          };
    } else if (verdict.strength === "maintainer") {
      rating = checkout.branch
        ? {
            severity: "high",
            note: `checks out ${what} ${where} and runs it (${exec}) when ${verdict.reason}, but it checks out the branch rather than the commit that was reviewed, so commits pushed after that also run`,
          }
        : {
            severity: "medium",
            note: `checks out ${what} ${where} and runs it (${exec}) when ${verdict.reason}; review the exact commit before that`,
          };
    } else {
      rating = {
        severity: "low",
        note: `checks out ${what} ${where} and runs it (${exec}), but only when ${verdict.reason}`,
      };
    }
    ratings.push(withUpstream(rating, wf, ctx, event));
  }
  const rating = worst(ratings);
  return rating && withEnvironment(rating, job);
}

/** The first step after `index` (or the rest of the checkout's own script) that runs the checked-out code. */
function laterExec(job: Job, index: number, checkout: Checkout): string | undefined {
  if (checkout.scriptRest !== undefined) {
    const inline = scriptRunsCode(checkout.scriptRest);
    if (inline) return inline;
  }
  for (const step of job.steps.slice(index + 1)) {
    const exec = stepRunsCode(step);
    if (exec) return exec;
  }
  return undefined;
}

export function checkPwnRequest(wf: Workflow, ctx: Context): Finding[] {
  if (!wf.triggers.some((t) => privileged.includes(t))) return [];
  const findings: Finding[] = [];
  const taint = artifactTaint(wf);
  for (const job of wf.jobs) {
    job.steps.forEach((step, index) => {
      const checkout = untrustedCheckout(job, step, taint);
      if (!checkout) return;
      const rating = rate(wf, job, index, checkout, laterExec(job, index, checkout), ctx);
      if (!rating) return;
      findings.push({
        ruleId: "GHA002",
        severity: rating.severity,
        file: wf.file,
        line: step.line,
        message: rating.note.replace(/^; /, "") + (checkout.why ?? ""),
        help: "Use the pull_request trigger to build untrusted code, or split into an unprivileged build workflow and a privileged workflow that only consumes artifacts.",
      });
    });
  }
  return findings;
}
