import type { Workflow } from "./workflow.js";

/**
 * Events an outsider can trigger that run with the base repository's secrets
 * and a token that can write (opening issues, commenting, forking, starring,
 * editing a public wiki, or finishing a run that a fork pull request started).
 */
export const privilegedEvents = new Set([
  "pull_request_target",
  "issues",
  "issue_comment",
  "discussion",
  "discussion_comment",
  "workflow_run",
  "gollum",
  "fork",
  "watch",
]);

/**
 * Events that GitHub restricts for pull requests from forks: the GITHUB_TOKEN
 * is read-only and secrets are not passed.
 */
export const forkRestrictedEvents = new Set([
  "pull_request",
  "pull_request_review",
  "pull_request_review_comment",
]);

/** Stands for "any event": a composite action or a reusable workflow inherits its caller's event. */
export const anyEvent = "*";

/** The events to consider for a workflow; reusable workflows and composite actions may run for any event. */
export function scenarios(wf: Workflow): string[] {
  if (wf.kind === "action") return [anyEvent];
  return wf.triggers.map((t) => (t === "workflow_call" ? anyEvent : t));
}

const prEvents = [
  "pull_request",
  "pull_request_target",
  "pull_request_review",
  "pull_request_review_comment",
];

/** Which events set a context; undefined when it is not specific to an event. */
const setBy: [RegExp, string[]][] = [
  [/^github\.(event\.pull_request\.|head_ref$)/, prEvents],
  [/^github\.event\.issue\./, ["issues", "issue_comment"]],
  [
    /^github\.event\.comment\./,
    ["issue_comment", "pull_request_review_comment", "commit_comment", "discussion_comment"],
  ],
  [/^github\.event\.review\./, ["pull_request_review"]],
  [/^github\.event\.discussion\./, ["discussion", "discussion_comment"]],
  [/^github\.event\.pages[.[]/, ["gollum"]],
  [/^github\.event\.(commits|head_commit)[.[]/, ["push"]],
  [/^github\.event\.workflow_run\./, ["workflow_run"]],
];

export function eventsSetting(context: string): string[] | undefined {
  return setBy.find(([re]) => re.test(context))?.[1];
}

/** Triggers of an upstream workflow under which its artifacts and head commit are trusted. */
const trustedUpstreamTriggers = new Set(["push", "schedule", "workflow_dispatch", "release", "merge_group"]);

/**
 * For a workflow_run workflow, the names of the upstream workflows when every
 * one of them is found among `workflows` and runs only on trusted events
 * (push, schedule, ...). Returns undefined otherwise.
 */
export function trustedUpstream(wf: Workflow, workflows: Workflow[]): string[] | undefined {
  const config = wf.on.workflow_run;
  const names =
    config && typeof config === "object" ? (config as { workflows?: unknown }).workflows : undefined;
  const list = typeof names === "string" ? [names] : Array.isArray(names) ? names : [];
  if (list.length === 0 || !list.every((n) => typeof n === "string")) return undefined;
  for (const name of list) {
    // A workflow without a `name:` is matched by its path.
    const wanted = name.toLowerCase();
    const upstream = workflows.filter(
      (w) =>
        w !== wf &&
        w.kind === "workflow" &&
        (w.name === undefined ? w.file.toLowerCase().endsWith(wanted) : w.name.toLowerCase() === wanted),
    );
    if (upstream.length === 0) return undefined;
    if (
      !upstream.every((u) => u.triggers.length > 0 && u.triggers.every((t) => trustedUpstreamTriggers.has(t)))
    ) {
      return undefined;
    }
  }
  return list;
}
