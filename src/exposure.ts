import { anyEvent, forkRestrictedEvents, scenarios, trustedUpstream } from "./events.js";
import { stepVerdict } from "./gates.js";
import type { Verdict } from "./gates.js";
import type { Severity } from "./types.js";
import { severityRank } from "./types.js";
import type { Job, Workflow } from "./workflow.js";

/** What the rules know besides the workflow itself. */
export interface Context {
  /** Workflows in the same directory, to look up the upstream of workflow_run. */
  workflows: Workflow[];
}

/** A severity and the clause that explains it, appended to the finding's message. */
export interface Rating {
  severity: Severity;
  note: string;
}

export function worst(ratings: Rating[]): Rating | undefined {
  let out: Rating | undefined;
  for (const r of ratings) {
    if (!out || severityRank[r.severity] > severityRank[out.severity]) out = r;
  }
  return out;
}

/** Protected environments can require a reviewer to approve each run. */
export function withEnvironment(rating: Rating, job: Job): Rating {
  if (!job.environment || rating.severity !== "high") return rating;
  return {
    severity: "medium",
    note: `${rating.note}; the job uses an environment, which requires approval only if the environment has required reviewers`,
  };
}

/**
 * A workflow_run workflow whose upstream workflows only run on push and the
 * like is safer, but not safe: workflows are matched by name, and a pull
 * request can add a workflow with the same name.
 */
export function withUpstream(rating: Rating, wf: Workflow, ctx: Context, event: string): Rating {
  if (event !== "workflow_run" || rating.severity !== "high") return rating;
  const upstream = trustedUpstream(wf, ctx.workflows);
  if (!upstream) return rating;
  return {
    severity: "medium",
    note: `${rating.note}; the upstream workflow ${upstream.map((n) => `"${n}"`).join(", ")} only runs on push, schedule or similar, but a pull request can add a workflow with the same name, so also check github.event.workflow_run.event`,
  };
}

/** The scenarios (events) under which a step can run, with the gate for each. */
export function exposures(
  wf: Workflow,
  job: Job,
  stepIndex: number,
  events = scenarios(wf),
): { event: string; verdict: Exclude<Verdict, { kind: "never" }> }[] {
  const out: { event: string; verdict: Exclude<Verdict, { kind: "never" }> }[] = [];
  for (const event of events) {
    const verdict = stepVerdict(wf, job, stepIndex, event);
    if (verdict.kind !== "never") out.push({ event, verdict });
  }
  return out;
}

/**
 * Rates untrusted data reaching a script: high when an outsider can reach it
 * with a privileged token, lower when a gate or the fork restrictions of
 * pull_request events stand in the way. Undefined when the step never runs.
 */
export function rateScript(
  wf: Workflow,
  job: Job,
  stepIndex: number,
  events: string[],
  ctx: Context,
): Rating | undefined {
  const ratings: Rating[] = [];
  const restricted: string[] = [];
  for (const { event, verdict } of exposures(wf, job, stepIndex, events)) {
    let rating: Rating;
    if (forkRestrictedEvents.has(event)) {
      restricted.push(event);
      continue;
    } else if (verdict.kind === "open") {
      rating = { severity: "high", note: "" };
    } else if (verdict.strength === "actor") {
      rating = {
        severity: "low",
        note: `; it only runs when ${verdict.reason}, so an outsider cannot trigger it`,
      };
    } else {
      rating = { severity: "medium", note: `; it only runs when ${verdict.reason}` };
    }
    ratings.push(withUpstream(rating, wf, ctx, event));
  }
  if (restricted.length > 0) {
    ratings.push({
      severity: "low",
      note: `; only ${restricted.join("/")} events reach it, where pull requests from forks get a read-only token and no secrets`,
    });
  }
  const rating = worst(ratings);
  return rating && withEnvironment(rating, job);
}

/** Events of `events` that set a context; the rest leave it empty. */
export function settingEvents(events: string[], setters: string[] | undefined): string[] {
  return setters ? events.filter((e) => e === anyEvent || setters.includes(e)) : events;
}
