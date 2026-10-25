import { anyEvent } from "./events.js";
import { conditionText, parseExpression } from "./expr.js";
import type { Expr } from "./expr.js";
import type { Job, Step, Workflow } from "./workflow.js";

/**
 * How strongly a condition keeps outsiders out:
 * - actor: only trusted people or same-repository pull requests get through
 *   (author_association, actor allowlists, head.repo.fork == false, ...);
 * - maintainer: a maintainer has to act on this event (add a label, merge);
 * - label: the pull request merely has to carry a label. That is a state, so
 *   once a maintainer adds it, later events (new pushes, other labels) pass too.
 */
export type Strength = "actor" | "maintainer" | "label";

const rank: Record<Strength, number> = { actor: 3, maintainer: 2, label: 1 };

/** Whether a job or step can run for an event, and what keeps outsiders out. */
export type Verdict =
  { kind: "never" } | { kind: "open" } | { kind: "gated"; strength: Strength; reason: string };

/** The abstract value of a condition, from an outsider's point of view. */
type Value =
  { k: "true" } | { k: "false" } | { k: "unknown" } | { k: "gate"; strength: Strength; reason: string };

const TRUE: Value = { k: "true" };
const FALSE: Value = { k: "false" };
const UNKNOWN: Value = { k: "unknown" };

function gate(strength: Strength, reason: string): Value {
  return { k: "gate", strength, reason };
}

function and(a: Value, b: Value): Value {
  if (a.k === "false" || b.k === "false") return FALSE;
  if (a.k === "gate" && b.k === "gate") return rank[b.strength] > rank[a.strength] ? b : a;
  if (a.k === "gate") return a;
  if (b.k === "gate") return b;
  return a.k === "true" && b.k === "true" ? TRUE : UNKNOWN;
}

function or(a: Value, b: Value): Value {
  if (a.k === "true" || b.k === "true") return TRUE;
  if (a.k === "unknown" || b.k === "unknown") return UNKNOWN;
  if (a.k === "false") return b;
  if (b.k === "false") return a;
  // Both are gates: an outsider takes the weaker one.
  return rank[b.strength] < rank[a.strength] ? b : a;
}

function not(a: Value): Value {
  if (a.k === "true") return FALSE;
  if (a.k === "false") return TRUE;
  return UNKNOWN;
}

/** Values of author_association that only people with access to the repository have. */
const trustedAssociations = new Set(["owner", "member", "collaborator"]);

/** Events of an upstream run that a pull request cannot produce. */
const trustedRunEvents = new Set([
  "push",
  "schedule",
  "workflow_dispatch",
  "release",
  "merge_group",
  "repository_dispatch",
  "pull_request_target",
]);

const associationRE = /^github\.event\.[\w.]*author_association$/;
const actorRE =
  /^github\.(actor|triggering_actor|event\.sender\.login|event\.[\w]+\.user\.login|event\.[\w]+\.author\.login)$/;
const headRepoRE =
  /^github\.event\.(pull_request\.head\.repo\.full_name|workflow_run\.head_repository\.full_name)$/;
const forkRE = /^github\.event\.(pull_request\.head\.repo\.fork|workflow_run\.head_repository\.fork)$/;
const labelsRE = /^github\.event\.(pull_request|issue)\.labels\.\*\.name$/;

interface Scope {
  event: string;
  /** Output references that come from a permission check, with a description. */
  checks: Map<string, string>;
}

function literal(e: Expr): string | number | boolean | null | undefined {
  return e.type === "literal" ? e.value : undefined;
}

function refPath(e: Expr): string | undefined {
  return e.type === "ref" ? e.path : undefined;
}

/** Literal list items in fromJSON('[...]') or a comma/space separated string. */
function listItems(e: Expr): string[] | undefined {
  const [arg] = e.type === "call" ? e.args : [];
  if (e.type === "call" && e.name === "fromjson" && e.args.length === 1 && arg) {
    const text = literal(arg);
    if (typeof text !== "string") return undefined;
    try {
      const parsed: unknown = JSON.parse(text);
      if (Array.isArray(parsed) && parsed.length > 0 && parsed.every((x) => typeof x === "string")) {
        return parsed;
      }
    } catch {
      return undefined;
    }
    return undefined;
  }
  const text = literal(e);
  return typeof text === "string" && text.trim() ? text.split(/[\s,]+/).filter(Boolean) : undefined;
}

function checkRef(path: string, scope: Scope): string | undefined {
  for (const [prefix, reason] of scope.checks) {
    if (path === prefix || path.startsWith(`${prefix}.`)) return reason;
  }
  return undefined;
}

/** Compares a context with a value: `path == value`. */
function equals(path: string, other: Expr, scope: Scope): Value {
  const value = literal(other);
  const otherPath = refPath(other);
  if (path === "github.event_name" && typeof value === "string") {
    if (scope.event === anyEvent) return UNKNOWN;
    return value.toLowerCase() === scope.event ? TRUE : FALSE;
  }
  if (associationRE.test(path) && typeof value === "string") {
    return trustedAssociations.has(value.toLowerCase())
      ? gate("actor", `author_association is ${value}`)
      : UNKNOWN;
  }
  if (actorRE.test(path) && (typeof value === "string" || otherPath === "github.repository_owner")) {
    const who = typeof value === "string" ? value : "the repository owner";
    return gate("actor", `${path} is ${who}`);
  }
  if (
    headRepoRE.test(path) &&
    (otherPath === "github.repository" || (typeof value === "string" && value.includes("/")))
  ) {
    return gate("actor", "the pull request comes from this repository, not a fork");
  }
  if (forkRE.test(path) && value === false) {
    return gate("actor", "the pull request comes from this repository, not a fork");
  }
  if (path === "github.event.workflow_run.event" && typeof value === "string") {
    return trustedRunEvents.has(value.toLowerCase())
      ? gate("actor", `the triggering run came from a ${value} event`)
      : UNKNOWN;
  }
  if (path === "github.event.label.name" && typeof value === "string") {
    return gate("maintainer", `a maintainer adds the '${value}' label`);
  }
  if (path === "github.event.pull_request.merged" && value === true) {
    return gate("maintainer", "a maintainer merges the pull request");
  }
  const check = checkRef(path, scope);
  if (check) return gate("actor", check);
  return UNKNOWN;
}

function compare(e: Extract<Expr, { type: "binary" }>, scope: Scope): Value {
  const sides: [Expr, Expr][] = [
    [e.left, e.right],
    [e.right, e.left],
  ];
  if (e.op === "==") {
    for (const [a, b] of sides) {
      const path = refPath(a);
      if (path) {
        const v = equals(path, b, scope);
        if (v.k !== "unknown") return v;
      }
    }
    return UNKNOWN;
  }
  if (e.op === "!=") {
    for (const [a, b] of sides) {
      const path = refPath(a);
      if (path === "github.event_name" && typeof literal(b) === "string") {
        if (scope.event === anyEvent) return UNKNOWN;
        return String(literal(b)).toLowerCase() === scope.event ? FALSE : TRUE;
      }
      if (path && forkRE.test(path) && literal(b) === true) {
        return gate("actor", "the pull request comes from this repository, not a fork");
      }
    }
  }
  return UNKNOWN;
}

function call(e: Extract<Expr, { type: "call" }>, scope: Scope): Value {
  if (e.name !== "contains" || e.args.length !== 2) return UNKNOWN;
  const [haystack, needle] = e.args as [Expr, Expr];
  const hay = refPath(haystack);
  const label = literal(needle);
  if (hay && labelsRE.test(hay) && typeof label === "string") {
    return gate("label", `the pull request has the '${label}' label`);
  }
  if (hay && labelsRE.test(hay)) return UNKNOWN;
  const path = refPath(needle);
  const items = listItems(haystack);
  if (!path || !items) return UNKNOWN;
  if (associationRE.test(path)) {
    return items.every((i) => trustedAssociations.has(i.toLowerCase()))
      ? gate("actor", `author_association is ${items.join(", ")}`)
      : UNKNOWN;
  }
  if (actorRE.test(path) && haystack.type === "call") {
    return gate("actor", `${path} is one of ${items.join(", ")}`);
  }
  if (path === "github.event_name") {
    if (scope.event === anyEvent) return UNKNOWN;
    return items.some((i) => i.toLowerCase() === scope.event) ? TRUE : FALSE;
  }
  return UNKNOWN;
}

function evaluate(e: Expr, scope: Scope): Value {
  switch (e.type) {
    case "literal":
      return e.value === false || e.value === null || e.value === "" || e.value === 0 ? FALSE : TRUE;
    case "ref": {
      const check = checkRef(e.path, scope);
      return check ? gate("actor", check) : UNKNOWN;
    }
    case "call":
      return call(e, scope);
    case "not":
      if (e.operand.type === "ref" && forkRE.test(e.operand.path)) {
        return gate("actor", "the pull request comes from this repository, not a fork");
      }
      return not(evaluate(e.operand, scope));
    case "binary":
      if (e.op === "&&") return and(evaluate(e.left, scope), evaluate(e.right, scope));
      if (e.op === "||") return or(evaluate(e.left, scope), evaluate(e.right, scope));
      return compare(e, scope);
    case "other":
      return UNKNOWN;
  }
}

function parseCondition(raw: unknown): Expr | boolean | null {
  if (raw === undefined) return true;
  const text = conditionText(raw);
  if (typeof text === "boolean") return text;
  return text === null ? null : parseExpression(text);
}

function evaluateCondition(raw: unknown, scope: Scope): Value {
  const cond = parseCondition(raw);
  if (cond === true) return TRUE;
  if (cond === false) return FALSE;
  return cond === null ? UNKNOWN : evaluate(cond, scope);
}

/** True when the condition calls always(), failure() or cancelled(), so skipped needs do not skip it. */
function usesStatusFunction(raw: unknown): boolean {
  const cond = parseCondition(raw);
  if (cond === null) return typeof raw === "string" && /\b(always|failure|cancelled)\s*\(/i.test(raw);
  if (typeof cond === "boolean") return false;
  const visit = (e: Expr): boolean => {
    switch (e.type) {
      case "call":
        return ["always", "failure", "cancelled"].includes(e.name) || e.args.some(visit);
      case "not":
        return visit(e.operand);
      case "binary":
        return visit(e.left) || visit(e.right);
      default:
        return false;
    }
  };
  return visit(cond);
}

// --- Permission checks ----------------------------------------------------

const checkActionRE =
  /^[^@]*(team-membership|check-user-permission|check-actor-permission|actor-permission|repo-permission|repository-permission|permission-check|check-permission|is-collaborator|collaborator-check|org-membership)[^@]*@/i;
/** Actions that fail the job when the actor lacks the permission. */
const failingCheckActionRE =
  /^(lannonbr\/repo-permission-check-action|prince-chrismc\/check-actor-permissions-action|sushichop\/action-repository-permission)@/i;
const checkScriptRE =
  /getCollaboratorPermissionLevel|collaborators\/[^\s'"]+\/permission|checkMembershipForUser|getMembershipForUserInOrg|\/teams\/[^\s'"]+\/memberships\/|orgs\/[^\s'"]+\/members\//;
const failRE = /setFailed|\bexit\s+1\b|\bthrow\b|process\.exit\(\s*1\s*\)/;

function stepLabel(step: Step): string {
  return step.uses?.split("@")[0] ?? step.name ?? step.id ?? "a step";
}

/** Whether a step checks the actor's permission or membership, and whether it fails the job when it does not pass. */
export function permissionCheck(step: Step): { fails: boolean; label: string } | undefined {
  const script = step.run ?? (step.uses?.startsWith("actions/github-script@") ? step.with.script : undefined);
  if (step.uses && checkActionRE.test(step.uses)) {
    const fails = failingCheckActionRE.test(step.uses) || step.with.exit === "true";
    return { fails, label: stepLabel(step) };
  }
  if (script !== undefined && checkScriptRE.test(script)) {
    return { fails: failRE.test(script), label: stepLabel(step) };
  }
  return undefined;
}

/** Output references (steps.<id>.outputs, needs.<job>.outputs.<name>) that come from a permission check. */
function checkOutputs(wf: Workflow, job: Job): Map<string, string> {
  const out = new Map<string, string>();
  for (const step of job.steps) {
    const check = step.id ? permissionCheck(step) : undefined;
    if (step.id && check) out.set(`steps.${step.id.toLowerCase()}.outputs`, `${check.label} passes`);
  }
  for (const id of job.needs) {
    const needed = wf.jobs.find((j) => j.id === id);
    if (!needed) continue;
    const inner = checkOutputs(wf, { ...needed, needs: [] });
    for (const [name, value] of Object.entries(needed.outputs)) {
      const m = /steps\.([\w-]+)\.outputs/i.exec(value);
      const reason = m?.[1] ? inner.get(`steps.${m[1].toLowerCase()}.outputs`) : undefined;
      if (reason) out.set(`needs.${id.toLowerCase()}.outputs.${name.toLowerCase()}`, reason);
    }
  }
  return out;
}

// --- Verdicts ---------------------------------------------------------------

function toVerdict(v: Value): Verdict {
  if (v.k === "false") return { kind: "never" };
  if (v.k === "gate") return { kind: "gated", strength: v.strength, reason: v.reason };
  return { kind: "open" };
}

function jobValue(wf: Workflow, job: Job, event: string, seen: Set<string>): Value {
  if (seen.has(job.id)) return UNKNOWN;
  seen.add(job.id);
  let value = evaluateCondition(job.if, { event, checks: checkOutputs(wf, job) });
  if (!usesStatusFunction(job.if)) {
    // A job is skipped when a job it needs is skipped or fails.
    for (const id of job.needs) {
      const needed = wf.jobs.find((j) => j.id === id);
      if (!needed) continue;
      let v = jobValue(wf, needed, event, seen);
      const fails = needed.steps.map(permissionCheck).find((c) => c?.fails);
      if (fails) v = and(v, gate("actor", `job ${needed.id} runs ${fails.label} first`));
      value = and(value, v);
    }
  }
  seen.delete(job.id);
  return value;
}

/** Whether a job can run for `event` (e.g. "pull_request_target", or "*" for any), and what gates it. */
export function jobVerdict(wf: Workflow, job: Job, event: string): Verdict {
  return toVerdict(jobValue(wf, job, event, new Set()));
}

/** Whether the step at `index` of a job can run for `event`, and what gates it. */
export function stepVerdict(wf: Workflow, job: Job, index: number, event: string): Verdict {
  let value = jobValue(wf, job, event, new Set());
  const step = job.steps[index];
  if (step) value = and(value, evaluateCondition(step.if, { event, checks: checkOutputs(wf, job) }));
  // A failing permission check earlier in the job stops it before this step.
  for (const earlier of job.steps.slice(0, index)) {
    const check = permissionCheck(earlier);
    if (check?.fails) value = and(value, gate("actor", `${check.label} checks the actor's permission first`));
  }
  return toVerdict(value);
}
