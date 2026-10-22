import { isMap, isScalar, isSeq, LineCounter, parseDocument } from "yaml";
import type { Document, Node, YAMLMap } from "yaml";

/** A step of a job or of a composite action. */
export interface Step {
  node: YAMLMap;
  line: number;
  uses?: string;
  run?: string;
  shell?: string;
  with: Record<string, string>;
  env: Record<string, string>;
}

export interface Job {
  id: string;
  node: YAMLMap;
  line: number;
  hasPermissions: boolean;
  permissions: unknown;
  runsOn: string[];
  uses?: string;
  secretsInherit: boolean;
  steps: Step[];
}

/** A parsed workflow file or composite action (action.yml). */
export interface Workflow {
  file: string;
  kind: "workflow" | "action";
  doc: Document;
  lines: LineCounter;
  triggers: string[];
  hasPermissions: boolean;
  permissions: unknown;
  env: Record<string, string>;
  jobs: Job[];
}

export function lineOf(lines: LineCounter, node: Node | null | undefined): number {
  const offset = node?.range?.[0];
  return offset === undefined ? 1 : lines.linePos(offset).line;
}

function asStringMap(value: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") out[k] = String(v);
    }
  }
  return out;
}

function stringList(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string");
  if (value && typeof value === "object") {
    const labels = (value as { labels?: unknown }).labels;
    if (labels !== undefined) return stringList(labels);
  }
  return [];
}

function parseSteps(lines: LineCounter, seq: unknown): Step[] {
  if (!isSeq(seq)) return [];
  const steps: Step[] = [];
  for (const item of seq.items) {
    if (!isMap(item)) continue;
    const plain = item.toJSON() as Record<string, unknown>;
    const step: Step = {
      node: item,
      line: lineOf(lines, item),
      with: asStringMap(plain.with),
      env: asStringMap(plain.env),
    };
    if (typeof plain.uses === "string") step.uses = plain.uses;
    if (typeof plain.run === "string") step.run = plain.run;
    if (typeof plain.shell === "string") step.shell = plain.shell;
    steps.push(step);
  }
  return steps;
}

function triggersOf(on: unknown): string[] {
  if (typeof on === "string") return [on];
  if (Array.isArray(on)) return on.filter((t): t is string => typeof t === "string");
  if (on && typeof on === "object") return Object.keys(on);
  return [];
}

/** Parses a workflow or composite action. Returns null for other YAML files. */
export function parseWorkflow(file: string, source: string): Workflow | null {
  const lines = new LineCounter();
  const doc = parseDocument(source, { lineCounter: lines, keepSourceTokens: true });
  if (doc.errors.length > 0) {
    throw new Error(`${file}: ${doc.errors[0]?.message ?? "invalid YAML"}`);
  }
  const root = doc.contents;
  if (!isMap(root)) return null;
  const plain = root.toJSON() as Record<string, unknown>;

  // Composite actions keep their steps under runs.steps.
  const runs = root.get("runs", true);
  if (isMap(runs) && runs.get("using") === "composite") {
    return {
      file,
      kind: "action",
      doc,
      lines,
      triggers: [],
      hasPermissions: true, // actions inherit the caller's permissions
      permissions: undefined,
      env: {},
      jobs: [
        {
          id: "(composite)",
          node: runs,
          line: lineOf(lines, runs),
          hasPermissions: true,
          permissions: undefined,
          runsOn: [],
          secretsInherit: false,
          steps: parseSteps(lines, runs.get("steps", true)),
        },
      ],
    };
  }

  const jobsNode = root.get("jobs", true);
  if (!isMap(jobsNode)) return null;
  const jobs: Job[] = [];
  for (const pair of jobsNode.items) {
    if (!isScalar(pair.key) || !isMap(pair.value)) continue;
    const node = pair.value;
    const job = node.toJSON() as Record<string, unknown>;
    const parsed: Job = {
      id: String(pair.key.value),
      node,
      line: lineOf(lines, pair.key),
      hasPermissions: node.has("permissions"),
      permissions: job.permissions,
      runsOn: stringList(job["runs-on"]),
      secretsInherit: job.secrets === "inherit",
      steps: parseSteps(lines, node.get("steps", true)),
    };
    if (typeof job.uses === "string") parsed.uses = job.uses;
    jobs.push(parsed);
  }
  return {
    file,
    kind: "workflow",
    doc,
    lines,
    // "on" can be parsed as the boolean true by YAML 1.1 tools; yaml 2 keeps it as a string.
    triggers: triggersOf(plain.on ?? plain.true),
    hasPermissions: root.has("permissions"),
    permissions: plain.permissions,
    env: asStringMap(plain.env),
    jobs,
  };
}
