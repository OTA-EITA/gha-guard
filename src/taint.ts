import type { Job, Step, Workflow } from "./workflow.js";

/**
 * A small intra-workflow taint analysis for workflow_run: artifacts of the
 * triggering run can be written by a pull request, so outputs of steps that
 * read a downloaded artifact are untrusted, and so is whatever is derived from
 * them through steps.<id>.outputs and needs.<job>.outputs.
 */
export interface Tainted {
  /** The reference that carries the value, e.g. needs.meta.outputs.sha. */
  ref: string;
  /** Where the value comes from, e.g. "an artifact ... → steps.read.outputs → needs.meta.outputs.sha". */
  chain: string;
}

export interface Taint {
  /** The first tainted reference in `text`, as seen from inside `job`. */
  find(text: string, job: Job): Tainted | undefined;
}

const none: Taint = { find: () => undefined };

/** How a step downloads an artifact of another run, if it does. */
function downloads(step: Step): string | undefined {
  const uses = step.uses?.split("@")[0];
  // Without run-id, actions/download-artifact reads artifacts of the current run.
  if (uses === "actions/download-artifact" && step.with["run-id"] !== undefined) return uses;
  if (uses === "dawidd6/action-download-artifact") return uses;
  if (step.run !== undefined && /\bgh\s+run\s+download\b/.test(step.run)) return "gh run download";
  const script = uses === "actions/github-script" ? (step.with.script ?? "") : (step.run ?? "");
  const api = /listWorkflowRunArtifacts|downloadArtifact|actions\/(?:runs\/\S+\/)?artifacts/.exec(script);
  if (api) return `${uses ?? "a run: step"} via ${api[0]}`;
  return undefined;
}

/** Whether a step can turn what it reads into outputs. */
function producesOutputs(step: Step): boolean {
  if (step.uses?.startsWith("actions/github-script@")) return true;
  if (step.run !== undefined) return step.run.includes("GITHUB_OUTPUT");
  return step.uses !== undefined;
}

const stepRefRE = /steps\.([\w-]+)\.outputs(?:\.[\w-]+)?/gi;
const needsRefRE = /needs\.([\w-]+)\.outputs\.([\w-]+)/gi;

export function artifactTaint(wf: Workflow): Taint {
  if (!wf.triggers.includes("workflow_run")) return none;
  const steps = new Map<string, Map<string, string>>(); // job -> step id -> chain
  const outputs = new Map<string, string>(); // "job.name" -> chain

  const find = (text: string, job: Job): Tainted | undefined => {
    for (const m of text.matchAll(needsRefRE)) {
      const chain = outputs.get(`${(m[1] ?? "").toLowerCase()}.${(m[2] ?? "").toLowerCase()}`);
      if (chain && job.needs.some((n) => n.toLowerCase() === m[1]?.toLowerCase()))
        return { ref: m[0], chain };
    }
    const own = steps.get(job.id);
    for (const m of text.matchAll(stepRefRE)) {
      const chain = own?.get((m[1] ?? "").toLowerCase());
      if (chain) return { ref: m[0], chain };
    }
    return undefined;
  };

  // Sources: steps that read a downloaded artifact.
  for (const job of wf.jobs) {
    const own = new Map<string, string>();
    steps.set(job.id, own);
    let source: string | undefined;
    for (const step of job.steps) {
      source ??= downloads(step);
      if (source && step.id && producesOutputs(step)) {
        own.set(
          step.id.toLowerCase(),
          `an artifact of the triggering run (downloaded in job ${job.id} by ${source}) → steps.${step.id}.outputs`,
        );
      }
    }
  }

  // Propagate through env/with/run of steps and through job outputs until nothing changes.
  for (let changed = true, rounds = 0; changed && rounds < 10; rounds++) {
    changed = false;
    for (const job of wf.jobs) {
      const own = steps.get(job.id) ?? new Map<string, string>();
      for (const step of job.steps) {
        if (!step.id || own.has(step.id.toLowerCase()) || !producesOutputs(step)) continue;
        const inputs = [...Object.values(step.env), ...Object.values(step.with), step.run ?? ""].join("\n");
        const hit = find(inputs, job);
        if (hit) {
          own.set(step.id.toLowerCase(), `${hit.chain} → steps.${step.id}.outputs`);
          changed = true;
        }
      }
      for (const [name, value] of Object.entries(job.outputs)) {
        const key = `${job.id.toLowerCase()}.${name.toLowerCase()}`;
        if (outputs.has(key)) continue;
        const hit = find(value, job);
        if (hit) {
          outputs.set(key, `${hit.chain} → needs.${job.id}.outputs.${name}`);
          changed = true;
        }
      }
    }
  }
  return { find };
}
