import { isMap, isScalar, YAMLMap } from "yaml";
import { envName, findInjections } from "./rules/injection.js";
import type { Step, Workflow } from "./workflow.js";

export interface FixResult {
  /** The rewritten file, or null when nothing changed. */
  source: string | null;
  fixed: string[];
}

function shellOf(step: Step, wf: Workflow): string {
  if (step.shell) return step.shell;
  const defaults = wf.doc.getIn(["defaults", "run", "shell"]);
  return typeof defaults === "string" ? defaults : "bash";
}

/** How a shell reads an environment variable. */
function reference(shell: string, name: string): string {
  if (/^(pwsh|powershell)/.test(shell)) return `$env:${name}`;
  if (shell === "cmd") return `%${name}%`;
  return `\${${name}}`;
}

function fixInjections(wf: Workflow): string[] {
  const fixed: string[] = [];
  for (const job of wf.jobs) {
    for (const step of job.steps) {
      if (step.run === undefined) continue;
      const injections = findInjections(step.run);
      if (injections.length === 0) continue;
      const runNode = step.node.get("run", true);
      if (!isScalar(runNode)) continue;

      const existing: unknown = step.node.get("env", true);
      let env: YAMLMap;
      if (isMap(existing)) {
        env = existing;
      } else {
        env = new YAMLMap();
        step.node.set("env", env);
      }
      const shell = shellOf(step, wf);
      let script = step.run;
      for (const inj of injections) {
        let name = envName(inj.context);
        // Reuse a variable that already holds this expression; avoid clobbering others.
        for (let n = 2; env.has(name) && String(env.get(name)) !== inj.text; n++) {
          name = `${envName(inj.context)}_${String(n)}`;
        }
        env.set(name, inj.text);
        const ref = reference(shell, name);
        script = script.split(inj.text).join(ref);
        // Quote bare references so word splitting and globbing cannot change the value.
        if (ref.startsWith("${")) {
          script = script.replace(new RegExp(`(^|[^"\\w])${escape(ref)}(?=$|[^"\\w])`, "g"), `$1"${ref}"`);
        }
        fixed.push(`GHA001 ${wf.file}:${String(step.line)} ${inj.context} -> $${name}`);
      }
      runNode.value = script;
    }
  }
  return fixed;
}

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function fixPermissions(wf: Workflow): string[] {
  const root = wf.doc.contents;
  if (wf.kind !== "workflow" || wf.hasPermissions || !isMap(root)) return [];
  if (wf.jobs.every((j) => j.hasPermissions || j.uses !== undefined)) return [];
  const pair = wf.doc.createPair("permissions", { contents: "read" });
  const onIndex = root.items.findIndex(
    (p) => isScalar(p.key) && (p.key.value === "on" || p.key.value === true),
  );
  root.items.splice(onIndex >= 0 ? onIndex + 1 : root.items.length, 0, pair);
  return [`GHA003 ${wf.file}: added permissions: { contents: read }; grant more per job if a job needs it`];
}

/** Applies every automatic fix to a parsed workflow. */
export function fix(wf: Workflow): FixResult {
  const fixed = [...fixInjections(wf), ...fixPermissions(wf)];
  if (fixed.length === 0) return { source: null, fixed };
  return { source: wf.doc.toString({ lineWidth: 0, flowCollectionPadding: false }), fixed };
}
