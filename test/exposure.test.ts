import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { analyze } from "../src/rules/index.js";
import type { Finding } from "../src/types.js";
import { parseWorkflow } from "../src/workflow.js";
import type { Workflow } from "../src/workflow.js";

const dir = new URL("./fixtures/exposure/.github/workflows/", import.meta.url);

/** Every exposure fixture, parsed, so rules can look up sibling workflows. */
const workflows: Workflow[] = readdirSync(dir)
  .filter((name) => name.endsWith(".yml"))
  .map((name) => {
    const wf = parseWorkflow(name, readFileSync(new URL(name, dir), "utf8"));
    if (!wf) throw new Error(`${name} is not a workflow`);
    return wf;
  });

function findings(name: string, rule: string): Finding[] {
  const wf = workflows.find((w) => w.file === name);
  if (!wf) throw new Error(`no fixture ${name}`);
  return analyze(wf, { workflows }).filter((f) => f.ruleId === rule);
}

/** rule findings as "line:severity". */
function summary(name: string, rule: string): string[] {
  return findings(name, rule).map((f) => `${String(f.line)}:${f.severity}`);
}

describe("GHA001 exposure", () => {
  it("rates injection in pull_request-only workflows low: forks get a read-only token and no secrets", () => {
    expect(summary("inj-pull-request.yml", "GHA001")).toEqual(["9:low"]);
    expect(findings("inj-pull-request.yml", "GHA001")[0]?.message).toContain("read-only token");
  });

  it("rates each context by the triggers that set it", () => {
    expect(summary("inj-mixed.yml", "GHA001")).toEqual(["10:high", "11:low"]);
    expect(summary("inj-not-set.yml", "GHA001")).toEqual(["7:low"]);
    expect(findings("inj-not-set.yml", "GHA001")[0]?.message).toContain("only set for issues, issue_comment");
  });

  it("downgrades jobs gated on trusted actors and explains the gate", () => {
    expect(summary("inj-gated.yml", "GHA001")).toEqual(["8:low"]);
    expect(findings("inj-gated.yml", "GHA001")[0]?.message).toContain(
      "only runs when author_association is MEMBER",
    );
  });

  it("skips disabled jobs and steps", () => {
    expect(summary("inj-disabled.yml", "GHA001")).toEqual([]);
  });

  it("rates jobs with an environment medium", () => {
    expect(summary("inj-environment.yml", "GHA001")).toEqual(["8:medium"]);
    expect(findings("inj-environment.yml", "GHA001")[0]?.message).toContain(
      "requires approval only if the environment has required reviewers",
    );
  });

  it("rates a label added by a maintainer medium", () => {
    expect(summary("inj-label.yml", "GHA001")).toEqual(["10:medium"]);
  });
});
