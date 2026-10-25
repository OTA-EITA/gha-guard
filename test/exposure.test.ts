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

describe("GHA002 exposure", () => {
  const message = (name: string, line: number) =>
    findings(name, "GHA002").find((f) => f.line === line)?.message ?? "";

  it("is high only when a later step runs the checked-out code", () => {
    expect(summary("pwn-exec.yml", "GHA002")).toEqual(["7:high", "14:high", "21:low"]);
    expect(message("pwn-exec.yml", 7)).toContain("npm ci");
    expect(message("pwn-exec.yml", 14)).toContain("./.github/actions/setup");
    expect(message("pwn-exec.yml", 21)).toContain("doesn't appear to execute it");
  });

  it("downgrades same-repository gates and environments", () => {
    expect(summary("pwn-gated.yml", "GHA002")).toEqual(["16:medium", "8:low"]);
    expect(message("pwn-gated.yml", 8)).toContain("the pull request comes from this repository, not a fork");
    expect(message("pwn-gated.yml", 16)).toContain(
      "requires approval only if the environment has required reviewers",
    );
  });

  it("trusts a maintainer's label only for the labelled commit", () => {
    expect(summary("pwn-label-event.yml", "GHA002")).toEqual(["18:high", "10:medium"]);
    expect(message("pwn-label-event.yml", 10)).toContain("a maintainer adds the 'safe to test' label");
    expect(message("pwn-label-event.yml", 18)).toContain("commits pushed after");
  });

  it("flags label checks that later events can pass (TOCTOU)", () => {
    expect(summary("pwn-label-state.yml", "GHA002")).toEqual(["16:high"]);
    expect(message("pwn-label-state.yml", 16)).toContain(
      "any later label event runs newer commits once the label is present",
    );
    expect(summary("pwn-label-opened.yml", "GHA002")).toEqual(["10:medium"]);
  });

  it("detects pull request checkouts in issue_comment workflows", () => {
    expect(summary("pwn-comment.yml", "GHA002")).toEqual(["11:high", "19:low", "28:low"]);
    expect(message("pwn-comment.yml", 11)).toContain("issue_comment");
    expect(message("pwn-comment.yml", 11)).toContain("npm install");
    expect(message("pwn-comment.yml", 19)).toContain("author_association is MEMBER");
    expect(summary("pwn-comment-branch.yml", "GHA002")).toEqual(["29:high", "18:low"]);
    expect(message("pwn-comment-branch.yml", 18)).toContain("TheModdingInquisition/actions-team-membership");
  });

  it("ignores fetches that never reach the working tree and refs the event does not set", () => {
    expect(summary("pwn-not-checkout.yml", "GHA002")).toEqual([]);
  });

  it("treats workflow_dispatch inputs as empty for other events and honours actor checks in scripts", () => {
    expect(summary("pwn-inputs.yml", "GHA002")).toEqual(["28:high", "20:low"]);
    expect(message("pwn-inputs.yml", 20)).toContain("Check user authorization");
    expect(message("pwn-inputs.yml", 28)).toContain("once the label is present");
  });

  it("uses the right article for the event", () => {
    expect(message("pwn-comment.yml", 11)).toContain("in an issue_comment workflow");
  });

  it("follows workflow_run to its upstream workflows", () => {
    expect(summary("pwn-workflow-run.yml", "GHA002")).toEqual(["10:medium", "18:low"]);
    expect(message("pwn-workflow-run.yml", 10)).toContain(
      "a pull request can add a workflow with the same name",
    );
    expect(summary("pwn-workflow-run-pr.yml", "GHA002")).toEqual(["10:high"]);
  });
});
