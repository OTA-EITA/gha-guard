import { describe, expect, it } from "vitest";
import { envName, findInjections } from "../src/rules/injection.js";

describe("findInjections", () => {
  it("flags attacker-controlled contexts", () => {
    const script = [
      'echo "${{ github.event.issue.title }}"',
      "echo ${{github.head_ref}}",
      "echo ${{ github.event.commits[0].message }}",
      "echo ${{ github.event.pull_request.head.ref }}",
      "echo ${{ github.event.workflow_run.head_commit.author.email }}",
      "echo ${{ github.event.pages.*.page_name }}",
    ].join("\n");
    expect(findInjections(script).map((i) => i.context)).toEqual([
      "github.event.issue.title",
      "github.head_ref",
      "github.event.commits[0].message",
      "github.event.pull_request.head.ref",
      "github.event.workflow_run.head_commit.author.email",
      "github.event.pages.*.page_name",
    ]);
  });

  it("ignores values the attacker cannot choose", () => {
    const script =
      "echo ${{ github.sha }} ${{ github.event.pull_request.number }} ${{ secrets.TOKEN }} ${{ inputs.name }}";
    expect(findInjections(script)).toEqual([]);
  });
});

describe("envName", () => {
  it.each([
    ["github.event.issue.title", "ISSUE_TITLE"],
    ["github.head_ref", "HEAD_REF"],
    ["github.event.commits[0].message", "COMMITS_MESSAGE"],
    ["github.event.pull_request.head.ref", "HEAD_REF"],
    ["github.event.workflow_run.head_commit.author.email", "AUTHOR_EMAIL"],
  ])("%s -> %s", (context, name) => {
    expect(envName(context)).toBe(name);
  });
});
