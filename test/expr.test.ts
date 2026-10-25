import { describe, expect, it } from "vitest";
import { conditionText, parseExpression } from "../src/expr.js";

describe("parseExpression", () => {
  it("parses operators with GitHub's precedence", () => {
    expect(
      parseExpression(
        "github.event_name == 'push' && !contains(github.event.pull_request.labels.*.name, 'x') || false",
      ),
    ).toEqual({
      type: "binary",
      op: "||",
      left: {
        type: "binary",
        op: "&&",
        left: {
          type: "binary",
          op: "==",
          left: { type: "ref", path: "github.event_name" },
          right: { type: "literal", value: "push" },
        },
        right: {
          type: "not",
          operand: {
            type: "call",
            name: "contains",
            args: [
              { type: "ref", path: "github.event.pull_request.labels.*.name" },
              { type: "literal", value: "x" },
            ],
          },
        },
      },
      right: { type: "literal", value: false },
    });
  });

  it("reads literals, ids with dashes, indexes and nested parentheses", () => {
    expect(parseExpression("'it''s'")).toEqual({ type: "literal", value: "it's" });
    expect(parseExpression("1.5")).toEqual({ type: "literal", value: 1.5 });
    expect(parseExpression("null")).toEqual({ type: "literal", value: null });
    expect(parseExpression("steps.my-id.outputs.result")).toEqual({
      type: "ref",
      path: "steps.my-id.outputs.result",
    });
    expect(parseExpression("GitHub.Event['pull_request'].Head.Repo.Fork")).toEqual({
      type: "ref",
      path: "github.event.pull_request.head.repo.fork",
    });
    expect(parseExpression("github.event.commits[0].message")).toEqual({
      type: "ref",
      path: "github.event.commits.*.message",
    });
    expect(parseExpression("((a)) != b")).toEqual({
      type: "binary",
      op: "!=",
      left: { type: "ref", path: "a" },
      right: { type: "ref", path: "b" },
    });
    expect(parseExpression("fromJSON(steps.x.outputs.json).pr")).toEqual({ type: "other" });
    expect(parseExpression("a >= 1 && b < 2 && c <= 3 && d > 4")).not.toBeNull();
  });

  it("returns null for what it cannot parse", () => {
    for (const bad of ["a ==", "(a", "a b", "a ? b", "'open", "a.", "f(a,", ""]) {
      expect(parseExpression(bad)).toBeNull();
    }
  });
});

describe("conditionText", () => {
  it("unwraps ${{ }} and passes booleans through", () => {
    expect(conditionText("${{ false }}")).toBe("false");
    expect(conditionText("  github.actor == 'x'\n")).toBe("github.actor == 'x'");
    expect(conditionText(false)).toBe(false);
    expect(conditionText(true)).toBe(true);
  });

  it("gives up on conditions that mix text and expressions", () => {
    expect(conditionText("${{ a }} && ${{ b }}")).toBeNull();
    expect(conditionText(3)).toBeNull();
  });
});
