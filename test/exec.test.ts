import { describe, expect, it } from "vitest";
import { scriptRunsCode, stepRunsCode } from "../src/exec.js";
import type { Step } from "../src/workflow.js";
import { YAMLMap } from "yaml";

function step(fields: Partial<Step>): Step {
  return { node: new YAMLMap(), line: 1, with: {}, env: {}, ...fields };
}

describe("scriptRunsCode", () => {
  it.each([
    ["npm ci", "npm ci"],
    ["yarn install --frozen-lockfile", "yarn install"],
    ["yarn", "yarn"],
    ["cd web && pnpm run build", "pnpm run"],
    ["bun test", "bun test"],
    ["python -m pip install -e .[test]", "pip install -e"],
    ["pip install .", "pip install ."],
    ["pip install -r requirements.txt", "pip install -r"],
    ["poetry install", "poetry install"],
    ["uv sync", "uv sync"],
    ["python setup.py test", "python setup.py"],
    ["python -m pytest", "pytest"],
    ["make e2e", "make"],
    ["sudo make install", "make"],
    ["go test ./...", "go test"],
    ["cargo build --release", "cargo build"],
    ["./gradlew check", "./gradlew"],
    ["mvn -B verify", "mvn"],
    ["bundle exec rake", "bundle exec"],
    ["composer install", "composer install"],
    ["docker build -t x .", "docker build"],
    ["docker buildx build .", "docker buildx build"],
    ["vercel build --token=$T", "vercel build"],
    ["./scripts/test.sh", "./scripts/test.sh"],
    ["bash ci/classify.sh", "bash ci/classify.sh"],
    ["node scripts/build.js", "node scripts/build.js"],
    ["npx playwright test", "playwright test"],
  ])("%s", (script, expected) => {
    expect(scriptRunsCode(script)).toBe(expected);
  });

  it.each([
    "git diff --stat",
    "echo make sure it works",
    'echo "run npm ci locally"',
    "npm install --global vercel@latest",
    "pip install requests",
    "ls && git status",
    "gh pr comment 1 --body hi",
    "cat package.json | jq .version",
    "node -e 'console.log(1)'",
  ])("%s does not run repository code", (script) => {
    expect(scriptRunsCode(script)).toBeUndefined();
  });
});

describe("stepRunsCode", () => {
  it("recognises local actions, builders and github-script requiring repository files", () => {
    expect(stepRunsCode(step({ uses: "./.github/actions/setup" }))).toBe("./.github/actions/setup");
    expect(stepRunsCode(step({ uses: "docker/build-push-action@v6" }))).toBe("docker/build-push-action");
    expect(
      stepRunsCode(
        step({ uses: "actions/github-script@v7", with: { script: "await require('./.github/x.cjs')()" } }),
      ),
    ).toBe("require('./.github/x.cjs')");
    expect(stepRunsCode(step({ run: "npm test" }))).toBe("npm test");
    expect(stepRunsCode(step({ uses: "actions/upload-artifact@v4" }))).toBeUndefined();
    expect(
      stepRunsCode(step({ uses: "actions/github-script@v7", with: { script: "core.info(1)" } })),
    ).toBeUndefined();
  });
});
