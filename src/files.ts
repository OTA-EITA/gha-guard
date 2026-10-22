import { readdir, stat } from "node:fs/promises";
import path from "node:path";

// Test fixtures often contain deliberately insecure workflows.
const skipDirs = new Set(["node_modules", ".git", "dist", "vendor", "testdata", "fixtures"]);

/**
 * Finds workflow files (.github/workflows/*.yml|yaml) and action metadata
 * (action.yml|yaml anywhere) below root. A file path is returned as is.
 */
export async function findFiles(root: string): Promise<string[]> {
  const info = await stat(root);
  if (info.isFile()) return [root];
  const out: string[] = [];
  const workflows = path.join(root, ".github", "workflows");
  try {
    for (const name of (await readdir(workflows)).sort()) {
      if (/\.ya?ml$/.test(name)) out.push(path.join(workflows, name));
    }
  } catch {
    // no workflows directory
  }
  const walk = async (dir: string): Promise<void> => {
    for (const entry of (await readdir(dir, { withFileTypes: true })).sort((a, b) =>
      a.name.localeCompare(b.name),
    )) {
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) await walk(path.join(dir, entry.name));
      } else if (entry.name === "action.yml" || entry.name === "action.yaml") {
        out.push(path.join(dir, entry.name));
      }
    }
  };
  await walk(root);
  return out;
}
