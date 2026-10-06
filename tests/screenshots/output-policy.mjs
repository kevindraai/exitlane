import { randomUUID } from "node:crypto";
import { chmod, mkdir, realpath, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";

const within = (candidate, root) => candidate === root || candidate.startsWith(`${root}${path.sep}`);

export function resolveCaptureOutput({ mode, requestedOutput, repositoryRoot }) {
  const root = path.resolve(repositoryRoot);
  if (mode === "live" && !requestedOutput) {
    throw new Error("Live capture requires an explicit EXITLANE_SCREENSHOT_OUTPUT outside the repository");
  }
  const output = path.resolve(requestedOutput || path.join(root, "docs/images"));
  if (mode === "live" && within(output, root)) {
    throw new Error("Live capture output must be outside the repository");
  }
  return output;
}

export async function prepareCaptureDirectory(directory, { mode, repositoryRoot }) {
  if (mode === "live") {
    const root = await realpath(repositoryRoot);
    let ancestor = directory;
    for (;;) {
      try {
        const resolved = path.resolve(await realpath(ancestor), path.relative(ancestor, directory));
        if (within(resolved, root)) throw new Error("Live capture output resolves inside the repository");
        break;
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
        const parent = path.dirname(ancestor);
        if (parent === ancestor) throw error;
        ancestor = parent;
      }
    }
  }
  await mkdir(directory, { recursive: true, mode: mode === "live" ? 0o700 : 0o755 });
  if (mode === "live") await chmod(directory, 0o700);
}

export async function writeCaptureFile(filename, data, { mode }) {
  if (mode !== "live") {
    await writeFile(filename, data);
    return;
  }
  const temporary = path.join(path.dirname(filename), `.exitlane-capture-${randomUUID()}`);
  try {
    await writeFile(temporary, data, { flag: "wx", mode: 0o600 });
    await chmod(temporary, 0o600);
    await rename(temporary, filename);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
}
