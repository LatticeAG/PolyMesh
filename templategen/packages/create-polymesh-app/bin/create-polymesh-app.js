#!/usr/bin/env node

import { access, cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const templateDirectory = resolve(packageDirectory, "template");

const usage = `Usage: npx @latticeag/create-polymesh-app <directory>

Creates a minimal PolyMesh broker/client project. Then run:
  cd <directory>
  npm install
  npm run demo`;

function generatedPackageName(targetDirectory) {
  const candidate = basename(targetDirectory)
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^[._-]+|[._-]+$/g, "");
  return candidate || "polymesh-agents";
}

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function createProject(targetArgument) {
  if (!targetArgument || targetArgument.startsWith("-")) {
    throw new Error("A new project directory is required.\n\n" + usage);
  }

  const destination = resolve(process.cwd(), targetArgument);
  if (await exists(destination)) {
    throw new Error(`Refusing to overwrite the existing path: ${destination}`);
  }

  await mkdir(dirname(destination), { recursive: true });
  await cp(templateDirectory, destination, { recursive: true, errorOnExist: true });

  const manifestPath = resolve(destination, "package.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  manifest.name = generatedPackageName(destination);
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

  process.stdout.write(`Created ${destination}\n\nNext steps:\n  cd ${targetArgument}\n  npm install\n  npm run demo\n`);
}

async function main(argv = process.argv.slice(2)) {
  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) {
    process.stdout.write(`${usage}\n`);
    return;
  }
  if (argv.length !== 1) {
    throw new Error(usage);
  }
  await createProject(argv[0]);
}

void main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
