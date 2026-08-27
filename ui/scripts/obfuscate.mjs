import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import JavaScriptObfuscator from 'javascript-obfuscator';

const assetsDirectory = path.resolve('dist', 'assets');
const entries = (await readdir(assetsDirectory, { withFileTypes: true }))
  .filter((entry) => entry.isFile() && entry.name.endsWith('.js'))
  .sort((left, right) => left.name.localeCompare(right.name));

if (entries.length === 0) {
  throw new Error(`No JavaScript bundles found in ${assetsDirectory}`);
}

for (const entry of entries) {
  const file = path.join(assetsDirectory, entry.name);
  const source = await readFile(file, 'utf8');
  const output = JavaScriptObfuscator.obfuscate(source, {
    compact: true,
    renameGlobals: false,
    seed: 0x4d415254,
    selfDefending: false,
    sourceMap: false,
  }).getObfuscatedCode();
  await writeFile(file, output, 'utf8');
}
