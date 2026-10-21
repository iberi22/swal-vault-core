#!/usr/bin/env node
// Usage: node scripts/vendor-envelope.mjs <destDir> | --check <destDir>
// Copies src/envelope/** and test/vectors/** (repo-relative layout) into destDir and writes VENDORED_FROM.
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DIRS = ['src/envelope', 'test/vectors'];
const MARK = 'VENDORED_FROM';

function walk(base, rel, out = []) {
  const abs = join(base, rel);
  if (!existsSync(abs)) return out;
  for (const n of readdirSync(abs).sort()) {
    const r = `${rel}/${n}`;
    if (statSync(join(base, r)).isDirectory()) walk(base, r, out);
    else out.push(r);
  }
  return out;
}

export function treeSha256(base) {
  const h = createHash('sha256');
  for (const f of DIRS.flatMap((d) => walk(base, d)).sort()) {
    h.update(`${f}\0${createHash('sha256').update(readFileSync(join(base, f))).digest('hex')}\n`);
  }
  return h.digest('hex');
}

function versionOf(base) {
  const p = join(base, 'src/envelope/version.ts');
  if (!existsSync(p)) return null;
  const m = /ENVELOPE_VERSION\s*=\s*'(\d+)\.(\d+)\.(\d+)'/.exec(readFileSync(p, 'utf8'));
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}
function cmp(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}

function fail(msg) {
  console.error(msg);
  process.exit(1);
}

const args = process.argv.slice(2);
const check = args[0] === '--check';
const destArg = check ? args[1] : args[0];
if (!destArg) fail('usage: vendor-envelope.mjs <destDir> | --check <destDir>');
const dest = resolve(destArg);

if (check) {
  const f = join(dest, MARK);
  if (!existsSync(f)) fail(`${MARK} missing in ${dest}`);
  const m = /^tree-sha256:\s*([0-9a-f]{64})\s*$/m.exec(readFileSync(f, 'utf8'));
  if (!m) fail(`${MARK} has no tree-sha256`);
  const actual = treeSha256(dest);
  if (actual !== m[1]) fail(`tree-sha256 mismatch: expected ${m[1]} got ${actual}`);
  console.log(`ok ${actual}`);
} else {
  const src = versionOf(ROOT);
  if (!src) fail('cannot read source envelope version');
  const have = versionOf(dest);
  if (have && cmp(src, have) < 0) fail(`refusing to vendor older ${src.join('.')} over newer ${have.join('.')}`);
  // Refuse any dest equal to, inside, or containing a managed dir (would delete the source tree).
  const overlaps = (a, b) => { const r = relative(a, b); return r === '' || (r !== '..' && !r.startsWith('..' + sep) && !isAbsolute(r)); };
  for (const d of DIRS) {
    const managed = join(ROOT, d);
    if (overlaps(dest, managed) || overlaps(managed, dest)) fail(`refusing to vendor into ${dest}: overlaps source ${managed}`);
  }
  for (const d of DIRS) {
    rmSync(join(dest, d), { recursive: true, force: true });
    mkdirSync(join(dest, d), { recursive: true });
    cpSync(join(ROOT, d), join(dest, d), { recursive: true });
  }
  const git = (...a) => execFileSync('git', a, { cwd: ROOT, encoding: 'utf8' }).trim();
  let commit = 'unknown';
  try { commit = git('rev-parse', 'HEAD'); } catch { /* not a git checkout */ }
  const repo = String(JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).repository?.url ?? 'unknown')
    .replace(/^git\+/, '').replace(/\.git$/, '');
  const hash = treeSha256(dest);
  writeFileSync(join(dest, MARK), `repo: ${repo}\ncommit: ${commit}\nversion: ${src.join('.')}\ntree-sha256: ${hash}\n`);
  console.log(`vendored ${src.join('.')} -> ${dest} (${hash})`);
}
