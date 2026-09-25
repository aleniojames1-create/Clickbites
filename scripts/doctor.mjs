import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const root = process.cwd();
const pkgPath = path.join(root, 'package.json');
const requiredFiles = [
  'package.json', 'package-lock.json', '.env.example',
  'public/index.html', 'server/server.js', 'server/schema.sql',
  'server/risk-engine.js', 'scripts/frontend-dev.mjs',
  'scripts/build-check.mjs', 'tests/smoke.test.mjs'
];

function run(command, args) {
  const r = spawnSync(command, args, { cwd: root, encoding: 'utf8', shell: process.platform === 'win32' });
  return { ok: r.status === 0, out: (r.stdout || '').trim(), err: (r.stderr || '').trim() };
}
function check(label, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${label}${detail ? ` — ${detail}` : ''}`);
  return ok;
}

console.log('=== ClickBites Doctor ===');
let allOk = true;
const node = run('node', ['-v']);
allOk &&= check('Node.js', node.ok, node.out || node.err);
const npm = run('npm', ['-v']);
allOk &&= check('npm', npm.ok, npm.out || npm.err);

let pkg = null;
try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')); allOk &&= check('package.json parses', true); }
catch (e) { allOk = false; check('package.json parses', false, e.message); }

for (const file of requiredFiles) allOk &&= check(`file ${file}`, fs.existsSync(path.join(root, file)));
if (pkg) {
  for (const name of ['server','server:backend','dev','dev:frontend','dev:backend','build','check','test','seed:admin']) {
    allOk &&= check(`npm script ${name}`, Boolean(pkg.scripts?.[name]));
  }
  for (const dep of Object.keys(pkg.dependencies || {})) {
    allOk &&= check(`dependency declared: ${dep}`, true);
  }
}

const envExists = fs.existsSync(path.join(root, '.env'));
check('.env', envExists, envExists ? 'present' : 'missing; copy .env.example to .env before starting');
if (envExists) {
  const env = fs.readFileSync(path.join(root, '.env'), 'utf8');
  for (const key of ['JWT_SECRET','PORT','FRONTEND_PORT']) {
    const found = new RegExp(`^${key}\\s*=`, 'm').test(env);
    allOk &&= check(`.env key ${key}`, found);
  }
}

const lock = run('npm', ['ci', '--dry-run', '--ignore-scripts', '--no-audit', '--no-fund']);
allOk &&= check('package-lock consistency (npm ci --dry-run)', lock.ok, lock.ok ? 'OK' : (lock.err || lock.out).slice(0, 500));

const build = run('npm', ['run', 'build']);
allOk &&= check('frontend/backend build check', build.ok, build.ok ? 'OK' : (build.err || build.out).slice(0, 500));

console.log(allOk ? '\nALL STATIC CHECKS PASSED.' : '\nSOME CHECKS FAILED. Fix the FAIL lines before deployment.');
process.exit(allOk ? 0 : 1);
