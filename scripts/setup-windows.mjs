import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

const root = process.cwd();
const envExample = path.join(root, '.env.example');
const envFile = path.join(root, '.env');
const packageFile = path.join(root, 'package.json');

function run(command) {
  console.log(`> ${command}`);
  execSync(command, { cwd: root, stdio: 'inherit', shell: process.platform === 'win32' });
}

if (!fs.existsSync(packageFile)) throw new Error('Run this command from the ClickBites project root.');
const major = Number(process.versions.node.split('.')[0]);
if (!Number.isFinite(major) || major < 22) {
  throw new Error(`ClickBites requires Node.js 22.16+; detected ${process.version}.`);
}

if (!fs.existsSync(envFile) && fs.existsSync(envExample)) {
  fs.copyFileSync(envExample, envFile);
  console.log('Created .env from .env.example.');
}

if (!fs.existsSync(path.join(root, 'node_modules'))) {
  run('npm install');
} else {
  console.log('node_modules already exists; skipping npm install.');
}

run('npm run check');
run('npm run build');
run('npm test');
console.log('\nSetup complete. Start the backend with: npm run server');
console.log('Start the frontend in a second CMD with: npm run dev');
