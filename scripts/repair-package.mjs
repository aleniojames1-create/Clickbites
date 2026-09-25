import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const packageFile = path.join(root, 'package.json');

if (!fs.existsSync(packageFile)) {
  console.error('ERROR: package.json was not found. Run this script from the ClickBites project root.');
  process.exit(1);
}

const pkg = JSON.parse(fs.readFileSync(packageFile, 'utf8'));
pkg.type ||= 'module';
pkg.private = pkg.private ?? true;
pkg.scripts = {
  ...(pkg.scripts || {}),
  server: 'node server/server.js',
  start: 'node server/server.js',
  dev: 'npm run dev:frontend',
  'dev:frontend': 'node scripts/frontend-dev.mjs',
  build: 'node scripts/build-check.mjs',
  check: 'node scripts/check-project.mjs',
  test: 'node --test tests/*.test.mjs',
  'seed:admin': 'node scripts/seed-admin.mjs'
};
fs.writeFileSync(packageFile, JSON.stringify(pkg, null, 2) + '\n');
console.log('ClickBites package.json repaired. Available commands:');
console.log('  npm run server');
console.log('  npm run dev');
console.log('  npm run check');
console.log('  npm test');
console.log('  npm run build');
console.log('  npm run seed:admin');
