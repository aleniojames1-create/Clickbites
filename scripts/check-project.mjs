import fs from 'node:fs';
import {execSync} from 'node:child_process';
function cmd(c){try{return execSync(c,{stdio:['ignore','pipe','pipe'],encoding:'utf8'}).trim()}catch(e){return `ERROR: ${e.stderr?.toString()?.trim()||e.message}`}}
console.log('--- ClickBites environment check ---');
console.log('Node:',cmd('node -v'));console.log('npm:',cmd('npm -v'));console.log('package.json:',fs.existsSync('package.json')?'OK':'MISSING');console.log('node_modules:',fs.existsSync('node_modules')?'OK':'MISSING');console.log('.env:',fs.existsSync('.env')?'OK':'MISSING (copy .env.example to .env)');console.log('database directory:',fs.existsSync('data')?'OK':'MISSING');console.log('frontend:',fs.existsSync('public/index.html')?'OK':'MISSING');console.log('backend:',fs.existsSync('server/server.js')?'OK':'MISSING');console.log('risk engine:',fs.existsSync('server/risk-engine.js')?'OK':'MISSING');
try { const pkg=JSON.parse(fs.readFileSync('package.json','utf8')); for (const name of ['server','server:backend','dev','dev:backend']) console.log(`npm script ${name}:`,pkg.scripts?.[name]?'OK':'MISSING'); } catch(e) { console.log('package.json parse:',e.message); }
console.log('build check:',cmd('node scripts/build-check.mjs'));
if (fs.existsSync('node_modules')) {
  console.log('server syntax:',cmd('node --check server/server.js'));
  console.log('frontend syntax:',cmd('node scripts/build-check.mjs'));
  console.log('tests:',cmd('npm test'));
} else {
  console.log('runtime checks: SKIPPED (run npm install first)');
}
