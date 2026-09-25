import fs from 'node:fs';
import path from 'node:path';
const root=process.cwd();
const required=['package.json','server/server.js','server/schema.sql','public/index.html','.env.example'];
const missing=required.filter(f=>!fs.existsSync(path.join(root,f)));
if(missing.length){console.error('Missing required files:',missing.join(', '));process.exit(1)}
const html=fs.readFileSync(path.join(root,'public/index.html'),'utf8');
if(!html.includes('ClickBites')) throw new Error('Frontend validation failed');
console.log('ClickBites build check passed. Static frontend and backend entry points are present.');
