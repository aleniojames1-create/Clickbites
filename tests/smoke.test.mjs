import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

test('required project files exist', () => {
  for (const file of ['package.json','server/server.js','server/schema.sql','public/index.html','run-clickbites.bat','check-clickbites.bat']) {
    assert.equal(fs.existsSync(path.resolve(file)), true, file);
  }
});

test('SQLite schema creates the relational tables and seeds roles/categories', () => {
  const db = new DatabaseSync(':memory:');
  db.exec(fs.readFileSync('server/schema.sql','utf8'));
  const tables = db.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE type='table'").get().n;
  assert.ok(tables >= 20);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM roles').get().n, 3);
  for (const table of ['login_events','login_challenges','user_locations','risk_events']) assert.ok(db.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`).get(table));
  assert.ok(db.prepare('SELECT COUNT(*) AS n FROM categories').get().n >= 8);
  db.close();
});


test('risk engine scores suspicious login signals', async () => {
  const { assessLoginRisk } = await import('../server/risk-engine.js');
  const db = new DatabaseSync(':memory:');
  db.exec(`CREATE TABLE login_events (user_id INTEGER, success INTEGER, created_at TEXT, ip_address TEXT, device_hash TEXT); CREATE TABLE user_locations (user_id INTEGER, latitude REAL, longitude REAL, created_at TEXT);`);
  db.prepare(`INSERT INTO login_events(user_id,success,created_at,ip_address,device_hash) VALUES(1,1,datetime('now','-1 minute'),'10.0.0.1','known')`).run();
  const result = assessLoginRisk(db,{userId:1,ip:'10.0.0.2',userAgent:'test',deviceId:'new-device',latitude:14.5995,longitude:120.9842});
  assert.ok(result.score >= 40);
  assert.ok(['medium','high'].includes(result.riskLevel));
  db.close();
});
