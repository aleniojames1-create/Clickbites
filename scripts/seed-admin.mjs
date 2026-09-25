import 'dotenv/config';
import { DatabaseSync } from 'node:sqlite';
import bcrypt from 'bcryptjs';
import fs from 'node:fs';
import path from 'node:path';
const root=process.cwd();fs.mkdirSync(path.resolve(root,'data'),{recursive:true});const db=new DatabaseSync(path.resolve(root,process.env.DB_FILE||'./data/clickbites.db'));db.exec('PRAGMA foreign_keys=ON;');db.exec(fs.readFileSync(path.resolve(root,'server/schema.sql'),'utf8'));
const email=(process.env.ADMIN_EMAIL||'').toLowerCase().trim();const password=process.env.ADMIN_PASSWORD||'';if(!email||!password){console.error('Set ADMIN_EMAIL and ADMIN_PASSWORD in .env first.');process.exit(1)}
let u=db.prepare('SELECT * FROM users WHERE email=?').get(email);if(!u){const r=db.prepare('INSERT INTO users(email,mobile,password_hash) VALUES(?,?,?)').run(email,null,bcrypt.hashSync(password,12));u=db.prepare('SELECT * FROM users WHERE id=?').get(r.lastInsertRowid);db.prepare('INSERT INTO user_profiles(user_id,full_name,email_verified,phone_verified) VALUES(?,?,1,0)').run(u.id,'ClickBites Administrator');db.prepare('INSERT INTO carts(user_id) VALUES(?)').run(u.id)}
const role=db.prepare("SELECT id FROM roles WHERE name='admin'").get();db.prepare('INSERT OR IGNORE INTO user_roles(user_id,role_id) VALUES(?,?)').run(u.id,role.id);console.log(`Admin ready: ${email}`);db.close();
