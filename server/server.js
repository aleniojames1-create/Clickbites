import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import nodemailer from 'nodemailer';
import { DatabaseSync } from 'node:sqlite';
import { assessLoginRisk, hashDeviceId } from './risk-engine.js';

const ROOT = path.resolve(process.cwd());
const port = Number(process.env.PORT || 4000);
const dbPath = path.resolve(ROOT, process.env.DB_FILE || './data/clickbites.db');
const uploadDir = path.resolve(ROOT, process.env.UPLOAD_DIR || './uploads');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });

const db = new DatabaseSync(dbPath);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
function transaction(fn) { db.exec('BEGIN'); try { const out = fn(); db.exec('COMMIT'); return out; } catch (err) { db.exec('ROLLBACK'); throw err; } }
db.exec(fs.readFileSync(new URL('./schema.sql', import.meta.url), 'utf8'));

const app = express();
app.set('trust proxy', process.env.TRUST_PROXY === 'true');
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
const configuredOrigins = String(process.env.CORS_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
function isAllowedOrigin(origin) {
  if (!origin) return true;
  if (configuredOrigins.length && configuredOrigins.includes(origin)) return true;
  // Development convenience: allow localhost/127.0.0.1 on common Vite ports.
  try {
    const url = new URL(origin);
    const localHost = ['localhost','127.0.0.1','[::1]'].includes(url.hostname);
    return process.env.NODE_ENV !== 'production' && localHost && /^https?:$/.test(url.protocol) && url.port && Number(url.port) >= 3000 && Number(url.port) <= 5199;
  } catch { return false; }
}
// CORS: in development, allow localhost/127.0.0.1 on any port so Vite can
// safely move from 5173 to another free port without causing an
// "Origin not allowed" server error. Production still uses the explicit
// CORS_ORIGINS allow-list.
app.use(cors({
  origin: (origin, cb) => cb(null, isAllowedOrigin(origin) ? origin || true : false),
  credentials: false,
  methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Device-Id', 'X-Client-Latitude', 'X-Client-Longitude', 'X-Client-Accuracy']
}));
// Express 5 requires a named wildcard for this catch-all OPTIONS route.
app.options('/{*splat}', cors({ origin: (origin, cb) => cb(null, isAllowedOrigin(origin) ? origin || true : false) }));
const apiLimiter = rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000),
  limit: Number(process.env.RATE_LIMIT_MAX || 200),
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api', apiLimiter);

// Authentication endpoints have a stricter limiter than ordinary API traffic.
// This helps reduce password spraying, OTP abuse, and recovery-code brute force.
const authLimiter = rateLimit({
  windowMs: Number(process.env.AUTH_RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000),
  limit: Number(process.env.AUTH_RATE_LIMIT_MAX || 20),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Please try again later.' }
});
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/verify-registration-otp', authLimiter);
app.use('/api/auth/resend-registration-otp', authLimiter);
app.use('/api/auth/request-password-reset', authLimiter);
app.use('/api/auth/reset-password', authLimiter);

// Payment webhook uses raw request bytes for signature validation.
app.post('/api/payments/webhooks/paymongo', express.raw({ type: 'application/json' }), (req, res) => {
  try {
    const payload = JSON.parse(req.body.toString('utf8'));
    const eventType = payload?.data?.attributes?.type;
    const data = payload?.data?.attributes?.data;
    const providerId = data?.id;
    if (!eventType || !providerId) return res.status(400).json({ error: 'Invalid webhook payload' });

    if (process.env.PAYMONGO_WEBHOOK_SECRET) {
      const supplied = String(req.headers['paymongo-signature'] || '');
      const parts = Object.fromEntries(supplied.split(',').map(part => { const [key, value] = part.split('='); return [key, value || '']; }));
      const timestamp = Number(parts.t || 0);
      const signature = process.env.PAYMONGO_LIVEMODE === 'true' ? parts.li : parts.te;
      const tolerance = Number(process.env.PAYMONGO_WEBHOOK_TOLERANCE_SECONDS || 300);
      if (!timestamp || !signature || Math.abs(Date.now() / 1000 - timestamp) > tolerance) {
        return res.status(401).json({ error: 'Invalid or expired webhook signature' });
      }
      const signedPayload = `${timestamp}.${req.body.toString('utf8')}`;
      const digest = crypto.createHmac('sha256', process.env.PAYMONGO_WEBHOOK_SECRET).update(signedPayload).digest('hex');
      const expected = Buffer.from(digest, 'utf8');
      const received = Buffer.from(signature, 'utf8');
      if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) {
        return res.status(401).json({ error: 'Invalid webhook signature' });
      }
    }

    const paid = eventType === 'payment.paid';
    const failed = /failed|declined|cancelled|expired/i.test(eventType);
    const refund = /refund/i.test(eventType);
    const payment = db.prepare('SELECT * FROM payments WHERE provider_payment_id = ?').get(providerId);
    if (!payment) return res.status(202).json({ ok: true, ignored: true });

    const status = paid ? 'paid' : refund ? 'refunded' : failed ? 'failed' : payment.status;
    updatePaymentStatus(payment.id, status, JSON.stringify(payload), providerId);
    return res.json({ ok: true });
  } catch (error) {
    console.error('PayMongo webhook error:', error);
    return res.status(400).json({ error: 'Invalid webhook' });
  }
});

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

const publicDir = path.resolve(ROOT, 'public');
app.use('/uploads', express.static(uploadDir, { maxAge: '1h' }));
app.use(express.static(publicDir));

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadDir),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname || '').toLowerCase().replace(/[^a-z0-9.]/g, '');
      cb(null, `${Date.now()}-${crypto.randomBytes(8).toString('hex')}${ext || '.bin'}`);
    }
  }),
  limits: { fileSize: 5 * 1024 * 1024, files: 6 },
  fileFilter: (_req, file, cb) => cb(null, /^image\/(jpeg|png|webp|gif)$/.test(file.mimetype))
});

const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const COMMISSION = Math.max(0, Number(process.env.PLATFORM_COMMISSION_PERCENT || 5));

if (process.env.NODE_ENV === 'production') {
  if (JWT_SECRET.length < 32 || JWT_SECRET === 'dev-only-change-me') {
    throw new Error('Production requires a strong JWT_SECRET of at least 32 characters');
  }
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    throw new Error('Production requires SMTP configuration for mandatory Gmail/email OTP');
  }
}

function nowIso() { return new Date().toISOString(); }
function addMinutes(minutes) { return new Date(Date.now() + minutes * 60_000).toISOString(); }
function normalizeEmail(v) { return typeof v === 'string' && v.trim() ? v.trim().toLowerCase() : null; }
function maskEmail(email) {
  const value = normalizeEmail(email) || '';
  const [local, domain] = value.split('@');
  if (!local || !domain) return 'your email';
  const visible = local.length <= 2 ? local[0] || '*' : local.slice(0, 2);
  return `${visible}${'*'.repeat(Math.max(2, local.length - visible.length))}@${domain}`;
}
function normalizeMobile(v) { return typeof v === 'string' && v.trim() ? v.trim().replace(/[\s()-]/g, '') : null; }
function passwordError(password, confirmPassword = null) {
  const p = String(password || '');
  if (confirmPassword !== null && p !== String(confirmPassword || '')) return 'Passwords do not match';
  if (p.length < 10) return 'Password must be at least 10 characters';
  if (!/[A-Z]/.test(p)) return 'Password must contain an uppercase letter';
  if (!/[a-z]/.test(p)) return 'Password must contain a lowercase letter';
  if (!/[0-9]/.test(p)) return 'Password must contain a number';
  if (!/[^A-Za-z0-9]/.test(p)) return 'Password must contain a special character';
  return null;
}
function requestIp(req) { return String(req.ip || req.socket?.remoteAddress || '').slice(0, 64); }
function clientDeviceHash(req) { return String(req.headers['x-device-id'] || 'unknown').slice(0, 200); }
function clientLocation(req) {
  const lat = Number(req.headers['x-client-latitude']);
  const lon = Number(req.headers['x-client-longitude']);
  const accuracy = Number(req.headers['x-client-accuracy']);
  return Number.isFinite(lat) && lat >= -90 && lat <= 90 && Number.isFinite(lon) && lon >= -180 && lon <= 180
    ? { latitude: lat, longitude: lon, accuracy: Number.isFinite(accuracy) ? accuracy : null } : { latitude: null, longitude: null, accuracy: null };
}
function recordLocation(userId, req, eventType) {
  const loc = clientLocation(req);
  if (loc.latitude === null) return loc;
  db.prepare(`INSERT INTO user_locations(user_id,latitude,longitude,accuracy,source,event_type,ip_address,device_hash) VALUES(?,?,?,?,?,?,?,?)`).run(userId,loc.latitude,loc.longitude,loc.accuracy,'browser',eventType,requestIp(req),clientDeviceHash(req));
  return loc;
}
function createLoginChallenge(userId, risk, req, loc) {
  const raw = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO login_challenges(user_id,challenge_hash,expires_at,risk_score,risk_level,latitude,longitude,accuracy,ip_address,device_hash) VALUES(?,?,?,?,?,?,?,?,?,?)').run(userId,hashRandom(raw),addMinutes(5),risk.score,risk.riskLevel,loc.latitude,loc.longitude,loc.accuracy,requestIp(req),risk.deviceHash);
  return raw;
}
function getLoginChallenge(raw) { return db.prepare('SELECT * FROM login_challenges WHERE challenge_hash=? AND consumed_at IS NULL').get(hashRandom(raw)); }

function safeUser(user) {
  if (!user) return null;
  const profile = db.prepare('SELECT * FROM user_profiles WHERE user_id = ?').get(user.id);
  const roles = db.prepare(`SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=? ORDER BY r.name`).all(user.id).map(r => r.name);
  return {
    id: user.id, email: user.email, mobile: user.mobile, status: user.status,
    createdAt: user.created_at, updatedAt: user.updated_at,
    profile: profile ? { fullName: profile.full_name, profilePicture: profile.profile_picture, emailVerified: !!profile.email_verified, phoneVerified: !!profile.phone_verified, birthDate: profile.birth_date, gender: profile.gender } : null,
    roles
  };
}
function issueToken(user) {
  return jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: '7d' });
}
function getAuthUser(req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return null;
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(payload.sub));
    if (!user || user.status !== 'active') return null;
    return user;
  } catch { return null; }
}
function requireAuth(req, res, next) {
  const user = getAuthUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required' });
  req.user = user;
  next();
}
function hasRole(userId, role) {
  return !!db.prepare(`SELECT 1 FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=? AND r.name=?`).get(userId, role);
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || !hasRole(req.user.id, role)) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}
function grantRole(userId, roleName) {
  const role = db.prepare('SELECT id FROM roles WHERE name=?').get(roleName);
  if (!role) throw new Error(`Role ${roleName} is missing`);
  db.prepare('INSERT OR IGNORE INTO user_roles(user_id, role_id) VALUES (?,?)').run(userId, role.id);
}
function audit(adminId, action, entityType, entityId, targetUserId, metadata = {}) {
  db.prepare(`INSERT INTO admin_audit_logs(admin_user_id,action,entity_type,entity_id,target_user_id,metadata_json) VALUES(?,?,?,?,?,?)`).run(adminId, action, entityType, entityId ?? null, targetUserId ?? null, JSON.stringify(metadata));
}
function notify(userId, type, title, message) {
  db.prepare('INSERT INTO notifications(user_id,type,title,message) VALUES(?,?,?,?)').run(userId, type, title, message);
}
function hashRandom(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
let smtpTransporter = null;
function cleanEnv(value) {
  return String(value ?? '').trim().replace(/^['\"]|['\"]$/g, '');
}
function getMailer() {
  const host = cleanEnv(process.env.SMTP_HOST);
  const user = cleanEnv(process.env.SMTP_USER);
  // Google App Passwords are commonly copied with spaces (xxxx xxxx xxxx xxxx).
  // SMTP authentication must receive the 16-character value without spaces.
  const pass = cleanEnv(process.env.SMTP_PASS).replace(/\s+/g, '');
  if (!host || !user || !pass || /your-16-character-google-app-password/i.test(pass) || /yourgmail@gmail\.com/i.test(user)) return null;
  if (!smtpTransporter) {
    const smtpPort = Number(cleanEnv(process.env.SMTP_PORT) || 587);
    smtpTransporter = nodemailer.createTransport({
      host,
      port: smtpPort,
      secure: smtpPort === 465,
      requireTLS: smtpPort === 587,
      auth: { user, pass },
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 15000
    });
  }
  return smtpTransporter;
}
function emailDeliveryError(error) {
  const code = String(error?.responseCode || error?.code || '');
  const response = String(error?.response || error?.message || '');
  if (code === '535' || /5\.7\.8|BadCredentials|Username and Password not accepted/i.test(response)) {
    return 'Gmail authentication failed. In .env, use your Gmail address and a Google App Password (not your normal Gmail password). Enable 2-Step Verification first, then create the App Password and paste its 16 characters into SMTP_PASS.';
  }
  if (/ENOTFOUND|ECONNREFUSED|ETIMEDOUT|ECONNRESET/i.test(code + ' ' + response)) {
    return 'ClickBites could not connect to Gmail SMTP. Check SMTP_HOST=smtp.gmail.com, SMTP_PORT=587, your internet connection, and your Gmail SMTP settings.';
  }
  return 'ClickBites could not send the Gmail verification email. Check the Gmail/SMTP settings in your .env file.';
}
async function sendEmail(to, subject, text) {
  const transporter = getMailer();
  if (!transporter) {
    if (process.env.NODE_ENV === 'production' || String(process.env.EMAIL_DEV_FALLBACK || 'true').toLowerCase() === 'false') {
      throw new Error('Gmail SMTP is not configured. Set SMTP_USER to your Gmail address and SMTP_PASS to a Google App Password.');
    }
    console.log(`[DEV EMAIL FALLBACK] ${to}\nSubject: ${subject}\n${text}`);
    return { delivered: false, developmentFallback: true };
  }
  try {
    await transporter.sendMail({
      from: cleanEnv(process.env.SMTP_FROM) || cleanEnv(process.env.SMTP_USER),
      to,
      subject,
      text
    });
    return { delivered: true, developmentFallback: false };
  } catch (error) {
    const friendly = emailDeliveryError(error);
    console.error('[GMAIL SMTP ERROR]', friendly);
    console.error(error);
    if (process.env.NODE_ENV !== 'production' && String(process.env.EMAIL_DEV_FALLBACK || 'true').toLowerCase() !== 'false') {
      console.log(`[DEV EMAIL FALLBACK AFTER SMTP ERROR] ${to}\nSubject: ${subject}\n${text}`);
      return { delivered: false, developmentFallback: true, smtpError: friendly };
    }
    const wrapped = new Error(friendly);
    wrapped.statusCode = 503;
    throw wrapped;
  }
}
async function sendSms(to, body) {
  if (!process.env.TWILIO_ACCOUNT_SID) {
    console.log(`[DEV SMS] ${to}\n${body}`);
    return;
  }
  const auth = Buffer.from(`${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64');
  const params = new URLSearchParams({ To: to, From: process.env.TWILIO_FROM, Body: body });
  const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${process.env.TWILIO_ACCOUNT_SID}/Messages.json`, { method: 'POST', headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' }, body: params });
  if (!response.ok) throw new Error(`SMS provider error: ${response.status}`);
}
function createOtp(userId, channel, destination, purpose) {
  const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  const codeHash = hashRandom(code);
  db.prepare(`UPDATE otp_verifications SET consumed_at=? WHERE destination=? AND purpose=? AND consumed_at IS NULL`).run(nowIso(), destination, purpose);
  db.prepare(`INSERT INTO otp_verifications(user_id,channel,destination,purpose,code_hash,expires_at) VALUES(?,?,?,?,?,?)`).run(userId, channel, destination, purpose, codeHash, addMinutes(Number(process.env.OTP_MINUTES || 10)));
  return code;
}
function verifyOtp(destination, purpose, code) {
  const row = db.prepare(`SELECT * FROM otp_verifications WHERE destination=? AND purpose=? AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1`).get(destination, purpose);
  if (!row) return { ok: false, reason: 'OTP not found or already used' };
  if (new Date(row.expires_at) < new Date()) return { ok: false, reason: 'OTP expired' };
  if (row.attempts >= Number(process.env.OTP_MAX_ATTEMPTS || 5)) return { ok: false, reason: 'Too many attempts' };
  db.prepare('UPDATE otp_verifications SET attempts=attempts+1 WHERE id=?').run(row.id);
  if (!crypto.timingSafeEqual(Buffer.from(row.code_hash), Buffer.from(hashRandom(code)))) return { ok: false, reason: 'Invalid OTP' };
  db.prepare('UPDATE otp_verifications SET consumed_at=? WHERE id=?').run(nowIso(), row.id);
  return { ok: true, userId: row.user_id };
}
function price(cents) { return `₱${(cents / 100).toFixed(2)}`; }
function ensureCart(userId) {
  let cart = db.prepare('SELECT * FROM carts WHERE user_id=?').get(userId);
  if (!cart) {
    const result = db.prepare('INSERT INTO carts(user_id) VALUES(?)').run(userId);
    cart = db.prepare('SELECT * FROM carts WHERE id=?').get(result.lastInsertRowid);
  }
  return cart;
}
function serializeProduct(p) {
  const images = db.prepare('SELECT image_url FROM product_images WHERE product_id=? ORDER BY sort_order,id').all(p.id).map(x => x.image_url);
  const shop = db.prepare('SELECT id,name,location,contact_number,operating_hours,status FROM shops WHERE id=?').get(p.shop_id);
  const category = p.category_id ? db.prepare('SELECT name FROM categories WHERE id=?').get(p.category_id)?.name : null;
  return { id:p.id, name:p.name, description:p.description, priceCents:p.price_cents, price:price(p.price_cents), stock:p.stock, status:p.status, rating:p.rating, ratingCount:p.rating_count, images, image:images[0] || null, category, shop: shop ? {id:shop.id,name:shop.name,location:shop.location,contact:shop.contact_number,operatingHours:shop.operating_hours,status:shop.status} : null, externalUrl:p.external_url };
}
function serializeShop(s) {
  const owner = db.prepare(`SELECT u.id,u.email,u.mobile,up.full_name FROM users u LEFT JOIN user_profiles up ON up.user_id=u.id WHERE u.id=?`).get(s.owner_user_id);
  const category = s.category_id ? db.prepare('SELECT name FROM categories WHERE id=?').get(s.category_id)?.name : null;
  return { id:s.id, name:s.name, description:s.description, category, logo:s.logo, coverImage:s.cover_image, location:s.location, contactNumber:s.contact_number, contactEmail:s.contact_email, externalUrl:s.external_url, operatingHours:s.operating_hours, status:s.status, disapprovalReason:s.disapproval_reason, createdAt:s.created_at, updatedAt:s.updated_at, owner: owner ? {id:owner.id,fullName:owner.full_name,email:owner.email,mobile:owner.mobile} : null };
}
function orderDetails(orderId) {
  const order = db.prepare(`SELECT o.*, s.name shop_name, u.email buyer_email, u.mobile buyer_mobile, up.full_name buyer_name FROM orders o JOIN shops s ON s.id=o.shop_id JOIN users u ON u.id=o.buyer_user_id LEFT JOIN user_profiles up ON up.user_id=u.id WHERE o.id=?`).get(orderId);
  if (!order) return null;
  const items = db.prepare('SELECT * FROM order_items WHERE order_id=? ORDER BY id').all(orderId);
  const address = order.address_id ? db.prepare('SELECT * FROM addresses WHERE id=?').get(order.address_id) : null;
  const payments = db.prepare('SELECT id,provider,method,provider_payment_id,provider_reference,amount_cents,currency,status,checkout_url,paid_at,refunded_at,created_at FROM payments WHERE order_id=? ORDER BY id DESC').all(orderId);
  return { id:order.id, orderNumber:order.order_number, shop:{id:order.shop_id,name:order.shop_name}, buyer:{id:order.buyer_user_id,name:order.buyer_name,email:order.buyer_email,mobile:order.buyer_mobile}, items, address, subtotalCents:order.subtotal_cents, deliveryFeeCents:order.delivery_fee_cents, platformFeeCents:order.platform_fee_cents, totalCents:order.total_cents, total:price(order.total_cents), paymentMethod:order.payment_method, paymentStatus:order.payment_status, orderStatus:order.order_status, notes:order.notes, createdAt:order.created_at, updatedAt:order.updated_at, payments };
}
function updatePaymentStatus(paymentId, status, rawReference = null, providerId = null) {
  const payment = db.prepare('SELECT * FROM payments WHERE id=?').get(paymentId);
  if (!payment) return;
  const paidAt = status === 'paid' ? nowIso() : payment.paid_at;
  const refundedAt = status === 'refunded' ? nowIso() : payment.refunded_at;
  db.prepare(`UPDATE payments SET status=?, raw_reference=COALESCE(?,raw_reference), provider_payment_id=COALESCE(?,provider_payment_id), paid_at=?, refunded_at=?, updated_at=? WHERE id=?`).run(status, rawReference, providerId, paidAt, refundedAt, nowIso(), paymentId);
  if (status === 'paid') db.prepare(`UPDATE orders SET payment_status='paid', order_status=CASE WHEN order_status='pending' THEN 'confirmed' ELSE order_status END, updated_at=? WHERE id=?`).run(nowIso(), payment.order_id);
  else if (['failed','cancelled','expired','refunded'].includes(status)) db.prepare('UPDATE orders SET payment_status=?, updated_at=? WHERE id=?').run(status, nowIso(), payment.order_id);
}

// Email diagnostics: useful during local setup without exposing SMTP credentials.
app.get('/api/auth/email-status', async (_req, res) => {
  const host = cleanEnv(process.env.SMTP_HOST);
  const user = cleanEnv(process.env.SMTP_USER);
  const pass = cleanEnv(process.env.SMTP_PASS).replace(/\s+/g, '');
  if (!host || !user || !pass || /your-16-character-google-app-password/i.test(pass) || /yourgmail@gmail\.com/i.test(user)) {
    return res.json({ configured: false, provider: 'Gmail SMTP', message: 'Set SMTP_USER to your Gmail address and SMTP_PASS to a Google App Password.' });
  }
  try {
    await getMailer().verify();
    return res.json({ configured: true, provider: 'Gmail SMTP', verified: true, account: maskEmail(user) });
  } catch (error) {
    return res.status(503).json({ configured: true, provider: 'Gmail SMTP', verified: false, error: emailDeliveryError(error), account: maskEmail(user) });
  }
});

// ---------- Auth ----------
app.post('/api/auth/register', async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');
    const confirmPassword = String(req.body.confirmPassword || '');
    const fullName = String(req.body.fullName || '').trim();
    const passError = passwordError(password, confirmPassword);

    if (!fullName) return res.status(400).json({ error: 'Full name is required' });
    if (!email || !/^[^\s@]+@gmail\.com$/i.test(email)) {
      return res.status(400).json({ error: 'Please use a valid Gmail address (example@gmail.com)' });
    }
    if (passError) return res.status(400).json({ error: passError });
    if (db.prepare('SELECT id FROM users WHERE email=?').get(email)) {
      return res.status(409).json({ error: 'This Gmail address is already registered. Please log in.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const userId = transaction(() => {
      const result = db.prepare('INSERT INTO users(email,mobile,password_hash) VALUES(?,?,?)').run(email, null, passwordHash);
      const id = Number(result.lastInsertRowid);
      db.prepare('INSERT INTO user_profiles(user_id,full_name,email_verified) VALUES(?,?,0)').run(id, fullName);
      db.prepare('INSERT INTO carts(user_id) VALUES(?)').run(id);
      grantRole(id, 'user');
      return id;
    });

    const user = db.prepare('SELECT * FROM users WHERE id=?').get(userId);
    const code = createOtp(user.id, 'email', email, 'verify_email');
    await sendEmail(
      email,
      'ClickBites Gmail verification code',
      `Hello ${fullName},\n\nYour ClickBites Gmail verification code is ${code}. It expires in ${Number(process.env.OTP_MINUTES || 10)} minutes.\n\nIf you did not create this account, you can ignore this email.`
    );

    return res.status(201).json({
      requiresEmailVerification: true,
      maskedEmail: maskEmail(email),
      email
    });
  } catch (e) { next(e); }
});

app.post('/api/auth/verify-registration-otp', async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    const code = String(req.body.otp || '').trim();
    if (!email || !/^[^\s@]+@gmail\.com$/i.test(email) || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: 'Enter the 6-digit OTP sent to your Gmail.' });
    }

    const result = verifyOtp(email, 'verify_email', code);
    if (!result.ok) return res.status(400).json({ error: result.reason || 'Invalid verification code' });

    const user = db.prepare('SELECT * FROM users WHERE id=? AND email=?').get(result.userId, email);
    if (!user || user.status !== 'active') return res.status(403).json({ error: 'Account is unavailable' });

    db.prepare('UPDATE user_profiles SET email_verified=1, updated_at=? WHERE user_id=?').run(nowIso(), user.id);
    db.prepare('UPDATE users SET updated_at=? WHERE id=?').run(nowIso(), user.id);
    db.prepare('INSERT INTO risk_events(user_id,event_type,risk_score,risk_level,signals_json,metadata_json) VALUES(?,?,?,?,?,?)')
      .run(user.id, 'email_verified', 0, 'low', JSON.stringify(['registration_otp_verified']), JSON.stringify({ ip: requestIp(req), deviceHash: clientDeviceHash(req) }));

    res.json({ ok: true, token: issueToken(user), user: safeUser(user) });
  } catch (e) { next(e); }
});

app.post('/api/auth/resend-registration-otp', async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    if (!email || !/^[^\s@]+@gmail\.com$/i.test(email)) return res.status(400).json({ error: 'Valid Gmail address is required' });
    const user = db.prepare('SELECT u.*, up.email_verified FROM users u LEFT JOIN user_profiles up ON up.user_id=u.id WHERE u.email=?').get(email);
    if (!user || user.email_verified) return res.json({ ok: true });
    const code = createOtp(user.id, 'email', email, 'verify_email');
    await sendEmail(email, 'ClickBites Gmail verification code', `Your new ClickBites verification code is ${code}. It expires in ${Number(process.env.OTP_MINUTES || 10)} minutes.`);
    res.json({ ok: true, maskedEmail: maskEmail(email) });
  } catch (e) { next(e); }
});

app.post('/api/auth/login', async (req,res,next) => {
  try {
    const email = normalizeEmail(req.body.email || req.body.identifier);
    const password = String(req.body.password || '');
    if (!email) return res.status(400).json({ error: 'Gmail is required' });
    const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      if (user) {
        db.prepare('INSERT INTO login_events(user_id,identifier,success,ip_address,user_agent,device_hash) VALUES(?,?,?,?,?,?)')
          .run(user.id, email, 0, requestIp(req), String(req.headers['user-agent']||'').slice(0,500), clientDeviceHash(req));
      }
      return res.status(401).json({ error: 'Invalid Gmail or password' });
    }
    if (user.status !== 'active') return res.status(403).json({ error: `Account is ${user.status}` });

    const profile = db.prepare('SELECT email_verified FROM user_profiles WHERE user_id=?').get(user.id);
    if (!profile?.email_verified) {
      return res.status(403).json({ error: 'Please verify your Gmail first. We can send you a new verification code.', requiresEmailVerification: true, email: user.email, maskedEmail: maskEmail(user.email) });
    }

    const loc = recordLocation(user.id, req, 'login');
    const risk = assessLoginRisk(db, {
      userId:user.id,
      ip:requestIp(req),
      userAgent:req.headers['user-agent'],
      deviceId:clientDeviceHash(req),
      latitude:loc.latitude,
      longitude:loc.longitude
    });

    if (risk.riskLevel === 'high') {
      db.prepare('INSERT INTO risk_events(user_id,event_type,risk_score,risk_level,signals_json,metadata_json) VALUES(?,?,?,?,?,?)')
        .run(user.id,'login_blocked',risk.score,risk.riskLevel,JSON.stringify(risk.signals),JSON.stringify({ip:requestIp(req),distanceKm:risk.distanceKm}));
      return res.status(403).json({ error: 'Login temporarily blocked because unusual activity was detected. Please try again later or contact support.', riskLevel:risk.riskLevel });
    }

    db.prepare('INSERT INTO login_events(user_id,identifier,success,risk_score,risk_level,risk_signals_json,ip_address,user_agent,device_hash) VALUES(?,?,?,?,?,?,?,?,?)')
      .run(user.id,email,1,risk.score,risk.riskLevel,JSON.stringify(risk.signals),requestIp(req),String(req.headers['user-agent']||'').slice(0,500),risk.deviceHash);
    db.prepare('UPDATE users SET updated_at=? WHERE id=?').run(nowIso(),user.id);
    res.json({ token:issueToken(user), user:safeUser(user), locationCaptured:loc.latitude !== null, riskLevel:risk.riskLevel, riskScore:risk.score, riskSignals:risk.signals, riskEngine:'heuristic-v1' });
  } catch (e) { next(e); }
});

app.post('/api/auth/request-password-reset', async (req,res,next)=>{
  try {
    const identifier = String(req.body.identifier || '').trim();
    const email = normalizeEmail(identifier);
    const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);

    // Always return the same response shape so the endpoint does not disclose account existence.
    if (!user || !user.email) return res.json({ok:true});

    const code = createOtp(user.id,'email',user.email,'password_reset');
    await sendEmail(
      user.email,
      'ClickBites password reset OTP',
      `Your ClickBites password reset OTP is ${code}. It expires in ${Number(process.env.OTP_MINUTES || 10)} minutes. If you did not request a password reset, ignore this email and secure your account.`
    );

    // Keep the legacy reset-token table available for compatibility, but OTP is the
    // mandatory recovery factor and the reset endpoint no longer depends on a link.
    res.json({ok:true, maskedEmail:maskEmail(user.email)});
  } catch(e){next(e);}
});

app.post('/api/auth/reset-password', async (req,res,next)=>{
  try {
    const email = normalizeEmail(req.body.email);
    const otp = String(req.body.otp || '').trim();
    const newPassword = String(req.body.newPassword || '');
    const confirmPassword = String(req.body.confirmPassword || '');
    const passError = passwordError(newPassword,confirmPassword);

    if (!email || !otp) return res.status(400).json({error:'Email and the 6-digit OTP are required'});
    if (passError) return res.status(400).json({error:passError});

    const result = verifyOtp(email,'password_reset',otp);
    if (!result.ok) return res.status(400).json({error:result.reason});

    const user = db.prepare('SELECT * FROM users WHERE id=? AND email=?').get(result.userId,email);
    if (!user) return res.status(400).json({error:'Recovery verification failed'});

    db.prepare('UPDATE users SET password_hash=?,updated_at=? WHERE id=?')
      .run(await bcrypt.hash(newPassword,12),nowIso(),user.id);
    db.prepare('UPDATE login_challenges SET consumed_at=? WHERE user_id=? AND consumed_at IS NULL')
      .run(nowIso(),user.id);

    db.prepare('INSERT INTO risk_events(user_id,event_type,risk_score,risk_level,signals_json,metadata_json) VALUES(?,?,?,?,?,?)')
      .run(user.id,'password_reset',0,'low',JSON.stringify(['otp_verified']),JSON.stringify({ip:requestIp(req),deviceHash:clientDeviceHash(req)}));

    res.json({ok:true});
  }catch(e){next(e);}
});
app.post('/api/auth/verify-otp', requireAuth, (req,res)=>{
  const destination = req.body.channel === 'email' ? normalizeEmail(req.body.destination) : normalizeMobile(req.body.destination);
  const result = verifyOtp(destination, req.body.purpose, String(req.body.code || ''));
  if (!result.ok || result.userId !== req.user.id) return res.status(400).json({ error: result.reason || 'OTP validation failed' });
  if (req.body.channel === 'email') db.prepare('UPDATE user_profiles SET email_verified=1, updated_at=? WHERE user_id=?').run(nowIso(), req.user.id);
  if (req.body.channel === 'sms') db.prepare('UPDATE user_profiles SET phone_verified=1, updated_at=? WHERE user_id=?').run(nowIso(), req.user.id);
  res.json({ ok:true });
});

// ---------- User/profile ----------
app.get('/api/me', requireAuth, (req,res)=>res.json({user:safeUser(req.user)}));
app.put('/api/me', requireAuth, async (req,res,next)=>{
  try {
    const email = normalizeEmail(req.body.email);
    const mobile = normalizeMobile(req.body.mobile);
    if (email && email !== req.user.email && db.prepare('SELECT id FROM users WHERE email=? AND id<>?').get(email,req.user.id)) return res.status(409).json({error:'Email already used'});
    if (mobile && mobile !== req.user.mobile && db.prepare('SELECT id FROM users WHERE mobile=? AND id<>?').get(mobile,req.user.id)) return res.status(409).json({error:'Mobile already used'});
    db.prepare('UPDATE users SET email=?,mobile=?,updated_at=? WHERE id=?').run(email,mobile,nowIso(),req.user.id);
    db.prepare(`UPDATE user_profiles SET full_name=COALESCE(?,full_name),profile_picture=COALESCE(?,profile_picture),birth_date=COALESCE(?,birth_date),gender=COALESCE(?,gender),updated_at=? WHERE user_id=?`).run(req.body.fullName?.trim() || null, req.body.profilePicture || null, req.body.birthDate || null, req.body.gender || null, nowIso(), req.user.id);
    recordLocation(req.user.id, req, 'profile_update');
    const updated=db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
    res.json({user:safeUser(updated)});
  } catch(e){next(e);}
});
app.post('/api/me/password', requireAuth, async (req,res,next)=>{
  try{
    if (!(await bcrypt.compare(String(req.body.currentPassword||''),req.user.password_hash))) return res.status(400).json({error:'Current password is incorrect'});
    const passError = passwordError(req.body.newPassword, req.body.confirmPassword);
    if (passError) return res.status(400).json({error:passError});
    db.prepare('UPDATE users SET password_hash=?,updated_at=? WHERE id=?').run(await bcrypt.hash(String(req.body.newPassword),12),nowIso(),req.user.id);
    res.json({ok:true});
  }catch(e){next(e);}
});
app.post('/api/me/profile-picture', requireAuth, upload.single('image'), (req,res)=>{
  if (!req.file) return res.status(400).json({error:'Image required'});
  const url = `/uploads/${req.file.filename}`;
  db.prepare('UPDATE user_profiles SET profile_picture=?,updated_at=? WHERE user_id=?').run(url,nowIso(),req.user.id);
  res.json({url});
});

// ---------- Security / location ----------
app.get('/api/me/security', requireAuth, (req,res)=>{
  const latest=db.prepare('SELECT latitude,longitude,accuracy,source,event_type,created_at FROM user_locations WHERE user_id=? ORDER BY created_at DESC LIMIT 1').get(req.user.id);
  const events=db.prepare('SELECT event_type,risk_score,risk_level,signals_json,created_at FROM risk_events WHERE user_id=? ORDER BY created_at DESC LIMIT 20').all(req.user.id).map(x=>({...x,signals:JSON.parse(x.signals_json||'[]')}));
  res.json({latestLocation:latest||null,riskEvents:events});
});
app.post('/api/me/location', requireAuth, (req,res)=>{
  const lat=Number(req.body.latitude), lon=Number(req.body.longitude), accuracy=Number(req.body.accuracy);
  if(!Number.isFinite(lat)||lat<-90||lat>90||!Number.isFinite(lon)||lon<-180||lon>180)return res.status(400).json({error:'Valid latitude and longitude are required'});
  db.prepare('INSERT INTO user_locations(user_id,latitude,longitude,accuracy,source,event_type,ip_address,device_hash) VALUES(?,?,?,?,?,?,?,?)').run(req.user.id,lat,lon,Number.isFinite(accuracy)?accuracy:null,'browser','manual_profile_update',requestIp(req),clientDeviceHash(req));
  res.json({ok:true,latitude:lat,longitude:lon,accuracy:Number.isFinite(accuracy)?accuracy:null});
});

// ---------- Addresses ----------
app.get('/api/addresses', requireAuth, (req,res)=>res.json({addresses:db.prepare('SELECT * FROM addresses WHERE user_id=? ORDER BY is_default DESC,id DESC').all(req.user.id)}));
app.post('/api/addresses', requireAuth, (req,res,next)=>{try{
  const a=req.body; if(!a.recipientName||!a.recipientPhone||!a.line1||!a.city) return res.status(400).json({error:'Recipient, phone, address line and city are required'});
  const tx=transaction(()=>{ if(a.isDefault) db.prepare('UPDATE addresses SET is_default=0 WHERE user_id=?').run(req.user.id); return db.prepare(`INSERT INTO addresses(user_id,label,recipient_name,recipient_phone,line1,line2,barangay,city,province,postal_code,notes,is_default) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).run(req.user.id,a.label||'Home',a.recipientName,a.recipientPhone,a.line1,a.line2||null,a.barangay||null,a.city,a.province||null,a.postalCode||null,a.notes||null,a.isDefault?1:0);});
  res.status(201).json({address:db.prepare('SELECT * FROM addresses WHERE id=?').get(tx().lastInsertRowid)});
}catch(e){next(e);}});
app.put('/api/addresses/:id', requireAuth, (req,res,next)=>{try{
 const id=Number(req.params.id), existing=db.prepare('SELECT * FROM addresses WHERE id=? AND user_id=?').get(id,req.user.id); if(!existing)return res.status(404).json({error:'Address not found'}); const a=req.body;
 if(a.isDefault) db.prepare('UPDATE addresses SET is_default=0 WHERE user_id=?').run(req.user.id);
 db.prepare(`UPDATE addresses SET label=?,recipient_name=?,recipient_phone=?,line1=?,line2=?,barangay=?,city=?,province=?,postal_code=?,notes=?,is_default=?,updated_at=? WHERE id=? AND user_id=?`).run(a.label||existing.label,a.recipientName||existing.recipient_name,a.recipientPhone||existing.recipient_phone,a.line1||existing.line1,a.line2??existing.line2,a.barangay??existing.barangay,a.city||existing.city,a.province??existing.province,a.postalCode??existing.postal_code,a.notes??existing.notes,a.isDefault?1:0,nowIso(),id,req.user.id);
 res.json({address:db.prepare('SELECT * FROM addresses WHERE id=?').get(id)});
}catch(e){next(e);}});
app.delete('/api/addresses/:id', requireAuth,(req,res)=>{const r=db.prepare('DELETE FROM addresses WHERE id=? AND user_id=?').run(Number(req.params.id),req.user.id);res.json({ok:r.changes>0});});

// ---------- Public discovery ----------
app.get('/api/categories',(req,res)=>res.json({categories:db.prepare('SELECT id,name,type FROM categories WHERE is_active=1 ORDER BY type,name').all()}));
app.get('/api/products',(req,res)=>{
  const q=String(req.query.q||'').trim(); const category=String(req.query.category||''); const priceRange=String(req.query.priceRange||''); const minRating=Number(req.query.minRating||0); const openOnly=String(req.query.openOnly||'')==='true';
  const page=Math.max(1,Number(req.query.page||1)); const limit=Math.min(50,Math.max(1,Number(req.query.limit||20))); const offset=(page-1)*limit;
  const clauses=[`s.status='Approved'`,`p.status='available'`,`p.rating>=?`]; const params=[minRating];
  if(q){clauses.push(`(LOWER(p.name) LIKE ? OR LOWER(s.name) LIKE ? OR LOWER(COALESCE(c.name,'')) LIKE ?)`); const like=`%${q.toLowerCase()}%`; params.push(like,like,like);}
  if(category&&category!=='All'){clauses.push('c.name=?');params.push(category);}
  if(priceRange&&priceRange!=='All'){const map={'₱':[0,20000],'₱₱':[20001,50000],'₱₱₱':[50001,999999999]};const range=map[priceRange];if(range){clauses.push('p.price_cents BETWEEN ? AND ?');params.push(...range);}}
  if(openOnly) clauses.push(`(s.operating_hours IS NULL OR s.operating_hours <> '')`);
  const where=clauses.join(' AND ');
  const total=db.prepare(`SELECT COUNT(*) count FROM products p JOIN shops s ON s.id=p.shop_id LEFT JOIN categories c ON c.id=p.category_id WHERE ${where}`).get(...params).count;
  const rows=db.prepare(`SELECT p.* FROM products p JOIN shops s ON s.id=p.shop_id LEFT JOIN categories c ON c.id=p.category_id WHERE ${where} ORDER BY p.created_at DESC LIMIT ? OFFSET ?`).all(...params,limit,offset).map(serializeProduct);
  res.json({items:rows,page,limit,total,pages:Math.ceil(total/limit)});
});
app.get('/api/shops',(req,res)=>{
 const q=String(req.query.q||'').toLowerCase(); const status=req.query.status||'Approved'; const page=Math.max(1,Number(req.query.page||1)); const limit=Math.min(50,Math.max(1,Number(req.query.limit||20))); const offset=(page-1)*limit;
 const params=[]; const clauses=[]; if(status){clauses.push('s.status=?');params.push(status);} if(q){clauses.push('(LOWER(s.name) LIKE ? OR LOWER(s.location) LIKE ?)');const like=`%${q}%`;params.push(like,like);} const where=clauses.length?`WHERE ${clauses.join(' AND ')}`:''; const total=db.prepare(`SELECT COUNT(*) count FROM shops s ${where}`).get(...params).count; const shops=db.prepare(`SELECT * FROM shops s ${where} ORDER BY s.created_at DESC LIMIT ? OFFSET ?`).all(...params,limit,offset).map(serializeShop); res.json({shops,page,limit,total,pages:Math.ceil(total/limit)});
});
app.get('/api/shops/:id',(req,res)=>{const s=db.prepare('SELECT * FROM shops WHERE id=?').get(Number(req.params.id));if(!s)return res.status(404).json({error:'Shop not found'});res.json({shop:serializeShop(s),products:db.prepare('SELECT * FROM products WHERE shop_id=? ORDER BY created_at DESC').all(s.id).map(serializeProduct)});});

// ---------- Shops ----------
app.post('/api/shops', requireAuth, (req,res,next)=>{try{
 const x=req.body; if(!x.name?.trim()) return res.status(400).json({error:'Shop name is required'}); const categoryId=x.categoryId?Number(x.categoryId):null;
 const info=db.prepare(`INSERT INTO shops(owner_user_id,name,description,category_id,logo,cover_image,location,contact_number,contact_email,external_url,operating_hours) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(req.user.id,x.name.trim(),x.description||null,categoryId,x.logo||null,x.coverImage||null,x.location||null,x.contactNumber||null,normalizeEmail(x.contactEmail)||null,x.externalUrl||null,x.operatingHours||null); const id=Number(info.lastInsertRowid); db.prepare('INSERT INTO shop_owners(shop_id,user_id,is_primary) VALUES(?,?,1)').run(id,req.user.id); grantRole(req.user.id,'shop_owner'); notify(req.user.id,'shop_submitted','Shop submitted',`Your shop “${x.name.trim()}” is pending admin review.`); res.status(201).json({shop:serializeShop(db.prepare('SELECT * FROM shops WHERE id=?').get(id))});
}catch(e){next(e);}});
app.post('/api/shops/:id/logo',requireAuth,upload.single('image'),(req,res)=>saveShopImage(req,res,'logo'));
app.post('/api/shops/:id/cover',requireAuth,upload.single('image'),(req,res)=>saveShopImage(req,res,'cover_image'));
function canManageShop(userId,shopId){return !!db.prepare('SELECT 1 FROM shop_owners WHERE shop_id=? AND user_id=?').get(shopId,userId);}
function saveShopImage(req,res,column){const id=Number(req.params.id);if(!canManageShop(req.user.id,id))return res.status(403).json({error:'Not your shop'});if(!req.file)return res.status(400).json({error:'Image required'});const url=`/uploads/${req.file.filename}`;db.prepare(`UPDATE shops SET ${column}=?,updated_at=? WHERE id=?`).run(url,nowIso(),id);res.json({url});}
app.put('/api/shops/:id',requireAuth,(req,res,next)=>{try{const id=Number(req.params.id);if(!canManageShop(req.user.id,id))return res.status(403).json({error:'Not your shop'});const s=db.prepare('SELECT * FROM shops WHERE id=?').get(id);const x=req.body;db.prepare(`UPDATE shops SET name=?,description=?,category_id=?,location=?,contact_number=?,contact_email=?,external_url=?,operating_hours=?,updated_at=? WHERE id=?`).run(x.name||s.name,x.description??s.description,x.categoryId?Number(x.categoryId):s.category_id,x.location??s.location,x.contactNumber??s.contact_number,normalizeEmail(x.contactEmail)??s.contact_email,x.externalUrl??s.external_url,x.operatingHours??s.operating_hours,nowIso(),id);res.json({shop:serializeShop(db.prepare('SELECT * FROM shops WHERE id=?').get(id))});}catch(e){next(e);}});
app.get('/api/my/shops',requireAuth,(req,res)=>res.json({shops:db.prepare('SELECT * FROM shops WHERE owner_user_id=? ORDER BY created_at DESC').all(req.user.id).map(serializeShop)}));

// ---------- Products ----------
app.get('/api/my/shops/:shopId/products',requireAuth,(req,res)=>{const id=Number(req.params.shopId);if(!canManageShop(req.user.id,id))return res.status(403).json({error:'Forbidden'});res.json({products:db.prepare('SELECT * FROM products WHERE shop_id=? ORDER BY created_at DESC').all(id).map(serializeProduct)});});
app.post('/api/my/shops/:shopId/products',requireAuth,(req,res,next)=>{try{const shopId=Number(req.params.shopId);if(!canManageShop(req.user.id,shopId))return res.status(403).json({error:'Forbidden'});const x=req.body;if(!x.name||x.priceCents===undefined)return res.status(400).json({error:'Name and price are required'});const info=db.prepare(`INSERT INTO products(shop_id,category_id,name,description,price_cents,stock,status,external_url) VALUES(?,?,?,?,?,?,?,?)`).run(shopId,x.categoryId?Number(x.categoryId):null,x.name.trim(),x.description||null,Math.max(0,Number(x.priceCents)),Math.max(0,Number(x.stock||0)),x.status||'available',x.externalUrl||null);res.status(201).json({product:serializeProduct(db.prepare('SELECT * FROM products WHERE id=?').get(info.lastInsertRowid))});}catch(e){next(e);}});
app.put('/api/products/:id',requireAuth,(req,res,next)=>{try{const id=Number(req.params.id);const p=db.prepare('SELECT * FROM products WHERE id=?').get(id);if(!p||!canManageShop(req.user.id,p.shop_id))return res.status(404).json({error:'Product not found'});const x=req.body;db.prepare(`UPDATE products SET category_id=?,name=?,description=?,price_cents=?,stock=?,status=?,external_url=?,updated_at=? WHERE id=?`).run(x.categoryId?Number(x.categoryId):p.category_id,x.name||p.name,x.description??p.description,Math.max(0,Number(x.priceCents??p.price_cents)),Math.max(0,Number(x.stock??p.stock)),x.status||p.status,x.externalUrl??p.external_url,nowIso(),id);res.json({product:serializeProduct(db.prepare('SELECT * FROM products WHERE id=?').get(id))});}catch(e){next(e);}});
app.delete('/api/products/:id',requireAuth,(req,res)=>{const id=Number(req.params.id);const p=db.prepare('SELECT * FROM products WHERE id=?').get(id);if(!p||!canManageShop(req.user.id,p.shop_id))return res.status(404).json({error:'Product not found'});db.prepare('DELETE FROM products WHERE id=?').run(id);res.json({ok:true});});
app.post('/api/products/:id/images',requireAuth,upload.array('images',6),(req,res)=>{const id=Number(req.params.id);const p=db.prepare('SELECT * FROM products WHERE id=?').get(id);if(!p||!canManageShop(req.user.id,p.shop_id))return res.status(404).json({error:'Product not found'});const stmt=db.prepare('INSERT INTO product_images(product_id,image_url,sort_order) VALUES(?,?,?)');req.files.forEach((f,i)=>stmt.run(id,`/uploads/${f.filename}`,i));res.status(201).json({images:db.prepare('SELECT * FROM product_images WHERE product_id=? ORDER BY sort_order,id').all(id)});});
app.get('/api/my/shops/:shopId/dashboard',requireAuth,(req,res)=>{const shopId=Number(req.params.shopId);if(!canManageShop(req.user.id,shopId))return res.status(403).json({error:'Forbidden'});const row=db.prepare(`SELECT COUNT(DISTINCT p.id) total_products, SUM(CASE WHEN p.status='available' THEN 1 ELSE 0 END) available_products, SUM(CASE WHEN p.status='sold_out' THEN 1 ELSE 0 END) sold_out_products, COUNT(DISTINCT o.id) total_orders, SUM(CASE WHEN o.order_status IN ('pending','confirmed','preparing','ready','out_for_delivery') THEN 1 ELSE 0 END) pending_orders, SUM(CASE WHEN o.order_status='completed' THEN 1 ELSE 0 END) completed_orders, SUM(CASE WHEN o.order_status='cancelled' THEN 1 ELSE 0 END) cancelled_orders, COALESCE(SUM(CASE WHEN o.payment_status='paid' AND o.order_status!='cancelled' THEN o.subtotal_cents ELSE 0 END),0) gross_sales, COALESCE(SUM(CASE WHEN o.payment_status='paid' AND o.order_status!='cancelled' THEN o.subtotal_cents-o.platform_fee_cents ELSE 0 END),0) shop_earnings FROM products p LEFT JOIN orders o ON o.shop_id=p.shop_id WHERE p.shop_id=?`).get(shopId);const recentOrders=db.prepare(`SELECT o.id,o.order_number,o.total_cents,o.payment_status,o.order_status,o.created_at,up.full_name buyer_name FROM orders o LEFT JOIN user_profiles up ON up.user_id=o.buyer_user_id WHERE o.shop_id=? ORDER BY o.created_at DESC LIMIT 10`).all(shopId);res.json({stats:{...row,grossSales:price(row.gross_sales||0),shopEarnings:price(row.shop_earnings||0)},recentOrders});});
app.get('/api/my/shops/:shopId/buyers',requireAuth,(req,res)=>{const id=Number(req.params.shopId);if(!canManageShop(req.user.id,id))return res.status(403).json({error:'Forbidden'});const rows=db.prepare(`SELECT u.id buyer_id,up.full_name,u.email,u.mobile,o.id order_id,o.order_number,o.total_cents,o.payment_status,o.order_status,o.created_at FROM orders o JOIN users u ON u.id=o.buyer_user_id LEFT JOIN user_profiles up ON up.user_id=u.id WHERE o.shop_id=? ORDER BY o.created_at DESC LIMIT 200`).all(id);res.json({buyers:rows});});

// ---------- Cart ----------
app.get('/api/cart',requireAuth,(req,res)=>{const cart=ensureCart(req.user.id);const items=db.prepare(`SELECT ci.id,ci.product_id,ci.quantity,p.name,p.price_cents,p.stock,p.status,s.id shop_id,s.name shop_name FROM cart_items ci JOIN products p ON p.id=ci.product_id JOIN shops s ON s.id=p.shop_id WHERE ci.cart_id=? ORDER BY ci.created_at DESC`).all(cart.id).map(i=>({...i,price:price(i.price_cents),lineTotal:price(i.price_cents*i.quantity)}));res.json({cartId:cart.id,items});});
app.post('/api/cart/items',requireAuth,(req,res)=>{const productId=Number(req.body.productId),quantity=Math.max(1,Number(req.body.quantity||1));const p=db.prepare(`SELECT p.*,s.status shop_status FROM products p JOIN shops s ON s.id=p.shop_id WHERE p.id=?`).get(productId);if(!p||p.status!=='available'||p.shop_status!=='Approved')return res.status(400).json({error:'Product is not available'});if(quantity>p.stock)return res.status(400).json({error:'Requested quantity exceeds stock'});const cart=ensureCart(req.user.id);db.prepare(`INSERT INTO cart_items(cart_id,product_id,quantity) VALUES(?,?,?) ON CONFLICT(cart_id,product_id) DO UPDATE SET quantity=MIN(cart_items.quantity+excluded.quantity, ?)`).run(cart.id,productId,quantity,p.stock);res.status(201).json({ok:true});});
app.put('/api/cart/items/:id',requireAuth,(req,res)=>{const cart=ensureCart(req.user.id);const id=Number(req.params.id);const item=db.prepare(`SELECT ci.*,p.stock FROM cart_items ci JOIN products p ON p.id=ci.product_id WHERE ci.id=? AND ci.cart_id=?`).get(id,cart.id);if(!item)return res.status(404).json({error:'Cart item not found'});const q=Math.max(1,Number(req.body.quantity||1));if(q>item.stock)return res.status(400).json({error:'Quantity exceeds stock'});db.prepare('UPDATE cart_items SET quantity=?,updated_at=? WHERE id=?').run(q,nowIso(),id);res.json({ok:true});});
app.delete('/api/cart/items/:id',requireAuth,(req,res)=>{const cart=ensureCart(req.user.id);db.prepare('DELETE FROM cart_items WHERE id=? AND cart_id=?').run(Number(req.params.id),cart.id);res.json({ok:true});});

// ---------- Orders ----------
app.post('/api/orders',requireAuth,(req,res,next)=>{try{
 const addressId=Number(req.body.addressId); const address=db.prepare('SELECT * FROM addresses WHERE id=? AND user_id=?').get(addressId,req.user.id); if(!address)return res.status(400).json({error:'Valid delivery address required'});
 const cart=ensureCart(req.user.id); const items=db.prepare(`SELECT ci.product_id,ci.quantity,p.shop_id,p.name,p.price_cents,p.stock,p.status,s.status shop_status FROM cart_items ci JOIN products p ON p.id=ci.product_id JOIN shops s ON s.id=p.shop_id WHERE ci.cart_id=?`).all(cart.id); if(!items.length)return res.status(400).json({error:'Cart is empty'});
 const groups=new Map(); for(const item of items){if(item.status!=='available'||item.shop_status!=='Approved')return res.status(400).json({error:`${item.name} is not available`});if(item.quantity>item.stock)return res.status(400).json({error:`Not enough stock for ${item.name}`});if(!groups.has(item.shop_id))groups.set(item.shop_id,[]);groups.get(item.shop_id).push(item);}
 const orders=[]; const tx=transaction(()=>{for(const [shopId,shopItems] of groups){const subtotal=shopItems.reduce((sum,i)=>sum+i.price_cents*i.quantity,0);const platformFee=Math.round(subtotal*COMMISSION/100);const total=subtotal;const orderNumber=`CB-${new Date().toISOString().slice(0,10).replaceAll('-','')}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;const r=db.prepare(`INSERT INTO orders(order_number,buyer_user_id,shop_id,address_id,subtotal_cents,platform_fee_cents,total_cents,notes) VALUES(?,?,?,?,?,?,?,?)`).run(orderNumber,req.user.id,shopId,addressId,subtotal,platformFee,total,req.body.notes||null);const orderId=Number(r.lastInsertRowid);for(const i of shopItems){db.prepare('INSERT INTO order_items(order_id,product_id,product_name,unit_price_cents,quantity,line_total_cents) VALUES(?,?,?,?,?,?)').run(orderId,i.product_id,i.name,i.price_cents,i.quantity,i.price_cents*i.quantity);db.prepare('UPDATE products SET stock=MAX(stock-?,0),status=CASE WHEN stock-?<=0 THEN \'sold_out\' ELSE status END,updated_at=? WHERE id=?').run(i.quantity,i.quantity,nowIso(),i.product_id);}orders.push(orderDetails(orderId));}db.prepare('DELETE FROM cart_items WHERE cart_id=?').run(cart.id);});tx();res.status(201).json({orders});
}catch(e){next(e);}});
app.get('/api/orders',requireAuth,(req,res)=>{const status=String(req.query.status||'');const page=Math.max(1,Number(req.query.page||1));const limit=Math.min(50,Math.max(1,Number(req.query.limit||20)));const offset=(page-1)*limit;const args=[req.user.id];let where='o.buyer_user_id=?';if(status){where+=' AND o.order_status=?';args.push(status);}const total=db.prepare(`SELECT COUNT(*) count FROM orders o WHERE ${where}`).get(...args).count;const rows=db.prepare(`SELECT o.*,s.name shop_name FROM orders o JOIN shops s ON s.id=o.shop_id WHERE ${where} ORDER BY o.created_at DESC LIMIT ? OFFSET ?`).all(...args,limit,offset).map(o=>({id:o.id,orderNumber:o.order_number,shop:{id:o.shop_id,name:o.shop_name},totalCents:o.total_cents,total:price(o.total_cents),paymentMethod:o.payment_method,paymentStatus:o.payment_status,orderStatus:o.order_status,createdAt:o.created_at}));res.json({orders:rows,page,limit,total,pages:Math.ceil(total/limit)});});
app.get('/api/orders/:id',requireAuth,(req,res)=>{const o=orderDetails(Number(req.params.id));if(!o)return res.status(404).json({error:'Order not found'});const isOwner=o.buyer.id===req.user.id||hasRole(req.user.id,'admin')||canManageShop(req.user.id,o.shop.id);if(!isOwner)return res.status(403).json({error:'Forbidden'});res.json({order:o});});
app.put('/api/orders/:id/status',requireAuth,(req,res)=>{const id=Number(req.params.id);const o=orderDetails(id);if(!o)return res.status(404).json({error:'Order not found'});const allowedBuyer=o.buyer.id===req.user.id;const allowedOwner=canManageShop(req.user.id,o.shop.id);const allowedAdmin=hasRole(req.user.id,'admin');if(!allowedBuyer&&!allowedOwner&&!allowedAdmin)return res.status(403).json({error:'Forbidden'});const allowed=['pending','confirmed','preparing','ready','out_for_delivery','completed','cancelled'];if(!allowed.includes(req.body.status))return res.status(400).json({error:'Invalid order status'});if(allowedBuyer&&!allowedOwner&&!allowedAdmin&&!(req.body.status==='cancelled'&&o.orderStatus==='pending'))return res.status(403).json({error:'Buyers may only cancel a pending order'});db.prepare('UPDATE orders SET order_status=?,updated_at=? WHERE id=?').run(req.body.status,nowIso(),id);notify(o.buyer.id,'order_update','Order updated',`Order ${o.orderNumber} is now ${req.body.status}.`);res.json({order:orderDetails(id)});});

// ---------- Payments ----------
async function paymongoCheckout(order, method){
  if(!process.env.PAYMONGO_SECRET_KEY) throw new Error('PAYMONGO_SECRET_KEY is not configured');
  const allowed = method === 'GCASH' ? 'gcash' : 'paymaya';
  const body={data:{attributes:{billing:{name:order.buyer.name,email:order.buyer.email,phone:order.buyer.mobile},description:`ClickBites ${order.orderNumber}`,payment_method_types:[allowed],line_items:order.items.map(i=>({currency:'PHP',amount:i.unit_price_cents,quantity:i.quantity,name:i.product_name,description:i.product_name})),send_email_receipt:false,show_line_items:true,reference_number:order.orderNumber,success_url:`${process.env.APP_URL||`http://localhost:${port}`}/?payment_return=${order.id}&status=success`,cancel_url:`${process.env.APP_URL||`http://localhost:${port}`}/?payment_return=${order.id}&status=cancelled`}}};
  const auth=Buffer.from(`${process.env.PAYMONGO_SECRET_KEY}:`).toString('base64');
  const r=await fetch(`${process.env.PAYMONGO_BASE_URL||'https://api.paymongo.com'}/v1/checkout_sessions`,{method:'POST',headers:{Authorization:`Basic ${auth}`,'Content-Type':'application/json'},body:JSON.stringify(body)});const data=await r.json();if(!r.ok)throw new Error(data?.errors?.[0]?.detail||`PayMongo error ${r.status}`);return {providerId:data.data.id,checkoutUrl:data.data.attributes.checkout_url,reference:data.data.id};
}
async function mayaCheckout(order){
 if(!process.env.MAYA_PUBLIC_KEY)throw new Error('MAYA_PUBLIC_KEY is not configured');
 const body={totalAmount:{value:(order.totalCents/100).toFixed(2),currency:'PHP'},buyer:{firstName:order.buyer.name?.split(' ')[0]||'Customer',lastName:order.buyer.name?.split(' ').slice(1).join(' ')||'',contact:{phone:order.buyer.mobile,email:order.buyer.email}},items:order.items.map(i=>({name:i.product_name,quantity:i.quantity,amount:{value:(i.unit_price_cents/100).toFixed(2),currency:'PHP'}})),requestReferenceNumber:order.orderNumber,redirectUrl:{success:`${process.env.APP_URL||`http://localhost:${port}`}/?payment_return=${order.id}&status=success`,failure:`${process.env.APP_URL||`http://localhost:${port}`}/?payment_return=${order.id}&status=failed`,cancel:`${process.env.APP_URL||`http://localhost:${port}`}/?payment_return=${order.id}&status=cancelled`}};
 const auth=Buffer.from(`${process.env.MAYA_PUBLIC_KEY}:`).toString('base64'); const r=await fetch(`${process.env.MAYA_BASE_URL||'https://pg-sandbox.paymaya.com'}/checkout/v1/checkouts`,{method:'POST',headers:{Authorization:`Basic ${auth}`,'Content-Type':'application/json'},body:JSON.stringify(body)});const data=await r.json();if(!r.ok)throw new Error(data?.message||`Maya error ${r.status}`);return {providerId:data.checkoutId||data.id,checkoutUrl:data.redirectUrl,reference:data.checkoutId||data.id};
}
app.post('/api/payments/checkout',requireAuth,async(req,res,next)=>{try{const order=orderDetails(Number(req.body.orderId));if(!order||order.buyer.id!==req.user.id)return res.status(404).json({error:'Order not found'});if(order.paymentStatus==='paid')return res.status(400).json({error:'Order already paid'});const method=String(req.body.method||'').toUpperCase();if(!['GCASH','MAYA','PAYMAYA'].includes(method))return res.status(400).json({error:'Payment method must be GCASH or MAYA'});let result;if(method==='GCASH'||method==='PAYMAYA')result=await paymongoCheckout(order,method);else result=await mayaCheckout(order);const provider=method==='GCASH'||method==='PAYMAYA'?'paymongo':'maya';const payment=db.prepare(`INSERT INTO payments(order_id,provider,method,provider_payment_id,provider_reference,amount_cents,status,checkout_url) VALUES(?,?,?,?,?,?,?,?)`).run(order.id,provider,method,result.providerId,result.reference,order.totalCents,'pending',result.checkoutUrl);db.prepare('UPDATE orders SET payment_method=?,payment_status=\'pending\',updated_at=? WHERE id=?').run(method,nowIso(),order.id);res.json({paymentId:payment.lastInsertRowid,checkoutUrl:result.checkoutUrl});}catch(e){next(e);}});
app.post('/api/payments/:id/verify',requireAuth,async(req,res,next)=>{try{const payment=db.prepare('SELECT * FROM payments WHERE id=?').get(Number(req.params.id));if(!payment)return res.status(404).json({error:'Payment not found'});const order=orderDetails(payment.order_id);if(!order||(order.buyer.id!==req.user.id&&!hasRole(req.user.id,'admin')))return res.status(403).json({error:'Forbidden'});
 if(payment.provider==='paymongo'&&payment.provider_payment_id&&process.env.PAYMONGO_SECRET_KEY){const auth=Buffer.from(`${process.env.PAYMONGO_SECRET_KEY}:`).toString('base64');const r=await fetch(`${process.env.PAYMONGO_BASE_URL||'https://api.paymongo.com'}/v1/checkout_sessions/${payment.provider_payment_id}`,{headers:{Authorization:`Basic ${auth}`}});const d=await r.json();if(r.ok){const s=d?.data?.attributes?.payment_intent?.status||d?.data?.attributes?.status; if(String(s).toLowerCase()==='paid'||d?.data?.attributes?.status==='paid')updatePaymentStatus(payment.id,'paid',JSON.stringify(d),payment.provider_payment_id);}}
 if(payment.provider==='maya'&&payment.provider_payment_id&&process.env.MAYA_PUBLIC_KEY){const auth=Buffer.from(`${process.env.MAYA_PUBLIC_KEY}:`).toString('base64');const r=await fetch(`${process.env.MAYA_BASE_URL||'https://pg-sandbox.paymaya.com'}/payments/v1/payments/${payment.provider_payment_id}/status`,{headers:{Authorization:`Basic ${auth}`}});const d=await r.json();if(r.ok){const s=String(d?.paymentStatus||d?.status||'').toUpperCase();if(['PAYMENT_SUCCESS','COMPLETED','SUCCESS','PAID'].includes(s))updatePaymentStatus(payment.id,'paid',JSON.stringify(d),payment.provider_payment_id);else if(['PAYMENT_FAILED','PAYMENT_EXPIRED','PAYMENT_CANCELLED'].includes(s)){const mapped=s==='PAYMENT_EXPIRED'?'expired':s==='PAYMENT_CANCELLED'?'cancelled':'failed';updatePaymentStatus(payment.id,mapped,JSON.stringify(d),payment.provider_payment_id);}}}
 res.json({payment:db.prepare('SELECT id,provider,method,provider_payment_id,provider_reference,amount_cents,status,checkout_url,paid_at,refunded_at FROM payments WHERE id=?').get(payment.id),order:orderDetails(payment.order_id)});
}catch(e){next(e);}});
app.post('/api/payments/simulate/:id',requireAuth,(req,res)=>{if(process.env.NODE_ENV==='production')return res.status(404).end();const p=db.prepare('SELECT * FROM payments WHERE id=?').get(Number(req.params.id));if(!p)return res.status(404).json({error:'Payment not found'});const order=orderDetails(p.order_id);if(order.buyer.id!==req.user.id&&!hasRole(req.user.id,'admin'))return res.status(403).json({error:'Forbidden'});updatePaymentStatus(p.id,String(req.body.status||'paid'),JSON.stringify({simulated:true}),p.provider_payment_id||`SIM-${p.id}`);res.json({payment:db.prepare('SELECT * FROM payments WHERE id=?').get(p.id),order:orderDetails(p.order_id)});});

// Maya Checkout webhook. Configure this URL in Maya Manager after deploying over HTTPS.
app.post('/api/payments/webhooks/maya', express.json({ type: 'application/json' }), (req, res) => {
  try {
    const payload = req.body || {};
    const paymentId = payload.id || payload.paymentId || payload.payment_id;
    const paymentStatus = String(payload.paymentStatus || payload.status || '').toUpperCase();
    if (!paymentId || !paymentStatus) return res.status(400).json({ error: 'Invalid Maya webhook payload' });
    const payment = db.prepare('SELECT * FROM payments WHERE provider=? AND provider_payment_id=?').get('maya', paymentId);
    if (!payment) return res.status(202).json({ ok: true, ignored: true });
    const mapped = { PAYMENT_SUCCESS:'paid', PAYMENT_FAILED:'failed', PAYMENT_EXPIRED:'expired', PAYMENT_CANCELLED:'cancelled' }[paymentStatus];
    if (mapped) updatePaymentStatus(payment.id, mapped, JSON.stringify(payload), paymentId);
    return res.json({ ok: true });
  } catch (error) {
    console.error('Maya webhook error:', error);
    return res.status(400).json({ error: 'Invalid webhook' });
  }
});

// ---------- Notifications ----------
app.get('/api/notifications',requireAuth,(req,res)=>res.json({notifications:db.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 100').all(req.user.id)}));
app.post('/api/notifications/:id/read',requireAuth,(req,res)=>{db.prepare('UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?').run(Number(req.params.id),req.user.id);res.json({ok:true});});

// ---------- Admin ----------
app.get('/api/admin/dashboard',requireAuth,requireRole('admin'),(req,res)=>{
 const q=(sql,...params)=>db.prepare(sql).get(...params)?.count||0;
 const sum=(sql,...params)=>db.prepare(sql).get(...params)?.value||0;
 const stats={
  totalUsers:q('SELECT COUNT(*) count FROM users'),activeUsers:q("SELECT COUNT(*) count FROM users WHERE status='active'"),newUsers:q("SELECT COUNT(*) count FROM users WHERE created_at>=datetime('now','-30 day')"),
  totalShops:q('SELECT COUNT(*) count FROM shops'),pendingShops:q("SELECT COUNT(*) count FROM shops WHERE status='Pending'"),approvedShops:q("SELECT COUNT(*) count FROM shops WHERE status='Approved'"),disapprovedShops:q("SELECT COUNT(*) count FROM shops WHERE status='Disapproved'"),suspendedShops:q("SELECT COUNT(*) count FROM shops WHERE status='Suspended'"),
  totalMenuItems:q('SELECT COUNT(*) count FROM products'),availableItems:q("SELECT COUNT(*) count FROM products WHERE status='available'"),soldOutItems:q("SELECT COUNT(*) count FROM products WHERE status='sold_out'"),totalOrders:q('SELECT COUNT(*) count FROM orders'),pendingOrders:q("SELECT COUNT(*) count FROM orders WHERE order_status IN ('pending','confirmed','preparing','ready','out_for_delivery')"),completedOrders:q("SELECT COUNT(*) count FROM orders WHERE order_status='completed'"),cancelledOrders:q("SELECT COUNT(*) count FROM orders WHERE order_status='cancelled'"),successfulPayments:q("SELECT COUNT(*) count FROM payments WHERE status='paid'"),failedPayments:q("SELECT COUNT(*) count FROM payments WHERE status='failed'"),refundedPayments:q("SELECT COUNT(*) count FROM payments WHERE status='refunded'"),
  grossSales:sum("SELECT COALESCE(SUM(total_cents),0) value FROM orders WHERE payment_status='paid' AND order_status!='cancelled'"),shopEarnings:sum("SELECT COALESCE(SUM(subtotal_cents-platform_fee_cents),0) value FROM orders WHERE payment_status='paid' AND order_status!='cancelled'"),platformRevenue:sum("SELECT COALESCE(SUM(platform_fee_cents),0) value FROM orders WHERE payment_status='paid' AND order_status!='cancelled'"),refunds:sum("SELECT COALESCE(SUM(total_cents),0) value FROM orders WHERE payment_status='refunded'"),netRevenue:sum("SELECT COALESCE(SUM(total_cents),0) value FROM orders WHERE payment_status='paid' AND order_status!='cancelled'")-sum("SELECT COALESCE(SUM(total_cents),0) value FROM orders WHERE payment_status='refunded'")
 };
 ['grossSales','shopEarnings','platformRevenue','refunds','netRevenue'].forEach(k=>stats[k]=price(stats[k])); res.json({stats});
});
app.get('/api/admin/users',requireAuth,requireRole('admin'),(req,res)=>{const q=String(req.query.q||'').toLowerCase();const page=Math.max(1,Number(req.query.page||1)),limit=Math.min(100,Math.max(1,Number(req.query.limit||25))),offset=(page-1)*limit;const params=[];let where='';if(q){where='WHERE LOWER(COALESCE(u.email,\'\')) LIKE ? OR LOWER(COALESCE(u.mobile,\'\')) LIKE ? OR LOWER(COALESCE(up.full_name,\'\')) LIKE ?';const like=`%${q}%`;params.push(like,like,like);}const total=db.prepare(`SELECT COUNT(*) count FROM users u LEFT JOIN user_profiles up ON up.user_id=u.id ${where}`).get(...params).count;const rows=db.prepare(`SELECT u.id,u.email,u.mobile,u.status,u.created_at,up.full_name FROM users u LEFT JOIN user_profiles up ON up.user_id=u.id ${where} ORDER BY u.created_at DESC LIMIT ? OFFSET ?`).all(...params,limit,offset);res.json({users:rows,page,limit,total,pages:Math.ceil(total/limit)});});
app.get('/api/admin/shops',requireAuth,requireRole('admin'),(req,res)=>{const status=String(req.query.status||'');const q=String(req.query.q||'').toLowerCase();const page=Math.max(1,Number(req.query.page||1)),limit=Math.min(100,Math.max(1,Number(req.query.limit||25))),offset=(page-1)*limit;const params=[];const clauses=[];if(status){clauses.push('s.status=?');params.push(status);}if(q){clauses.push('(LOWER(s.name) LIKE ? OR LOWER(COALESCE(up.full_name,\'\')) LIKE ? OR LOWER(COALESCE(u.email,\'\')) LIKE ? OR LOWER(COALESCE(u.mobile,\'\')) LIKE ?)');const like=`%${q}%`;params.push(like,like,like,like);}const where=clauses.length?`WHERE ${clauses.join(' AND ')}`:'';const total=db.prepare(`SELECT COUNT(*) count FROM shops s JOIN users u ON u.id=s.owner_user_id LEFT JOIN user_profiles up ON up.user_id=u.id ${where}`).get(...params).count;const shops=db.prepare(`SELECT s.*,u.email owner_email,u.mobile owner_mobile,up.full_name owner_name FROM shops s JOIN users u ON u.id=s.owner_user_id LEFT JOIN user_profiles up ON up.user_id=u.id ${where} ORDER BY s.created_at DESC LIMIT ? OFFSET ?`).all(...params,limit,offset);res.json({shops,page,limit,total,pages:Math.ceil(total/limit)});});
app.put('/api/admin/shops/:id/status',requireAuth,requireRole('admin'),(req,res)=>{const id=Number(req.params.id);const s=db.prepare('SELECT * FROM shops WHERE id=?').get(id);if(!s)return res.status(404).json({error:'Shop not found'});const status=String(req.body.status||'');if(!['Pending','Approved','Disapproved','Suspended','Disabled'].includes(status))return res.status(400).json({error:'Invalid shop status'});db.prepare('UPDATE shops SET status=?,disapproval_reason=?,approved_by=?,approved_at=?,updated_at=? WHERE id=?').run(status,status==='Disapproved'?(req.body.reason||null):null,status==='Approved'?req.user.id:null,status==='Approved'?nowIso():null,nowIso(),id);audit(req.user.id,`shop_${status.toLowerCase()}`,'shop',id,s.owner_user_id,{reason:req.body.reason||null});notify(s.owner_user_id,'shop_status','Shop status updated',`Your shop is now ${status}.${req.body.reason?` Reason: ${req.body.reason}`:''}`);res.json({shop:serializeShop(db.prepare('SELECT * FROM shops WHERE id=?').get(id))});});
app.post('/api/admin/shops',requireAuth,requireRole('admin'),(req,res,next)=>{try{let user;const identifier=String(req.body.identifier||'').trim();const explicitId=req.body.userId?Number(req.body.userId):null;const identifierId=/^\d+$/.test(identifier)?Number(identifier):null;const id=Number.isInteger(explicitId)&&explicitId>0?explicitId:(Number.isInteger(identifierId)&&identifierId>0?identifierId:null);if(id)user=db.prepare('SELECT * FROM users WHERE id=?').get(id);else user=db.prepare('SELECT * FROM users WHERE email=? OR mobile=?').get(normalizeEmail(identifier),normalizeMobile(identifier));if(!user)return res.status(404).json({error:'Existing user account not found'});const x=req.body;const r=db.prepare(`INSERT INTO shops(owner_user_id,name,description,category_id,location,contact_number,contact_email,external_url,operating_hours,status,created_by_admin_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(user.id,x.name,x.description||null,x.categoryId?Number(x.categoryId):null,x.location||null,x.contactNumber||user.mobile||null,normalizeEmail(x.contactEmail)||user.email||null,x.externalUrl||null,x.operatingHours||null,x.status||'Pending',req.user.id);const shopId=Number(r.lastInsertRowid);if((x.status||'Pending')==='Approved'){db.prepare('UPDATE shops SET approved_by=?,approved_at=? WHERE id=?').run(req.user.id,nowIso(),shopId);}db.prepare('INSERT INTO shop_owners(shop_id,user_id,is_primary) VALUES(?,?,1)').run(shopId,user.id);grantRole(user.id,'shop_owner');audit(req.user.id,'admin_created_shop','shop',shopId,user.id,{createdByAdmin:req.user.id});notify(user.id,'shop_created_by_admin','Shop created',`An administrator created the shop “${x.name}” for your account.`);res.status(201).json({shop:serializeShop(db.prepare('SELECT * FROM shops WHERE id=?').get(shopId))});}catch(e){next(e);}});
app.get('/api/admin/products',requireAuth,requireRole('admin'),(req,res)=>{const q=String(req.query.q||'').toLowerCase();const status=String(req.query.status||'');const page=Math.max(1,Number(req.query.page||1)),limit=Math.min(100,Math.max(1,Number(req.query.limit||25))),offset=(page-1)*limit;const params=[];const c=[];if(q){c.push('(LOWER(p.name) LIKE ? OR LOWER(s.name) LIKE ? OR LOWER(COALESCE(up.full_name,\'\')) LIKE ?)');const like=`%${q}%`;params.push(like,like,like);}if(status){c.push('p.status=?');params.push(status);}const where=c.length?`WHERE ${c.join(' AND ')}`:'';const total=db.prepare(`SELECT COUNT(*) count FROM products p JOIN shops s ON s.id=p.shop_id JOIN users u ON u.id=s.owner_user_id LEFT JOIN user_profiles up ON up.user_id=u.id ${where}`).get(...params).count;const rows=db.prepare(`SELECT p.id,p.name,p.price_cents,p.stock,p.status,p.created_at,s.name shop_name,up.full_name owner_name,c.name category FROM products p JOIN shops s ON s.id=p.shop_id JOIN users u ON u.id=s.owner_user_id LEFT JOIN user_profiles up ON up.user_id=u.id LEFT JOIN categories c ON c.id=p.category_id ${where} ORDER BY p.created_at DESC LIMIT ? OFFSET ?`).all(...params,limit,offset);res.json({products:rows,page,limit,total,pages:Math.ceil(total/limit)});});
app.get('/api/admin/orders',requireAuth,requireRole('admin'),(req,res)=>{const status=String(req.query.status||'');const paymentMethod=String(req.query.paymentMethod||'');const shopId=req.query.shopId?Number(req.query.shopId):null;const from=req.query.from?String(req.query.from):null;const to=req.query.to?String(req.query.to):null;const page=Math.max(1,Number(req.query.page||1)),limit=Math.min(100,Math.max(1,Number(req.query.limit||25))),offset=(page-1)*limit;const params=[];const c=[];if(status){c.push('o.order_status=?');params.push(status);}if(paymentMethod){c.push('o.payment_method=?');params.push(paymentMethod);}if(shopId){c.push('o.shop_id=?');params.push(shopId);}if(from){c.push('date(o.created_at)>=date(?)');params.push(from);}if(to){c.push('date(o.created_at)<=date(?)');params.push(to);}const where=c.length?`WHERE ${c.join(' AND ')}`:'';const total=db.prepare(`SELECT COUNT(*) count FROM orders o ${where}`).get(...params).count;const rows=db.prepare(`SELECT o.id,o.order_number,o.total_cents,o.payment_method,o.payment_status,o.order_status,o.created_at,s.name shop_name,up.full_name buyer_name,ou.email buyer_email,oup.full_name shop_owner_name FROM orders o JOIN shops s ON s.id=o.shop_id JOIN users ou ON ou.id=o.buyer_user_id LEFT JOIN user_profiles up ON up.user_id=ou.id JOIN users su ON su.id=s.owner_user_id LEFT JOIN user_profiles oup ON oup.user_id=su.id ${where} ORDER BY o.created_at DESC LIMIT ? OFFSET ?`).all(...params,limit,offset);res.json({orders:rows,page,limit,total,pages:Math.ceil(total/limit)});});
app.get('/api/admin/payments',requireAuth,requireRole('admin'),(req,res)=>{const status=String(req.query.status||'');const method=String(req.query.method||'');const params=[];const c=[];if(status){c.push('p.status=?');params.push(status);}if(method){c.push('p.method=?');params.push(method);}const where=c.length?`WHERE ${c.join(' AND ')}`:'';const rows=db.prepare(`SELECT p.id,p.order_id,p.provider,p.method,p.amount_cents,p.provider_payment_id,p.provider_reference,p.status,p.paid_at,p.refunded_at,p.created_at,o.order_number,s.name shop_name,up.full_name buyer_name FROM payments p JOIN orders o ON o.id=p.order_id JOIN shops s ON s.id=o.shop_id JOIN users u ON u.id=o.buyer_user_id LEFT JOIN user_profiles up ON up.user_id=u.id ${where} ORDER BY p.created_at DESC LIMIT 500`).all(...params);res.json({payments:rows});});
app.get('/api/admin/revenue',requireAuth,requireRole('admin'),(req,res)=>{const from=String(req.query.from||new Date().toISOString().slice(0,10));const to=String(req.query.to||from);const rows=db.prepare(`SELECT COALESCE(SUM(o.total_cents),0) gross_sales, COALESCE(SUM(o.subtotal_cents-o.platform_fee_cents),0) shop_earnings, COALESCE(SUM(o.platform_fee_cents),0) platform_revenue, COALESCE(SUM(CASE WHEN o.payment_status='refunded' THEN o.total_cents ELSE 0 END),0) refunds, COALESCE(SUM(CASE WHEN o.payment_status='paid' AND o.order_status!='cancelled' THEN o.total_cents ELSE 0 END),0)-COALESCE(SUM(CASE WHEN o.payment_status='refunded' THEN o.total_cents ELSE 0 END),0) net_revenue FROM orders o WHERE date(o.created_at) BETWEEN date(?) AND date(?)`).get(from,to);const top=db.prepare(`SELECT s.id,s.name,COUNT(CASE WHEN o.payment_status='paid' THEN 1 END) total_orders,COALESCE(SUM(CASE WHEN o.payment_status='paid' THEN o.total_cents ELSE 0 END),0) gross_sales,COALESCE(SUM(CASE WHEN o.payment_status='paid' THEN o.subtotal_cents-o.platform_fee_cents ELSE 0 END),0) shop_earnings,COALESCE(SUM(CASE WHEN o.payment_status='paid' THEN o.platform_fee_cents ELSE 0 END),0) platform_commission FROM shops s LEFT JOIN orders o ON o.shop_id=s.id AND date(o.created_at) BETWEEN date(?) AND date(?) GROUP BY s.id ORDER BY gross_sales DESC LIMIT 50`).all(from,to);res.json({period:{from,to},summary:{grossSales:price(rows.gross_sales),shopEarnings:price(rows.shop_earnings),platformRevenue:price(rows.platform_revenue),refunds:price(rows.refunds),netRevenue:price(rows.net_revenue)},topShops:top.map(x=>({...x,grossSales:price(x.gross_sales),shopEarnings:price(x.shop_earnings),platformCommission:price(x.platform_commission)}))});});
app.get('/api/admin/audit-logs',requireAuth,requireRole('admin'),(req,res)=>res.json({logs:db.prepare('SELECT * FROM admin_audit_logs ORDER BY created_at DESC LIMIT 500').all()}));

app.get('/api/admin/security/risk-events',requireAuth,requireRole('admin'),(req,res)=>res.json({events:db.prepare(`SELECT r.*,u.email,u.mobile,up.full_name FROM risk_events r LEFT JOIN users u ON u.id=r.user_id LEFT JOIN user_profiles up ON up.user_id=r.user_id ORDER BY r.created_at DESC LIMIT 500`).all()}));

// ---------- Health ----------
app.get('/api/health',(req,res)=>res.json({ok:true,service:'clickbites',time:nowIso(),db:db.isOpen?'sqlite':'unknown'}));

app.use('/api', (req,res)=>res.status(404).json({error:'API route not found'}));
app.use((err,req,res,next)=>{
  console.error(err);
  if(res.headersSent)return next(err);
  if(String(err?.message||'').startsWith('Origin not allowed')){
    return res.status(403).json({error:'This browser origin is not allowed by the ClickBites API. Use the Vite localhost URL or add the frontend URL to CORS_ORIGINS.'});
  }
  const status=Number(err?.statusCode)||500;
  res.status(status).json({error:process.env.NODE_ENV==='production' && status===500?'Internal server error':(err?.message||'Request failed')});
});

// SPA fallback. API routes are already handled above.
app.get('/{*splat}', (req,res,next)=>{if(req.path.startsWith('/api/'))return next();res.sendFile(path.join(publicDir,'index.html'));});

function seedDevAdmin(){
  const email=normalizeEmail(process.env.ADMIN_EMAIL), password=process.env.ADMIN_PASSWORD;
  if(!email||!password)return;
  let user=db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if(!user){const r=db.prepare('INSERT INTO users(email,mobile,password_hash) VALUES(?,?,?)').run(email,null,bcrypt.hashSync(password,12));user=db.prepare('SELECT * FROM users WHERE id=?').get(r.lastInsertRowid);db.prepare('INSERT INTO user_profiles(user_id,full_name,email_verified,phone_verified) VALUES(?,?,1,0)').run(user.id,'ClickBites Administrator');db.prepare('INSERT INTO carts(user_id) VALUES(?)').run(user.id);grantRole(user.id,'user');}
  grantRole(user.id,'admin');
}
seedDevAdmin();

app.listen(port, ()=>console.log(`ClickBites server running at http://localhost:${port}`));
