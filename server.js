'use strict';
/**
 * שרת API לפורטל התלמידים — Node.js + Express + MongoDB
 * אחראי על: הרשמה, אימות קוד במייל, התחברות, איפוס סיסמה ושמירת נתוני משתמש.
 * הדפדפן לעולם לא מדבר ישירות עם MongoDB, רק עם השרת הזה.
 */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

/* ---------------- הגדרות (מתוך .env) ---------------- */
const env = process.env;
const PROD = env.NODE_ENV === 'production';
const PORT = +env.PORT || 3000;
const MONGODB_URI = env.MONGODB_URI || 'mongodb://127.0.0.1:27017';
const DB_NAME = env.DB_NAME || 'student_portal';
const ALLOWED_DOMAIN = (env.ALLOWED_DOMAIN || 'manhischools.org.il').toLowerCase();
const CORS_ORIGIN = (env.CORS_ORIGIN || '*').split(',').map((s) => s.trim()).filter(Boolean);
const CODE_TTL_MS = 10 * 60 * 1000;
const RESEND_COOLDOWN_MS = 60 * 1000;
const MAX_CODE_ATTEMPTS = 5;
const MAX_KEYS_PER_USER = 300;

let JWT_SECRET = env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  if (PROD) { console.error('חובה להגדיר JWT_SECRET באורך 32 תווים לפחות ב-.env'); process.exit(1); }
  JWT_SECRET = crypto.randomBytes(32).toString('hex');
  console.warn('[אזהרה] JWT_SECRET לא הוגדר. נוצר מפתח זמני (כניסות יימחקו בכל הפעלה).');
}

const emailRe = new RegExp('^[^@\\s]+@' + ALLOWED_DOMAIN.replace(/\./g, '\\.') + '$', 'i');
const normEmail = (e) => String(e == null ? '' : e).trim().toLowerCase();
const okEmail = (e) => e.length <= 254 && emailRe.test(e);
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const makeCode = () => String(crypto.randomInt(0, 1000000)).padStart(6, '0');
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 10);

class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }

/* ---------------- מייל ---------------- */
const transporter = env.SMTP_HOST
  ? nodemailer.createTransport({
      host: env.SMTP_HOST, port: +env.SMTP_PORT || 587, secure: +env.SMTP_PORT === 465,
      auth: env.SMTP_USER ? { user: env.SMTP_USER, pass: env.SMTP_PASS } : undefined
    })
  : null;
const devReturnCode = env.DEV_RETURN_CODE === 'true' && !PROD;

async function sendCode(email, code, purpose) {
  const subject = purpose === 'signup' ? 'קוד אימות לפורטל התלמידים' : 'קוד לאיפוס סיסמה בפורטל התלמידים';
  if (!transporter) { console.log(`[DEV] ${purpose} code for ${email}: ${code}`); return; }
  await transporter.sendMail({
    from: env.SMTP_FROM || env.SMTP_USER, to: email, subject,
    text: `קוד האימות שלך: ${code}\nהקוד תקף ל-10 דקות. אם לא ביקשת אותו, אפשר להתעלם מההודעה.`,
    html: `<div dir="rtl" style="font-family:Arial,sans-serif"><p>קוד האימות שלך:</p><p style="font-size:28px;letter-spacing:6px"><b>${code}</b></p><p>הקוד תקף ל-10 דקות. אם לא ביקשת אותו, אפשר להתעלם מההודעה.</p></div>`
  });
}

/* ---------------- MongoDB ---------------- */
let client, users, codes, userData;
async function initDb() {
  client = new MongoClient(MONGODB_URI);
  await client.connect();
  const db = client.db(DB_NAME);
  users = db.collection('users');
  codes = db.collection('codes');
  userData = db.collection('user_data');
  await users.createIndex({ email: 1 }, { unique: true });
  await codes.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  await codes.createIndex({ email: 1, purpose: 1 }, { unique: true });
  await userData.createIndex({ userId: 1, key: 1 }, { unique: true });
}

async function issueCode(email, purpose) {
  const prev = await codes.findOne({ email, purpose });
  if (prev && prev.sentAt && Date.now() - new Date(prev.sentAt).getTime() < RESEND_COOLDOWN_MS)
    throw new HttpError(429, 'אפשר לבקש קוד חדש רק אחרי דקה');
  const code = makeCode(), now = Date.now();
  await codes.updateOne({ email, purpose },
    { $set: { codeHash: sha(code), expiresAt: new Date(now + CODE_TTL_MS), attempts: 0, sentAt: new Date(now) } },
    { upsert: true });
  await sendCode(email, code, purpose);
  return code;
}
async function checkCode(email, purpose, code) {
  const bad = new HttpError(400, 'הקוד שגוי או שפג תוקפו');
  const doc = await codes.findOne({ email, purpose });
  if (!doc || new Date(doc.expiresAt).getTime() < Date.now()) throw bad;
  if ((doc.attempts || 0) >= MAX_CODE_ATTEMPTS) { await codes.deleteOne({ email, purpose }); throw bad; }
  const a = Buffer.from(sha(code)), b = Buffer.from(doc.codeHash);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    await codes.updateOne({ email, purpose }, { $inc: { attempts: 1 } });
    throw bad;
  }
  await codes.deleteOne({ email, purpose });
}

/* ---------------- Express ---------------- */
const app = express();
if (env.TRUST_PROXY) app.set('trust proxy', env.TRUST_PROXY === 'true' ? 1 : env.TRUST_PROXY);
app.use(helmet());
app.use(cors({
  origin: (origin, cb) => cb(null, !origin || CORS_ORIGIN.includes('*') || CORS_ORIGIN.includes(origin)),
  methods: ['GET', 'POST', 'PUT', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => { if (req.body === undefined || req.body === null || typeof req.body !== 'object') req.body = {}; next(); });
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, limit: 600, standardHeaders: true, legacyHeaders: false }));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 40, standardHeaders: true, legacyHeaders: false, message: { error: 'יותר מדי ניסיונות. נסו שוב בעוד כמה דקות.' } });

const wrap = (fn) => (req, res) => fn(req, res).catch((e) => {
  if (e instanceof HttpError) return res.status(e.status).json({ error: e.message });
  console.error(e); res.status(500).json({ error: 'שגיאת שרת' });
});
const signAccess = (u) => jwt.sign({ sub: String(u._id), email: u.email, typ: 'access' }, JWT_SECRET, { expiresIn: '7d' });
const publicUser = (u) => ({ id: String(u._id), email: u.email });
function requireToken(typ) {
  return (req, res, next) => {
    const h = req.headers.authorization || '';
    try {
      const p = jwt.verify(h.startsWith('Bearer ') ? h.slice(7) : '', JWT_SECRET);
      if (p.typ !== typ) throw new Error('typ');
      req.auth = p; next();
    } catch (e) { res.status(401).json({ error: 'נדרשת התחברות מחדש' }); }
  };
}
const extra = (code) => (devReturnCode ? { devCode: code } : {});

app.get('/', (req, res) => { res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-src https:; connect-src 'self';"); res.sendFile(require('path').join(__dirname, 'index.html')); }); app.get('/api/health', (req, res) => res.json({ ok: true }));

app.post('/api/signup', authLimiter, wrap(async (req, res) => {
  const email = normEmail(req.body.email), pw = typeof req.body.password === 'string' ? req.body.password : '';
  if (!okEmail(email)) throw new HttpError(400, 'אפשר להירשם רק עם מייל לימודי שמסתיים ב-@' + ALLOWED_DOMAIN);
  if (pw.length < 8 || pw.length > 200) throw new HttpError(400, 'הסיסמה חייבת להכיל לפחות 8 תווים');
  const ex = await users.findOne({ email });
  if (ex && ex.verified) throw new HttpError(409, 'כתובת המייל כבר רשומה. עברו להתחברות.');
  const passHash = await bcrypt.hash(pw, 12);
  await users.updateOne({ email }, { $set: { passHash,  }, $setOnInsert: { createdAt: new Date() } }, { upsert: true });
  const code = await issueCode(email, 'signup');
  res.json({ needsCode: true, ...extra(code) });
}));

app.post('/api/resend', authLimiter, wrap(async (req, res) => {
  const email = normEmail(req.body.email), purpose = req.body.purpose === 'recovery' ? 'recovery' : 'signup';
  if (!okEmail(email)) throw new HttpError(400, 'כתובת לא תקינה');
  const u = await users.findOne({ email });
  let code;
  if (u && ((purpose === 'signup' && !u.verified) || (purpose === 'recovery' && u.verified))) code = await issueCode(email, purpose);
  res.json({ ok: true, ...(code ? extra(code) : {}) });
}));

app.post('/api/verify', authLimiter, wrap(async (req, res) => {
  const email = normEmail(req.body.email), purpose = req.body.purpose === 'recovery' ? 'recovery' : 'signup';
  const code = String(req.body.code == null ? '' : req.body.code).trim();
  if (!okEmail(email) || !/^\d{6}$/.test(code)) throw new HttpError(400, 'הקוד שגוי או שפג תוקפו');
  await checkCode(email, purpose, code);
  const u = await users.findOne({ email });
  if (!u) throw new HttpError(400, 'הקוד שגוי או שפג תוקפו');
  if (purpose === 'signup') {
    await users.updateOne({ email }, { $set: { verified: true } });
    return res.json({ token: signAccess(u), user: publicUser(u) });
  }
  if (!u.verified) throw new HttpError(400, 'הקוד שגוי או שפג תוקפו');
  res.json({ resetToken: jwt.sign({ sub: String(u._id), email, typ: 'reset' }, JWT_SECRET, { expiresIn: '10m' }) });
}));

app.post('/api/login', authLimiter, wrap(async (req, res) => {
  const email = normEmail(req.body.email), pw = typeof req.body.password === 'string' ? req.body.password : '';
  const u = okEmail(email) ? await users.findOne({ email }) : null;
  const good = await bcrypt.compare(pw, u ? u.passHash : DUMMY_HASH);
  if (!u || !good) throw new HttpError(401, 'אימייל או סיסמה שגויים');
  if (!u.verified) throw new HttpError(403, 'יש לאמת את כתובת המייל לפני הכניסה');
  res.json({ token: signAccess(u), user: publicUser(u) });
}));

app.post('/api/forgot', authLimiter, wrap(async (req, res) => {
  const email = normEmail(req.body.email);
  let code;
  if (okEmail(email)) {
    const u = await users.findOne({ email });
    if (u && u.verified) { try { code = await issueCode(email, 'recovery'); } catch (e) { if (!(e instanceof HttpError)) throw e; } }
  }
  res.json({ needsCode: true, ...(code ? extra(code) : {}) });
}));

app.post('/api/reset', authLimiter, requireToken('reset'), wrap(async (req, res) => {
  const pw = typeof req.body.password === 'string' ? req.body.password : '';
  if (pw.length < 8 || pw.length > 200) throw new HttpError(400, 'הסיסמה חייבת להכיל לפחות 8 תווים');
  await users.updateOne({ email: req.auth.email }, { $set: { passHash: await bcrypt.hash(pw, 12) } });
  res.json({ ok: true });
}));

app.get('/api/me', requireToken('access'), wrap(async (req, res) => {
  const u = await users.findOne({ email: req.auth.email });
  if (!u || !u.verified) throw new HttpError(401, 'נדרשת התחברות מחדש');
  res.json({ user: publicUser(u) });
}));

app.get('/api/data', requireToken('access'), wrap(async (req, res) => {
  const rows = await userData.find({ userId: req.auth.sub }).toArray(), out = {};
  rows.forEach((r) => { out[r.key] = r.value; });
  res.json({ data: out });
}));

app.put('/api/data/:key', requireToken('access'), wrap(async (req, res) => {
  const key = req.params.key;
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(key)) throw new HttpError(400, 'מפתח לא תקין');
  if (!req.body || !Object.prototype.hasOwnProperty.call(req.body, 'value')) throw new HttpError(400, 'חסר value');
  const exists = await userData.findOne({ userId: req.auth.sub, key });
  if (!exists && (await userData.countDocuments({ userId: req.auth.sub })) >= MAX_KEYS_PER_USER) throw new HttpError(413, 'הגעתם למגבלת הנתונים');
  await userData.updateOne({ userId: req.auth.sub, key }, { $set: { value: req.body.value, updatedAt: new Date() } }, { upsert: true });
  res.json({ ok: true });
}));

app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'הנתונים גדולים מדי' });
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'בקשה לא תקינה' });
  console.error(err); res.status(500).json({ error: 'שגיאת שרת' });
});

async function start() {
  await initDb();
  return app.listen(PORT, () => console.log(`API מוכן על http://localhost:${PORT} (דומיין מותר: @${ALLOWED_DOMAIN})`));
}
if (require.main === module) start().catch((e) => { console.error('הפעלה נכשלה:', e.message); process.exit(1); });
module.exports = { app, start, initDb };
