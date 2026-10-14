/**
 * Keyy's Haven — functions/data.js
 * Shared data + security layer for every Function module.
 * Pure standard runtime APIs (Web Crypto, Request/Response) — no npm packages.
 * All database access targets the native `env.DB` Cloudflare D1 binding.
 */

export const SESSION_COOKIE = 'haven_session';
export const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days
export const USERNAME_RE = /^[A-Za-z0-9_]{3,24}$/;
export const RESERVED_USERNAMES = new Set(['keyy', 'platform', 'admin', 'system', 'root', 'keyyhaven', 'official', 'moderator', 'support']);
export const REACTIONS = ['👍', '❤️', '🔥', '😂', '😮'];

/** Admin-tracked comment patterns — matched comments are flagged for the ledger. */
export const FLAG_PATTERNS = [
  { id: 'external_link', re: /https?:\/\/|www\.|\.com\b|\.xyz\b/i, reason: 'external link' },
  { id: 'scam_terms', re: /\b(free\s+(crypto|nitro|robux|skins)|giveaway|airdrop)\b/i, reason: 'spam / scam terms' },
  { id: 'exploit_terms', re: /\b(hack|exploit|ddos|steal|phish)\w*\b/i, reason: 'suspicious language' },
];

export const json = (data, status = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extraHeaders },
  });

/** Cryptographically random opaque token (base64url). */
export const randomToken = (bytes = 32) => b64urlEncode(crypto.getRandomValues(new Uint8Array(bytes)));

export const clientIp = (request) => request.headers.get('cf-connecting-ip') || 'unknown';

/* ── lightweight D1 rate limiting (counts failures only) ───── */
export async function rateAllowed(env, key, max) {
  const row = await env.DB.prepare('SELECT count, reset_at FROM rate_limits WHERE key = ?1').bind(key).first();
  return !(row && Number(row.reset_at) > Date.now() && Number(row.count) >= max);
}
export async function rateHit(env, key, windowSec) {
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO rate_limits (key, count, reset_at) VALUES (?1, 1, ?2)
     ON CONFLICT(key) DO UPDATE SET
       count = CASE WHEN reset_at <= ?3 THEN 1 ELSE count + 1 END,
       reset_at = CASE WHEN reset_at <= ?3 THEN ?2 ELSE reset_at END`
  ).bind(key, now + windowSec * 1000, now).run();
}

export const nowIso = () => new Date().toISOString();
export const uuid = () => crypto.randomUUID();

/* ── base64url helpers ─────────────────────────────────────── */
export function b64urlEncode(buffer) {
  const bytes = new Uint8Array(buffer);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function b64urlDecode(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (str.length % 4)) % 4);
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/* ── hashing: PBKDF2-SHA256 (passwords, secret answers, 6-digit PINs) ── */
export async function hashSecret(value, iterations = 100000) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$${iterations}$${b64urlEncode(salt)}$${await pbkdf2(value, salt, iterations)}`;
}
export async function verifySecret(value, stored) {
  try {
    const [scheme, iterStr, saltB64, hashB64] = String(stored).split('$');
    if (scheme !== 'pbkdf2') return false;
    const hash = await pbkdf2(value, b64urlDecode(saltB64), Number(iterStr));
    return constantTimeEqual(hash, hashB64);
  } catch {
    return false;
  }
}
async function pbkdf2(value, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(value), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
  return b64urlEncode(bits);
}
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/* ── sessions (HttpOnly cookie ↔ opaque token) ─────────────── */
export async function createSession(env, userId) {
  const token = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
  const expires = new Date(Date.now() + SESSION_TTL_SECONDS * 1000).toISOString();
  await env.DB.prepare('INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)')
    .bind(token, userId, expires, nowIso()).run();
  return token;
}
export function sessionCookie(token, isHttps = true) {
  const secure = isHttps ? '; Secure' : '';
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Max-Age=${SESSION_TTL_SECONDS}; SameSite=Lax${secure}`;
}

export function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax`;
}

export function readCookie(request, name) {
  const raw = request.headers.get('cookie') || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

/** Resolve the signed-in user row from the session cookie (or null). */
export async function getSessionUser(request, env) {
  const token = readCookie(request, SESSION_COOKIE);
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = ?1 AND s.expires_at > ?2`
  ).bind(token, nowIso()).first();
  return row || null;
}

export async function destroySession(request, env) {
  const token = readCookie(request, SESSION_COOKIE);
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token = ?1').bind(token).run();
}

/* ── admin authorization (server-side gate for every admin action) ── */
export async function requireAdmin(request, env, body) {
  const rlKey = `admin:${clientIp(request)}`;
  const provided = String(body?.admin_key || request.headers.get('x-admin-key') || '').trim();
  const master = String(env.ADMIN_KEY || '').trim();

  // Block repeated failures (best effort — a missing table must never lock the owner out)
  let allowed = true;
  try { allowed = await rateAllowed(env, rlKey, 10); } catch { allowed = true; }
  if (!allowed) return { ok: false, status: 429, error: 'Too many failed attempts. Try again in a few minutes.' };

  if (master && provided && constantTimeEqual(provided, master)) return { ok: true, via: 'master_key' };
  // Fallback: a signed-in session belonging to the owner account.
  try {
    const user = await getSessionUser(request, env);
    if (user && user.username_lower === 'keyy') return { ok: true, via: 'owner_session' };
  } catch { /* DB not ready — fall through to the failure below */ }
  try { await rateHit(env, rlKey, 15 * 60); } catch { /* ignore */ }
  return { ok: false, status: 403, error: !master ? 'ADMIN_KEY secret is not configured on this deployment.' : 'Forbidden — admin authorization required.' };
}

/* ── settings ──────────────────────────────────────────────── */
export async function getSetting(env, key, fallback = null) {
  const row = await env.DB.prepare('SELECT value FROM site_settings WHERE key = ?1').bind(key).first();
  return row ? row.value : fallback;
}
export async function setSetting(env, key, value) {
  await env.DB.prepare('INSERT INTO site_settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .bind(key, String(value)).run();
}

/* ── validation & flagging ─────────────────────────────────── */
export function validateRegistration({ username, password, secret_question, secret_answer, pin }) {
  if (!USERNAME_RE.test(username || '')) return 'Username must be 3–24 characters (letters, numbers, underscore).';
  if (RESERVED_USERNAMES.has(String(username).toLowerCase())) return 'That username is reserved. Please choose another.';
  if (!password || password.length < 8 || password.length > 128) return 'Password must be 8–128 characters.';
  if (!secret_question || secret_question.length > 200) return 'Please provide a secret question.';
  if (!secret_answer || secret_answer.length > 200) return 'Please provide a secret answer.';
  if (!/^\d{6}$/.test(pin || '')) return 'The recovery PIN must be exactly 6 digits.';
  return null;
}

/** Returns { flagged, reason } for a comment body. */
export function analyzeComment(body) {
  for (const p of FLAG_PATTERNS) {
    if (p.re.test(body)) return { flagged: 1, reason: p.reason };
  }
  return { flagged: 0, reason: null };
}
