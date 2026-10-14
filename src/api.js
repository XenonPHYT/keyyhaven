/**
 * Keyy's Haven — functions/api.js
 * Single /api endpoint. Dispatches every action by the `action` field.
 * Pure standard runtime APIs — no npm packages. All database access runs on
 * the native `env.DB` Cloudflare D1 binding via prepared statements.
 */

import {
  json, nowIso, uuid, USERNAME_RE, randomToken, clientIp, rateAllowed, rateHit,
  hashSecret, verifySecret,
  createSession, sessionCookie, clearSessionCookie,
  getSessionUser, destroySession,
  requireAdmin, getSetting, setSetting,
  validateRegistration, analyzeComment, REACTIONS, RESERVED_USERNAMES,
} from './data.js';
import { loadFeed, loadStats, liveState } from './feed.js';

const INVITE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const normalizeInvite = (v) => String(v || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
function makeInviteCode() {
  const chars = Array.from(crypto.getRandomValues(new Uint8Array(12)), (b) => INVITE_ALPHABET[b % 32]).join('');
  return chars.replace(/(.{4})(?=.)/g, '$1-'); // XXXX-XXXX-XXXX
}

const isHttps = (request) => new URL(request.url).protocol === 'https:';

async function readBody(request) {
  try { return await request.json(); } catch { return {}; }
}

/* ══════════════════════════ GET actions ══════════════════════════ */

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');
  const me = await getSessionUser(request, env);

  if (action === 'site_state') {
    return json({ ok: true, live: await liveState(env), me: me ? publicIdentity(me) : null });
  }

  if (action === 'get_posts') {
    const [posts, stats, live] = await Promise.all([loadFeed(env, me), loadStats(env), liveState(env)]);
    return json({
      ok: true,
      live,
      me: me ? publicIdentity(me) : null,
      stats: { posts: stats.posts, comments: stats.comments, members: stats.members, flagged: stats.flagged },
      posts,
    });
  }

  return json({ ok: false, error: 'Unknown GET action.' }, 404);
}

function publicIdentity(user) {
  // Public DOM surface: plaintext username + verification state only.
  // Internal UUIDs and private tokens are NEVER included here.
  return { username: user.username, is_verified: Number(user.is_verified) };
}

/* ══════════════════════════ POST actions ═════════════════════════ */

export async function onRequestPost(context) {
  const { request, env } = context;
  const body = await readBody(request);
  const action = body.action || new URL(request.url).searchParams.get('action');

  switch (action) {
    /* ── public account lifecycle ── */
    case 'register':    return register(env, request, body);
    case 'login':       return login(env, request, body);
    case 'logout':      return logout(env, request);
    case 'recover_pin': return recoverPin(env, request, body);
    case 'comment':     return comment(env, request, body);
    case 'react':       return react(env, request, body);
    case 'share_create': return shareCreate(env, request, body);

    /* ── admin console + webhooks (server-side gated) ── */
    case 'admin_auth':
    case 'admin_list_users':
    case 'admin_set_verified':
    case 'admin_reset_pin':
    case 'admin_reveal_token':
    case 'admin_provision_keyy':
    case 'admin_invite_create':
    case 'admin_invite_list':
    case 'admin_invite_revoke':
    case 'admin_flagged':
    case 'admin_delete_comment':
    case 'admin_publish':
    case 'admin_toggle_live':
    case 'admin_site_state':
    case 'live_webhook':
      return adminDispatch(env, request, body, action);
  }
  return json({ ok: false, error: 'Unknown action.' }, 404);
}

/* ── register: username, password, secret Q/A, 6-digit recovery PIN ── */
async function register(env, request, body) {
  const username = String(body.username || '').trim();
  const password = String(body.password || '');
  const question = String(body.secret_question || '').trim();
  const answer = String(body.secret_answer || '').trim();
  const pin = String(body.pin || '').trim();

  const err = validateRegistration({ username, password, secret_question: question, secret_answer: answer, pin });
  if (err) return json({ ok: false, error: err }, 400);

  const exists = await env.DB.prepare('SELECT 1 FROM users WHERE username_lower = ?1').bind(username.toLowerCase()).first();
  if (exists) return json({ ok: false, error: 'That username is already part of the Haven.' }, 409);

  // Reserved handle? Only the person holding the admin-issued invite code may register it,
  // and that account is created verified.
  const lower = username.toLowerCase();
  let invite = null;
  try { invite = await env.DB.prepare('SELECT * FROM verified_invites WHERE handle_lower = ?1').bind(lower).first(); } catch { invite = null; }
  let verified = 0;
  if (invite) {
    const rlKey = `invite:${clientIp(request)}:${lower}`;
    if (!(await rateAllowed(env, rlKey, 5))) return json({ ok: false, error: 'Too many attempts. Try again later.' }, 429);
    const code = normalizeInvite(body.invite_code);
    if (!code || !(await verifySecret(code, invite.code_hash))) {
      await rateHit(env, rlKey, 60 * 60);
      return json({ ok: false, error: 'This username is reserved. Enter the invite code from the admin, or choose another username.' }, 403);
    }
    verified = 1;
  }

  const id = uuid();
  const privateToken = randomToken(32); // opaque hidden token
  const insertUser = env.DB.prepare(
    `INSERT INTO users (id, username, username_lower, password_hash, secret_question, secret_answer_hash, pin_hash, is_verified, private_token, flagged_count, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10)`
  ).bind(id, username, lower, await hashSecret(password), question, await hashSecret(answer.toLowerCase()), await hashSecret(pin), verified, privateToken, nowIso());
  if (invite) {
    await env.DB.batch([insertUser, env.DB.prepare('DELETE FROM verified_invites WHERE handle_lower = ?1').bind(lower)]);
  } else {
    await insertUser.run();
  }

  const token = await createSession(env, id);
  return json({ ok: true }, 200, { 'set-cookie': sessionCookie(token, isHttps(request)) });
}

/* ── login ── */
async function login(env, request, body) {
  const username = String(body.username || '').trim().toLowerCase();
  const rlKey = `login:${clientIp(request)}:${username}`;
  if (!(await rateAllowed(env, rlKey, 8))) return json({ ok: false, error: 'Too many attempts. Try again later.' }, 429);
  const user = await env.DB.prepare('SELECT * FROM users WHERE username_lower = ?1').bind(username).first();
  if (!user || !(await verifySecret(String(body.password || ''), user.password_hash))) {
    await rateHit(env, rlKey, 15 * 60);
    return json({ ok: false, error: 'Invalid username or password.' }, 401);
  }
  const token = await createSession(env, user.id);
  return json({ ok: true, username: user.username, is_verified: Number(user.is_verified) },
    200, { 'set-cookie': sessionCookie(token, isHttps(request)) });
}

async function logout(env, request) {
  await destroySession(request, env);
  return json({ ok: true }, 200, { 'set-cookie': clearSessionCookie() });
}

/* ── self-service PIN reset via secret answer (admin can also force-reset) ── */
async function recoverPin(env, request, body) {
  const username = String(body.username || '').trim().toLowerCase();
  const rlKey = `recover:${clientIp(request)}:${username}`;
  if (!(await rateAllowed(env, rlKey, 5))) return json({ ok: false, error: 'Too many attempts. Try again later.' }, 429);
  const user = await env.DB.prepare('SELECT * FROM users WHERE username_lower = ?1').bind(username).first();
  // Uniform error regardless of account existence (no user enumeration)
  if (!user || !(await verifySecret(String(body.secret_answer || '').trim().toLowerCase(), user.secret_answer_hash))) {
    await rateHit(env, rlKey, 60 * 60);
    return json({ ok: false, error: 'Verification failed.' }, 401);
  }
  const newPin = String(body.new_pin || '').trim();
  if (!/^\d{6}$/.test(newPin)) return json({ ok: false, error: 'The recovery PIN must be exactly 6 digits.' }, 400);
  await env.DB.prepare('UPDATE users SET pin_hash = ?1 WHERE id = ?2').bind(await hashSecret(newPin), user.id).run();
  return json({ ok: true, message: 'Recovery PIN reset. Keep your new 6-digit code safe.' });
}

/* ── comment (secondary users interact via text comments only) ── */
async function comment(env, request, body) {
  const me = await getSessionUser(request, env);
  if (!me) return json({ ok: false, error: 'Sign in to comment.' }, 401);
  const text = String(body.body || '').trim();
  if (!text || text.length > 1000) return json({ ok: false, error: 'Comment must be 1–1000 characters.' }, 400);
  const post = await env.DB.prepare('SELECT id FROM feed_posts WHERE id = ?1').bind(Number(body.post_id)).first();
  if (!post) return json({ ok: false, error: 'Post not found.' }, 404);

  const scan = analyzeComment(text); // admin-tracked pattern matching
  await env.DB.prepare(
    'INSERT INTO comments (post_id, user_id, body, status, flagged, flag_reason, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)'
  ).bind(post.id, me.id, text, 'active', scan.flagged, scan.reason, nowIso()).run();
  if (scan.flagged) {
    await env.DB.prepare('UPDATE users SET flagged_count = flagged_count + 1 WHERE id = ?1').bind(me.id).run();
  }
  return json({ ok: true, flagged: Boolean(scan.flagged) });
}

/* ── single-pass emoji reaction (one emoji per user per post) ── */
async function react(env, request, body) {
  const me = await getSessionUser(request, env);
  if (!me) return json({ ok: false, error: 'Sign in to react.' }, 401);
  const emoji = String(body.emoji || '');
  if (!REACTIONS.includes(emoji)) return json({ ok: false, error: 'Unsupported reaction.' }, 400);
  const postId = Number(body.post_id);
  const post = await env.DB.prepare('SELECT id FROM feed_posts WHERE id = ?1').bind(postId).first();
  if (!post) return json({ ok: false, error: 'Post not found.' }, 404);

  const existing = await env.DB.prepare('SELECT emoji FROM reactions WHERE post_id = ?1 AND user_id = ?2').bind(postId, me.id).first();
  if (existing && existing.emoji === emoji) {
    await env.DB.prepare('DELETE FROM reactions WHERE post_id = ?1 AND user_id = ?2').bind(postId, me.id).run();
  } else if (existing) {
    await env.DB.prepare('UPDATE reactions SET emoji = ?1, created_at = ?2 WHERE post_id = ?3 AND user_id = ?4')
      .bind(emoji, nowIso(), postId, me.id).run();
  } else {
    await env.DB.prepare('INSERT INTO reactions (post_id, user_id, emoji, created_at) VALUES (?1, ?2, ?3, ?4)')
      .bind(postId, me.id, emoji, nowIso()).run();
  }
  return json({ ok: true });
}

/* ── dynamic share masking: short-lived cryptographic hash → clipboard path ── */
async function shareCreate(env, request, body) {
  const me = await getSessionUser(request, env);
  if (!me) return json({ ok: false, error: 'Sign in to share.' }, 401);
  const postId = Number(body.post_id);
  const post = await env.DB.prepare('SELECT id FROM feed_posts WHERE id = ?1').bind(postId).first();
  if (!post) return json({ ok: false, error: 'Post not found.' }, 404);

  const ttl = Math.max(1, Number(await getSetting(env, 'share_ttl_minutes', '15'))); // short-lived
  const tokenHash = randomToken(24);
  const expiresAt = new Date(Date.now() + ttl * 60000).toISOString();
  await env.DB.prepare('INSERT INTO share_tokens (token_hash, post_id, created_by, expires_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5)')
    .bind(tokenHash, postId, me.id, expiresAt, nowIso()).run();

  // The sharer's active footprint stays server-side (created_by is never sent to the client DOM).
  return json({ ok: true, path: `/share/${tokenHash}`, expires_at: expiresAt });
}

/* ══════════════════════════ admin surface ════════════════════════ */

async function adminDispatch(env, request, body, action) {
  const gate = await requireAdmin(request, env, body); // every admin action is gated server-side
  if (!gate.ok) return json({ ok: false, error: gate.error }, gate.status || 403);

  switch (action) {
    case 'admin_auth':
      return json({ ok: true, via: gate.via });

    /* Scan user details: usernames, flags, join dates */
    case 'admin_list_users': {
      const q = String(body.query || '').trim();
      const rows = q
        ? await env.DB.prepare('SELECT username, is_verified, flagged_count, created_at FROM users WHERE username_lower LIKE ?1 ORDER BY created_at DESC LIMIT 200')
            .bind('%' + q.toLowerCase() + '%').all()
        : await env.DB.prepare('SELECT username, is_verified, flagged_count, created_at FROM users ORDER BY created_at DESC LIMIT 200').all();
      return json({ ok: true, users: (rows.results || []).map((u) => ({ ...u, is_verified: Number(u.is_verified) })) });
    }

    /* Dynamic verification engine — the is_verified master switch (integer 0/1) */
    case 'admin_set_verified': {
      const username = String(body.username || '').trim().toLowerCase();
      const verified = Number(body.verified) ? 1 : 0;
      if (username === 'keyy' && !verified) return json({ ok: false, error: 'The owner badge cannot be revoked.' }, 400);
      const r = await env.DB.prepare('UPDATE users SET is_verified = ?1 WHERE username_lower = ?2').bind(verified, username).run();
      if (!r.success || r.meta.changes === 0) return json({ ok: false, error: 'User not found.' }, 404);
      return json({ ok: true, username, is_verified: verified });
    }

    /* Manually force-reset forgotten 6-digit recovery PINs */
    case 'admin_reset_pin': {
      const username = String(body.username || '').trim().toLowerCase();
      const newPin = String(body.new_pin || '').trim();
      if (!/^\d{6}$/.test(newPin)) return json({ ok: false, error: 'PIN must be exactly 6 digits.' }, 400);
      const r = await env.DB.prepare('UPDATE users SET pin_hash = ?1 WHERE username_lower = ?2').bind(await hashSecret(newPin), username).run();
      if (!r.success || r.meta.changes === 0) return json({ ok: false, error: 'User not found.' }, 404);
      return json({ ok: true });
    }

    /* Disclose the hidden private token to the admin ledger only */
    case 'admin_reveal_token': {
      const row = await env.DB.prepare('SELECT private_token FROM users WHERE username_lower = ?1')
        .bind(String(body.username || '').trim().toLowerCase()).first();
      if (!row) return json({ ok: false, error: 'User not found.' }, 404);
      return json({ ok: true, private_token: row.private_token });
    }

    /* First-run provisioning of the hardcoded owner account */
    case 'admin_provision_keyy': {
      const password = String(body.password || '');
      if (password.length < 8) return json({ ok: false, error: 'Owner password must be at least 8 characters.' }, 400);
      const existing = await env.DB.prepare('SELECT id FROM users WHERE username_lower = ?1').bind('keyy').first();
      const hash = await hashSecret(password);
      if (existing) {
        await env.DB.prepare('UPDATE users SET password_hash = ?1, is_verified = 1 WHERE id = ?2').bind(hash, existing.id).run();
      } else {
        const id = uuid();
        const privateToken = randomToken(32);
        await env.DB.prepare(
          `INSERT INTO users (id, username, username_lower, password_hash, secret_question, secret_answer_hash, pin_hash, is_verified, private_token, flagged_count, created_at)
           VALUES (?1, 'Keyy', 'keyy', ?2, 'Owner provisioning question', '', ?3, 1, ?4, 0, ?5)`
        ).bind(id, hash, await hashSecret(String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000))), privateToken, nowIso()).run();
      }
      return json({ ok: true });
    }

    /* Reserve a handle for one verified individual and mint a one-time invite code */
    case 'admin_invite_create': {
      const handle = String(body.username || '').trim();
      if (!USERNAME_RE.test(handle)) return json({ ok: false, error: 'Username must be 3–24 characters (letters, numbers, underscore).' }, 400);
      const lower = handle.toLowerCase();
      if (RESERVED_USERNAMES.has(lower)) return json({ ok: false, error: 'That username is a system-reserved name.' }, 400);
      const taken = await env.DB.prepare('SELECT 1 FROM users WHERE username_lower = ?1').bind(lower).first();
      if (taken) return json({ ok: false, error: 'That username already has an account. Use the Verified toggle in the User ledger instead.' }, 409);
      const code = makeInviteCode();
      const note = String(body.note || '').trim().slice(0, 120);
      await env.DB.prepare(
        `INSERT INTO verified_invites (handle_lower, handle, code_hash, note, created_at) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(handle_lower) DO UPDATE SET code_hash = excluded.code_hash, handle = excluded.handle, note = excluded.note, created_at = excluded.created_at`
      ).bind(lower, handle, await hashSecret(normalizeInvite(code)), note, nowIso()).run();
      return json({ ok: true, username: handle, code }); // shown once — only the hash is stored
    }

    case 'admin_invite_list': {
      const rows = await env.DB.prepare('SELECT handle, note, created_at FROM verified_invites ORDER BY created_at DESC LIMIT 200').all();
      return json({ ok: true, invites: rows.results || [] });
    }

    case 'admin_invite_revoke': {
      const r = await env.DB.prepare('DELETE FROM verified_invites WHERE handle_lower = ?1').bind(String(body.username || '').trim().toLowerCase()).run();
      if (!r.success || r.meta.changes === 0) return json({ ok: false, error: 'Invite not found.' }, 404);
      return json({ ok: true });
    }

    /* Flagged comment patterns for the ledger */
    case 'admin_flagged': {
      const rows = await env.DB.prepare(
        `SELECT c.id, c.body, c.status, c.flag_reason, c.created_at, u.username
         FROM comments c JOIN users u ON u.id = c.user_id
         WHERE c.flagged = 1 OR c.status != 'active'
         ORDER BY c.created_at DESC LIMIT 200`
      ).all();
      return json({ ok: true, comments: rows.results || [] });
    }

    /* Soft-delete moderation: status flips to 'deleted_by_admin' */
    case 'admin_delete_comment': {
      const r = await env.DB.prepare("UPDATE comments SET status = 'deleted_by_admin' WHERE id = ?1").bind(Number(body.comment_id)).run();
      if (!r.success || r.meta.changes === 0) return json({ ok: false, error: 'Comment not found.' }, 404);
      return json({ ok: true });
    }

    /* Publishing: only Keyy (owner) and the Platform (system assistant) */
    case 'admin_publish': {
      const authorKey = body.author_key === 'platform' ? 'platform' : 'keyy';
      const text = String(body.body || '').trim();
      if (!text || text.length > 4000) return json({ ok: false, error: 'Post body must be 1–4000 characters.' }, 400);
      const paths = Array.isArray(body.media_paths) ? body.media_paths : [];
      for (const p of paths) {
        if (!/^[\w\-/]+\.(webp|png|jpg|jpeg)$/i.test(String(p))) return json({ ok: false, error: `Invalid media path: ${p}` }, 400);
      }
      const r = await env.DB.prepare(
        'INSERT INTO feed_posts (author_key, body, media_json, pinned, created_at) VALUES (?1, ?2, ?3, ?4, ?5)'
      ).bind(authorKey, text, JSON.stringify(paths), Number(body.pinned) ? 1 : 0, nowIso()).run();
      return json({ ok: true, post_id: r.meta.last_row_id });
    }

    /* Live indicator master switch (also used by the webhook below) */
    case 'admin_toggle_live': {
      const on = Number(body.on) ? 1 : 0;
      const expiry = on ? String(Date.now() + 2 * 60 * 60 * 1000) : '0'; // 2h window, refreshable
      await setSetting(env, 'live_stream', on);
      await setSetting(env, 'live_expires_at', expiry);
      return json({ ok: true, live: Boolean(on) });
    }

    /* Server webhook: flip the pulsing LIVE indicator for every visitor */
    case 'live_webhook': {
      const on = body.event === 'stream_end' ? 0 : 1;
      const expiry = on ? String(Date.now() + 2 * 60 * 60 * 1000) : '0';
      await setSetting(env, 'live_stream', on);
      await setSetting(env, 'live_expires_at', expiry);
      return json({ ok: true, live: Boolean(on) });
    }

    case 'admin_site_state': {
      const [live, stats] = await Promise.all([liveState(env), loadStats(env)]);
      return json({ ok: true, live, stats });
    }
  }
  return json({ ok: false, error: 'Unknown admin action.' }, 404);
}
