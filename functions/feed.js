/**
 * Keyy's Haven — functions/feed.js
 * Timeline assembly + rendered HTML pages (share resolver, private token node).
 * Pure standard runtime APIs — no npm packages. Database via native `env.DB` D1.
 */

import { nowIso, REACTIONS } from './data.js';

export const SEAL_SVG = (size = 18) =>
  `<svg width="${size}" height="${size}" viewBox="0 0 24 24" role="img" aria-label="Verified" style="vertical-align:-3px">` +
  `<path fill="#2f80ed" d="M12.0 0.8 L14.38 3.11 L17.6 2.3 L18.51 5.49 L21.7 6.4 L20.89 9.62 L23.2 12.0 L20.89 14.38 L21.7 17.6 L18.51 18.51 L17.6 21.7 L14.38 20.89 L12.0 23.2 L9.62 20.89 L6.4 21.7 L5.49 18.51 L2.3 17.6 L3.11 14.38 L0.8 12.0 L3.11 9.62 L2.3 6.4 L5.49 5.49 L6.4 2.3 L9.62 3.11 Z"/>` +
  `<path fill="#ffffff" d="M10.6 15.9 L7.2 12.5 L8.6 11.1 L10.6 13.1 L15.4 8.3 L16.8 9.7 Z"/></svg>`;

export function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

export function mediaUrl(path) {
  const p = String(path || '').replace(/^\/+/, '');
  return '/media/' + p;
}

/** Public identity mapping — only two posting authorities exist. */
export function authorIdentity(authorKey) {
  return authorKey === 'keyy'
    ? { name: 'Keyy Haven Official', verified: 1 }
    : { name: 'System Assistant', verified: 1 };
}

/**
 * Assemble the full timeline: pinned posts first, newest next, with
 * active comments, reaction counters and the viewer's own reaction.
 * Verified flags ride along so the client can render the badge everywhere.
 */
export async function loadFeed(env, viewer) {
  const posts = await env.DB.prepare(
    `SELECT id, author_key, body, media_json, pinned, created_at
     FROM feed_posts ORDER BY pinned DESC, created_at DESC LIMIT 100`
  ).all();
  const comments = await env.DB.prepare(
    `SELECT c.id, c.post_id, c.body, c.created_at, u.username, u.username_lower, u.is_verified
     FROM comments c JOIN users u ON u.id = c.user_id
     WHERE c.status = 'active' ORDER BY c.created_at ASC LIMIT 500`
  ).all();
  const reactionRows = await env.DB.prepare(
    `SELECT post_id, emoji, COUNT(*) AS n FROM reactions GROUP BY post_id, emoji`
  ).all();
  const mineRows = viewer
    ? await env.DB.prepare(`SELECT post_id, emoji FROM reactions WHERE user_id = ?1`).bind(viewer.id).all()
    : { results: [] };

  const reactionsByPost = new Map();
  for (const r of reactionRows.results || []) {
    if (!REACTIONS.includes(r.emoji)) continue;
    const m = reactionsByPost.get(r.post_id) || {};
    m[r.emoji] = r.n;
    reactionsByPost.set(r.post_id, m);
  }
  const mineByPost = new Map((mineRows.results || []).map((r) => [r.post_id, r.emoji]));
  const commentsByPost = new Map();
  for (const c of comments.results || []) {
    const arr = commentsByPost.get(c.post_id) || [];
    arr.push({
      id: c.id,
      username: c.username_lower === 'keyy' ? 'Keyy Haven Official' : c.username,
      verified: c.username_lower === 'keyy' ? 1 : Number(c.is_verified),
      body: c.body,
      created_at: c.created_at,
    });
    commentsByPost.set(c.post_id, arr);
  }

  return (posts.results || []).map((p) => {
    let media = [];
    try { media = JSON.parse(p.media_json || '[]'); } catch { media = []; }
    const id = authorIdentity(p.author_key);
    return {
      id: p.id,
      author_key: p.author_key,
      author_name: id.name,
      verified: 1, // both posting authorities are verified by definition
      body: p.body,
      media: media.map(mediaUrl),
      pinned: Number(p.pinned),
      created_at: p.created_at,
      comments: commentsByPost.get(p.id) || [],
      reactions: reactionsByPost.get(p.id) || {},
      mine: mineByPost.get(p.id) || null,
    };
  });
}

export async function loadStats(env) {
  const one = async (sql, ...binds) => Number((await env.DB.prepare(sql).bind(...binds).first())?.n || 0);
  const [posts, comments, members, flagged, shares] = await Promise.all([
    one('SELECT COUNT(*) AS n FROM feed_posts'),
    one("SELECT COUNT(*) AS n FROM comments WHERE status = 'active'"),
    one('SELECT COUNT(*) AS n FROM users'),
    one('SELECT COUNT(*) AS n FROM comments WHERE flagged = 1'),
    one('SELECT COUNT(*) AS n FROM share_tokens WHERE expires_at > ?1', nowIso()),
  ]);
  return { posts, comments, members, flagged, shares };
}

/** Live indicator state, synchronized with server webhooks. */
export async function liveState(env) {
  const [flag, expiry] = await Promise.all([
    env.DB.prepare(`SELECT value FROM site_settings WHERE key = 'live_stream'`).first(),
    env.DB.prepare(`SELECT value FROM site_settings WHERE key = 'live_expires_at'`).first(),
  ]);
  const notExpired = Number(expiry?.value || 0) > Date.now();
  return Number(flag?.value || 0) === 1 && notExpired;
}

/* ── standalone rendered pages ─────────────────────────────── */
const pageShell = (title, body, status = 200) =>
  new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<meta name="robots" content="noindex"><title>${escapeHtml(title)}</title>` +
    `<link rel="stylesheet" href="/style.css"></head>` +
    `<body><main class="auth-shell"><section class="card card-pad" style="width:min(620px,100%)">` +
    body +
    `<p class="mini-note" style="margin-top:16px"><a href="/">← Back to Keyy's Haven</a></p>` +
    `</section></main></body></html>`,
    { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } }
  );

export function messagePage(title, text, status = 403) {
  return pageShell(title, `<h1 style="font-size:20px;margin-bottom:10px">${escapeHtml(title)}</h1><p class="mini-note">${escapeHtml(text)}</p>`, status);
}

/** Share page: a single timeline post block addressed by its temporary hash. */
export function renderSharePage(post) {
  const id = authorIdentity(post.author_key);
  let media = [];
  try { media = JSON.parse(post.media_json || '[]'); } catch { media = []; }
  const mediaHtml = media.map((m) => `<img src="${escapeHtml(mediaUrl(m))}" alt="Post media" style="border-radius:12px;margin-top:10px;border:1px solid var(--border-subtle)">`).join('');
  return pageShell(
    "Keyy's Haven — shared post",
    `<div style="display:flex;align-items:center;gap:12px">
       <img src="/media/avatar.webp" alt="" width="46" height="46" style="border-radius:50%">
       <div><b>${escapeHtml(id.name)}</b> ${SEAL_SVG(18)}<br>
       <span class="mini-note">${escapeHtml(post.created_at)}</span></div>
     </div>
     <p style="margin-top:14px;white-space:pre-wrap;overflow-wrap:anywhere">${escapeHtml(post.body)}</p>
     ${mediaHtml}
     <p class="mini-note" style="margin-top:14px">Shared via a masked, short-lived link. The sharer's identity and internal ID are never disclosed here.</p>`,
    200
  );
}

/**
 * Private token node — /user=<username>/ID=<value>
 * Re-discloses the hidden private token ONLY to the true account holder's
 * authenticated session. UUIDs are never rendered.
 */
export function renderPrivateNodePage(user) {
  return pageShell(
    'Private token node — Keyy\u2019s Haven',
    `<h1 style="font-size:20px;margin-bottom:10px">🔓 Private token node</h1>
     <p class="mini-note">Authenticated as <b>${escapeHtml(user.username)}</b>${Number(user.is_verified) ? ' ' + SEAL_SVG(16) : ''}. This node re-discloses your hidden verification token only inside your own session cookie. Your internal UUID is never exposed anywhere in the app.</p>
     <div class="field" style="margin-top:14px">
       <label>Private token</label>
       <input type="text" readonly value="${escapeHtml(user.private_token)}" onclick="this.select()">
     </div>
     <p class="hint" style="margin-top:10px">Keep it secret. It is the hidden verification node value for <code>${escapeHtml(user.username)}</code>.</p>`,
    200
  );
}
