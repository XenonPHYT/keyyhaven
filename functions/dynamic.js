/**
 * Keyy's Haven — functions/[[path]].js
 * Pages Functions catch-all. Handles the three dynamic GET routes that are
 * not static assets:
 *   1. /media/<path>          → R2 WebP vault reader (static /media falls back to assets)
 *   2. /share/<token_hash>    → masked short-lived share page for a timeline post
 *   3. /user=<name>/ID=<value>→ private token node (owner-only disclosure)
 * Everything else is passed through to the static asset layer.
 */

import { getSessionUser, nowIso } from './data.js';
import { renderSharePage, renderPrivateNodePage, messagePage } from './feed.js';

export async function onRequest(context) {
  const { request, env, next } = context;
  if (request.method !== 'GET') return next();

  const url = new URL(request.url);
  let path;
  try { path = decodeURIComponent(url.pathname); } catch { return messagePage('Bad request', 'Malformed URL.', 400); }

  /* ── R2 WebP vault reader ─────────────────────────────────── */
  if (path.startsWith('/media/')) {
    const key = path.replace(/^\/media\//, '');
    if (!key || key.includes('..') || key.includes('\\')) return next(); // path-traversal guard
    if (env.MEDIA) {
      const object = await env.MEDIA.get(key);
      if (object) {
        const headers = new Headers();
        object.writeHttpMetadata(headers);
        headers.set('content-type', object.httpMetadata?.contentType || 'image/webp');
        headers.set('cache-control', 'public, max-age=31536000, immutable');
        headers.set('etag', object.httpEtag);
        return new Response(object.body, { headers });
      }
    }
    return next(); // fall back to statically bundled /media assets (banner, avatar)
  }

  /* ── Masked share resolver: /share/<token_hash> ───────────── */
  if (path.startsWith('/share/')) {
    const tokenHash = path.split('/')[2];
    if (!tokenHash || tokenHash.length < 8) return messagePage('Link expired', 'This masked share link is invalid or has already expired.', 404);
    const row = await env.DB.prepare(
      `SELECT p.* FROM share_tokens s JOIN feed_posts p ON p.id = s.post_id
       WHERE s.token_hash = ?1 AND s.expires_at > ?2`
    ).bind(tokenHash, nowIso()).first();
    if (!row) return messagePage('Link expired', 'This masked share link has expired. Ask for a fresh one — share links are short-lived by design.', 404);
    return renderSharePage(row);
  }

  /* ── Private token node: /user=<username>/ID=<value> ──────── */
  const nodeMatch = path.match(/^\/user=([^/]+)\/ID=(.+)$/);
  if (nodeMatch) {
    const requested = nodeMatch[1].toLowerCase();
    const viewer = await getSessionUser(request, env);
    // The node re-discloses the private token ONLY to the true account holder's
    // authenticated session — nobody else, admins included, via this route.
    if (!viewer || viewer.username_lower !== requested) {
      return messagePage('Private node locked', 'This hidden verification node only re-discloses its token inside an authenticated session belonging to the true account holder.', 403);
    }
    return renderPrivateNodePage(viewer);
  }

  return next();
}
