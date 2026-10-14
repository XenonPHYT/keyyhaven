/**
 * Keyy's Haven — src/index.js (Cloudflare Workers entry point)
 * Single fetch handler that ports the Pages Functions routing model:
 *   • /api              → functions/api.js  (GET + POST action dispatcher)
 *   • /media/*          → functions/dynamic.js (R2 vault reader, static fallback)
 *   • /share/<hash>     → functions/dynamic.js (masked short-lived share page)
 *   • /user=<x>/ID=<y>  → functions/dynamic.js (private token node)
 *   • everything else   → Workers Static Assets via the ASSETS binding
 *
 * Pure standard runtime APIs — no npm runtime packages.
 */

import { onRequestGet, onRequestPost } from '../functions/api.js';
import { onRequest as handleDynamic } from '../functions/dynamic.js';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ── /api: the action dispatcher (same contract as the Pages build) ──
    if (url.pathname === '/api') {
      const context = { request, env };
      if (request.method === 'GET') return onRequestGet(context);
      if (request.method === 'POST') return onRequestPost(context);
      return new Response(JSON.stringify({ ok: false, error: 'Method not allowed.' }), {
        status: 405,
        headers: { 'content-type': 'application/json; charset=utf-8' },
      });
    }

    // ── dynamic GET routes (share resolver, private token node, R2 media) ──
    if (request.method === 'GET') {
      return handleDynamic({
        request,
        env,
        // `next()` now defers to Workers Static Assets instead of the Pages asset layer
        next: () => env.ASSETS.fetch(request),
      });
    }

    return env.ASSETS.fetch(request);
  },

  // Daily cleanup (cron in wrangler.jsonc): expired sessions, share links, rate-limit rows
  async scheduled(event, env) {
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare('DELETE FROM sessions WHERE expires_at <= ?1').bind(now),
      env.DB.prepare('DELETE FROM share_tokens WHERE expires_at <= ?1').bind(now),
      env.DB.prepare('DELETE FROM rate_limits WHERE reset_at <= ?1').bind(Date.now()),
    ]);
  },
};
