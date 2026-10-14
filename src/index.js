/**
 * Keyy's Haven — src/index.js (Cloudflare Workers entry point)
 *   • /api              → functions/api.js
 *   • /media/*, /share/<hash>, /user=<x>/ID=<y> → functions/dynamic.js
 *   • everything else   → Workers Static Assets (ASSETS binding)
 */

import { onRequestGet, onRequestPost } from '../functions/api.js';
import { onRequest as handleDynamic } from '../functions/dynamic.js';

const jsonResponse = (data, status) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });

async function handle(request, env) {
  const url = new URL(request.url);

  if (url.pathname === '/api') {
    const context = { request, env };
    if (request.method === 'GET') return onRequestGet(context);
    if (request.method === 'POST') return onRequestPost(context);
    return jsonResponse({ ok: false, error: 'Method not allowed.' }, 405);
  }

  if (request.method === 'GET') {
    return handleDynamic({ request, env, next: () => env.ASSETS.fetch(request) });
  }

  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch (e) {
      console.error(e);
      return jsonResponse({ ok: false, error: 'Server error: ' + (e && e.message ? e.message : String(e)) }, 500);
    }
  },

  // Daily cleanup (cron in wrangler.jsonc)
  async scheduled(event, env) {
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare('DELETE FROM sessions WHERE expires_at <= ?1').bind(now),
      env.DB.prepare('DELETE FROM share_tokens WHERE expires_at <= ?1').bind(now),
      env.DB.prepare('DELETE FROM rate_limits WHERE reset_at <= ?1').bind(Date.now()),
    ]);
  },
};
