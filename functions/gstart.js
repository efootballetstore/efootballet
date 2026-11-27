import { json, sign, userOf, REDIRECT } from './_gcommon.js';
// POST {token} -> {url}: the Google consent page address for this signed-in customer
export async function onRequestPost({ request, env }) {
  try {
    if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) return json({ error: 'not-configured' }, 500);
    const { token } = await request.json();
    const u = await userOf(env, token);
    if (!u) return json({ error: 'auth' }, 401);
    const state = await sign(env.GOOGLE_CLIENT_SECRET, { u: u.id, t: Date.now() });
    const q = new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID, redirect_uri: REDIRECT(request.url), response_type: 'code',
      scope: 'openid email https://www.googleapis.com/auth/gmail.readonly',
      access_type: 'offline', prompt: 'consent select_account', state,
    });
    return json({ url: 'https://accounts.google.com/o/oauth2/v2/auth?' + q });
  } catch (e) { return json({ error: String(e) }, 500); }
}
