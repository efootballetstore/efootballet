import { json, userOf, sbh } from './_gcommon.js';
// POST {token}: revoke the Google access and delete the stored token
export async function onRequestPost({ request, env }) {
  try {
    const { token } = await request.json();
    const u = await userOf(env, token);
    if (!u) return json({ error: 'auth' }, 401);
    const H = sbh(env), SB = env.SUPABASE_URL + '/rest/v1';
    const r = await fetch(SB + '/gmail_links?user_id=eq.' + u.id + '&select=refresh_token', { headers: H });
    const rows = r.ok ? await r.json() : [];
    if (rows[0]) await fetch('https://oauth2.googleapis.com/revoke?token=' + encodeURIComponent(rows[0].refresh_token), { method: 'POST' }).catch(() => {});
    await fetch(SB + '/gmail_links?user_id=eq.' + u.id, { method: 'DELETE', headers: H });
    return json({ ok: true });
  } catch (e) { return json({ error: String(e) }, 500); }
}
