import { unsign, sbh, REDIRECT } from './_gcommon.js';
// Google sends the customer back here after the consent page
export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const done = (r) => Response.redirect(new URL('/?acc=1&gmail=' + r, url).toString(), 302);
  try {
    if (url.searchParams.get('error')) return done('no');
    const st = await unsign(env.GOOGLE_CLIENT_SECRET, url.searchParams.get('state'));
    if (!st || !st.u || Date.now() - st.t > 15 * 60 * 1000) return done('err');
    const tr = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code: url.searchParams.get('code') || '', client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, redirect_uri: REDIRECT(request.url), grant_type: 'authorization_code' }),
    });
    const t = await tr.json();
    if (!t.refresh_token || !/gmail\.readonly/.test(t.scope || '')) return done('scope');   // customer unticked the Gmail permission
    let email = '';
    try { email = JSON.parse(atob(t.id_token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))).email || ''; } catch (e) {}
    email = String(email).toLowerCase();
    if (!/^[^@\s]+@[^@\s]+$/.test(email)) return done('err');
    const H = sbh(env), SB = env.SUPABASE_URL + '/rest/v1';
    await fetch(SB + '/gmail_links?on_conflict=user_id', { method: 'POST', headers: { ...H, Prefer: 'resolution=merge-duplicates,return=minimal' }, body: JSON.stringify({ user_id: st.u, email, refresh_token: t.refresh_token }) });
    await fetch(SB + '/fwd_links?on_conflict=email,user_id', { method: 'POST', headers: { ...H, Prefer: 'resolution=ignore-duplicates,return=minimal' }, body: JSON.stringify({ email, user_id: st.u }) });
    return done('ok');
  } catch (e) { return done('err'); }
}
