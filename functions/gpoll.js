import { json, sbh } from './_gcommon.js';
// Called every minute by the Email Worker (Authorization: Bearer <service key>).
// For every customer who is waiting for a code and connected Gmail: read the newest Konami email, pass the code on.
const dec = (s) => new TextDecoder().decode(Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)));
function bodyText(p) {
  if (!p) return '';
  let out = '';
  if (p.body && p.body.data && /text\/(plain|html)/.test(p.mimeType || '')) { try { out += ' ' + dec(p.body.data); } catch (e) {} }
  for (const c of p.parts || []) out += ' ' + bodyText(c);
  return out;
}
function findCode(raw) {
  const t = raw.replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/\s+/g, ' ');
  let m = t.match(/(?:code|verification|コード|認証)[^0-9]{0,80}(\d{6})(?!\d)/i);
  if (!m) m = t.match(/(?<!\d)(\d{6})(?!\d)/);
  return m ? m[1] : null;
}
export async function onRequestGet({ request, env }) {
  if (request.headers.get('Authorization') !== 'Bearer ' + env.SUPABASE_SERVICE_KEY) return json({ error: 'auth' }, 401);
  const H = sbh(env), SB = env.SUPABASE_URL + '/rest/v1', log = [];
  try {
    const w = await fetch(SB + '/rpc/gmail_waiting', { method: 'POST', headers: H, body: '{}' });
    const list = w.ok ? await w.json() : [];
    for (const g of list.slice(0, 10)) {
      try {
        const tr = await (await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, refresh_token: g.refresh_token, grant_type: 'refresh_token' }) })).json();
        if (tr.error === 'invalid_grant') { await fetch(SB + '/gmail_links?user_id=eq.' + g.user_id, { method: 'DELETE', headers: H }); log.push('unlinked'); continue; }
        if (!tr.access_token) { log.push('token-fail'); continue; }
        const A = { Authorization: 'Bearer ' + tr.access_token };
        const ls = await (await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=3&q=' + encodeURIComponent('from:konami newer_than:1h'), { headers: A })).json();
        for (const m of ls.messages || []) {
          const msg = await (await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/' + m.id + '?format=full', { headers: A })).json();
          if (Date.now() - Number(msg.internalDate || 0) > 9 * 60 * 1000) continue;   // only fresh codes
          const code = findCode(bodyText(msg.payload));
          if (!code) { log.push('no-code'); continue; }
          const r = await fetch(SB + '/rpc/auto_konami_code', { method: 'POST', headers: H, body: JSON.stringify({ p_email: g.email, p_val: code, p_kind: 'code' }) });
          log.push('code->' + (await r.text()).slice(0, 30));
          break;
        }
      } catch (e) { log.push('err ' + e); }
    }
  } catch (e) { log.push('fatal ' + e); }
  return json({ waiting: log.length, log });
}
