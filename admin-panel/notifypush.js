// POST /notifypush  { msg_id }   (Authorization: Bearer <user access token>)
// Sends a web-push "you have a new message" to the other side of a conversation.
// Needs env vars: VAPID_PUBLIC (base64url public key) and VAPID_PRIVATE_JWK (private key as JSON).
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb = (s) => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); };
const enc = new TextEncoder();
const cat = (...a) => { const n = a.reduce((t, x) => t + x.length, 0); const o = new Uint8Array(n); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };

async function vapidAuth(env, endpoint) {
  const aud = new URL(endpoint).origin;
  const h = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const p = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 43200, sub: env.VAPID_SUBJECT || 'mailto:noreply@efootballet.store' })));
  const key = await crypto.subtle.importKey('jwk', JSON.parse(env.VAPID_PRIVATE_JWK), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(h + '.' + p));
  return `vapid t=${h}.${p}.${b64u(sig)}, k=${env.VAPID_PUBLIC}`;
}
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}
async function encryptPayload(p256dh, auth, text) {
  const ua = unb(p256dh), authSecret = unb(auth);
  const eph = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', ua, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, eph.privateKey, 256));
  const ikm = await hkdf(authSecret, secret, cat(enc.encode('WebPush: info\0'), ua, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, cat(enc.encode(text), new Uint8Array([2]))));
  const rs = new Uint8Array([0, 0, 0x10, 0]);
  return cat(salt, rs, new Uint8Array([asPub.length]), asPub, ct);
}

export async function onRequestPost({ request, env }) {
  const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json' } });
  try {
    if (!env.VAPID_PUBLIC || !env.VAPID_PRIVATE_JWK) return json({ sent: 0, reason: 'no-keys' });
    const SB = env.SUPABASE_URL, K = env.SUPABASE_SERVICE_KEY;
    const H = { apikey: K, Authorization: 'Bearer ' + K };
    const u = await fetch(`${SB}/auth/v1/user`, { headers: { apikey: K, Authorization: request.headers.get('authorization') || '' } });
    if (!u.ok) return json({ error: 'auth' }, 401);
    const uid = (await u.json()).id;
    const { msg_id } = await request.json();
    const ms = await (await fetch(`${SB}/rest/v1/messages?id=eq.${Number(msg_id)}&select=id,conv_id,sender_id,role,kind,body`, { headers: H })).json();
    const m = ms && ms[0];
    if (!m || m.sender_id !== uid) return json({ error: 'msg' }, 403);
    const cs = await (await fetch(`${SB}/rest/v1/conversations?id=eq.${m.conv_id}&select=kind,buyer_id,seller_id`, { headers: H })).json();
    const c = cs && cs[0];
    if (!c) return json({ sent: 0, why: 'no-conv' });

    let to = [];
    if (c.kind === 'support') {
      if (m.role === 'admin') to = [c.buyer_id];
      else to = (await (await fetch(`${SB}/rest/v1/admins?select=user_id`, { headers: H })).json()).map((a) => a.user_id);
    } else {
      to = [m.sender_id === c.buyer_id ? c.seller_id : c.buyer_id].filter(Boolean);
      // a deal was agreed or an exchange accepted: tell the admins too
      if (m.kind === 'deal_agree' || m.kind === 'exchange_accept') {
        const ad = await (await fetch(`${SB}/rest/v1/admins?select=user_id`, { headers: H })).json();
        to = to.concat(ad.map((a) => a.user_id));
      }
    }
    to = to.filter((x) => x && x !== uid);
    if (!to.length) return json({ sent: 0, why: 'no-recipient', kind: c.kind, role: m.role });

    let subs = await (await fetch(`${SB}/rest/v1/push_subs?user_id=in.(${to.join(',')})&select=id,user_id,endpoint,p256dh,auth,app`, { headers: H })).json();
    // admin-app phones get admin events only; everyone else gets their normal phones
    const toAdmins = (c.kind === 'support' && m.role !== 'admin') || m.kind === 'deal_agree' || m.kind === 'exchange_accept';
    const byUser = {};
    for (const s of Array.isArray(subs) ? subs : []) (byUser[s.user_id] = byUser[s.user_id] || []).push(s);
    subs = [];
    for (const k of Object.keys(byUser)) {
      const adm = byUser[k].filter((s) => s.app === 'admin');
      subs = subs.concat(toAdmins && adm.length ? adm : byUser[k].filter((s) => s.app !== 'admin'));
    }
    let sent = 0;
    const st = [];
    const LBL = { image: '\u{1F5BC} Photo', exchange_offer: '\u{1F501} Exchange offer', exchange_accept: '\u2705 Exchange accepted', exchange_decline: 'Exchange declined', price_ask: 'Asked for the last price', price_offer: '\u{1F4B0} New price offer', no_price: 'No lower price', deal_agree: '\u{1F91D} Deal agreed', creds_sent: '\u{1F510} Login details sent', code_sent: '\u{1F510} Code sent', fee_propose: 'Fee payer proposed', fee_agree: 'Fee payer agreed', req_accept: '\u2705 Seller accepted — you can pay now', req_decline: '\u274C Seller declined', buy_request: '\u{1F6D2} New buy request' };
    let who = 'eFootballET';
    try { const t = await (await fetch(`${SB}/rest/v1/tg_links?user_id=eq.${uid}&select=username,first_name&limit=1`, { headers: H })).json(); if (t && t[0]) who = t[0].first_name || (t[0].username ? '@' + t[0].username : who); } catch (e) {}
    if (m.role === 'admin') who = 'eFootballET';
    const text = m.kind === 'text' ? String(m.body || '').slice(0, 140) : (LBL[m.kind] || 'New message');
    const msg = { title: '\u{1F4AC} ' + who, body: text, url: '/?msgs=1', tag: 'chat-' + m.conv_id };
    for (const s of subs) {
      try {
        let init = { method: 'POST', headers: { TTL: '86400', Urgency: 'high', Authorization: await vapidAuth(env, s.endpoint) } };
        if (s.p256dh && s.auth) { init.headers['Content-Encoding'] = 'aes128gcm'; init.headers['Content-Type'] = 'application/octet-stream'; init.body = await encryptPayload(s.p256dh, s.auth, JSON.stringify(msg)); }
        else init.headers['Content-Length'] = '0';
        const r = await fetch(s.endpoint, init);
        st.push(r.status);
        if (r.status === 404 || r.status === 410) await fetch(`${SB}/rest/v1/push_subs?id=eq.${s.id}`, { method: 'DELETE', headers: H });
        else if (r.ok) sent++;
      } catch (e) { st.push('err'); }
    }
    return json({ sent, to: to.length, subs: subs.length, st });
  } catch (e) {
    return json({ error: 'server' }, 500);
  }
}
