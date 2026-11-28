// POST /notifydeal { deal_id }  (Authorization: Bearer <user token>)
// Sends a web-push to whoever's turn it is in an account deal.
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
    const H = { apikey: K, Authorization: 'Bearer ' + K, 'content-type': 'application/json' };
    const u = await fetch(`${SB}/auth/v1/user`, { headers: { apikey: K, Authorization: request.headers.get('authorization') || '' } });
    if (!u.ok) return json({ error: 'auth' }, 401);
    const uid = (await u.json()).id;
    const { deal_id } = await request.json();
    const id = Number(deal_id);
    if (!id) return json({ error: 'bad' }, 400);
    const ds = await (await fetch(`${SB}/rest/v1/deals?id=eq.${id}&select=id,kind,status,title,buyer_id,seller_id`, { headers: H })).json();
    const d = Array.isArray(ds) && ds[0];
    if (!d) return json({ error: 'deal' }, 404);
    const ad = await (await fetch(`${SB}/rest/v1/admins?select=user_id`, { headers: H })).json();
    const admins = (Array.isArray(ad) ? ad : []).map((a) => a.user_id);
    if (uid !== d.buyer_id && uid !== d.seller_id && !admins.includes(uid)) return json({ error: 'forbidden' }, 403);
    const tr = await fetch(`${SB}/rest/v1/rpc/deal_turn`, { method: 'POST', headers: H, body: JSON.stringify({ p_id: id }) });
    const turn = tr.ok ? await tr.json() : [];
    const ids = [];
    if (turn.includes('buyer')) ids.push(d.buyer_id);
    if (turn.includes('seller') && d.seller_id) ids.push(d.seller_id);
    const T = {
      requested: ['\u{1F514} አዲስ ጥያቄ', 'New request on your account'],
      login: ['\u{1F464} ተራዎ ነው', 'Send your account email + password'],
      code1: ['\u{1F510} ተራዎ ነው', 'Konami sent a code to your account email. Enter it now'],
      code3: ['\u{1F510} ተራዎ ነው', 'Konami sent the email-change code. Enter it now'],
      pay: ['\u{1F4B0} ክፍያ ተራዎ ነው', 'Time to pay for your deal'],
    }[d.status] || ['eFootballET', 'Your deal has an update'];
    const send = async (uids, adminApp, msg) => {
      uids = [...new Set(uids)].filter((x) => x && x !== uid);
      if (!uids.length) return 0;
      let subs = await (await fetch(`${SB}/rest/v1/push_subs?user_id=in.(${uids.join(',')})&select=id,endpoint,p256dh,auth,app`, { headers: H })).json();
      subs = Array.isArray(subs) ? subs : [];
      const adm = subs.filter((s) => s.app === 'admin');
      const use = adminApp ? (adm.length ? adm : subs) : subs.filter((s) => s.app !== 'admin');
      let sent = 0;
      for (const s of use) {
        try {
          const body = await encryptPayload(s.p256dh, s.auth, JSON.stringify(msg));
          const r = await fetch(s.endpoint, { method: 'POST', headers: { TTL: '86400', Urgency: 'high', 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', Authorization: await vapidAuth(env, s.endpoint) }, body });
          if (r.status === 404 || r.status === 410) await fetch(`${SB}/rest/v1/push_subs?id=eq.${s.id}`, { method: 'DELETE', headers: H });
          else if (r.ok) sent++;
        } catch (e) { /* ignore */ }
      }
      return sent;
    };
    let sent = await send(ids, false, { title: T[0], body: `${d.title || 'Account deal'} · ${T[1]}`, url: '/?deals=1', tag: 'deal-' + id });
    if (turn.includes('admin')) sent += await send(admins, true, { title: '\u{1F3F7}️ Deal needs you', body: `#${id} ${d.title || ''}`, url: '/admin-panel/#sales', tag: 'deal-' + id });
    return json({ sent });
  } catch (e) { return json({ error: 'server' }, 500); }
}
