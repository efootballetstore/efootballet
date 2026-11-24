// POST /notifyadmin  { type: 'order' | 'ready' | 'receipt', ref: <order code> }
// (Authorization: Bearer <customer access token>)
// Tells the admin app that something happened, with a real text (encrypted web-push payload).
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb = (s) => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); };
const enc = new TextEncoder();
const cat = (...a) => { const n = a.reduce((t, x) => t + x.length, 0); const o = new Uint8Array(n); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };

async function vapidAuth(env, endpoint) {
  const aud = new URL(endpoint).origin;
  const h = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const p = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 43200, sub: 'mailto:samisanta7990@gmail.com' })));
  const key = await crypto.subtle.importKey('jwk', JSON.parse(env.VAPID_PRIVATE_JWK), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(h + '.' + p));
  return `vapid t=${h}.${p}.${b64u(sig)}, k=${env.VAPID_PUBLIC}`;
}

// RFC 8291 (aes128gcm) payload encryption
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
    const SB = env.SUPABASE_URL, K = env.SUPABASE_SERVICE_KEY;
    const H = { apikey: K, Authorization: 'Bearer ' + K, 'content-type': 'application/json' };
    const u = await fetch(`${SB}/auth/v1/user`, { headers: { apikey: K, Authorization: request.headers.get('authorization') || '' } });
    if (!u.ok) return json({ error: 'auth' }, 401);
    const uid = (await u.json()).id;
    const { type, ref } = await request.json();
    if (!['order', 'ready', 'receipt', 'code'].includes(type) || !/^[A-Za-z0-9]{4,20}$/.test(String(ref || ''))) return json({ error: 'bad' }, 400);
    const os = await (await fetch(`${SB}/rest/v1/orders?code=eq.${encodeURIComponent(ref)}&user_id=eq.${uid}&select=code,amount,package,product,created_at`, { headers: H })).json();
    const o = Array.isArray(os) && os[0];
    if (!o) return json({ error: 'order' }, 403);
    if (Date.now() - new Date(o.created_at).getTime() > 3 * 3600 * 1000 && type === 'order') return json({ skipped: 'old' });
    // one notification per order + type
    const dd = await fetch(`${SB}/rest/v1/admin_notified`, { method: 'POST', headers: { ...H, Prefer: 'return=representation,resolution=ignore-duplicates' }, body: JSON.stringify({ k: `${type}:${o.code}` }) });
    const ins = await dd.json();
    if (!Array.isArray(ins) || !ins.length) return json({ skipped: 'dup' });

    const what = `${o.package || o.product || 'Order'} · ${o.amount} ETB`;
    const msg = {
      order: { title: '🛒 New order', body: what, url: '/sam-admin/#orders' },
      receipt: { title: '🧾 Receipt sent', body: what, url: '/sam-admin/#orders' },
      ready: { title: '🟢 Customer is ready', body: `${what} · ask for the code now`, url: '/sam-admin/#orders' },
      code: { title: '🔑 Code submitted', body: `${what} · open now, it expires fast`, url: '/sam-admin/#orders' },
    }[type];
    const text = JSON.stringify(msg);

    const ad = await (await fetch(`${SB}/rest/v1/admins?select=user_id`, { headers: H })).json();
    const ids = (Array.isArray(ad) ? ad : []).map((a) => a.user_id).filter((x) => x && x !== uid);
    if (!ids.length) return json({ sent: 0, why: 'no-admins' });
    let subs = await (await fetch(`${SB}/rest/v1/push_subs?user_id=in.(${ids.join(',')})&select=id,endpoint,p256dh,auth,app`, { headers: H })).json();
    subs = Array.isArray(subs) ? subs : [];
    const apps = subs.filter((s) => s.app === 'admin');
    const use = apps.length ? apps : subs;
    let sent = 0; const st = [];
    for (const s of use) {
      try {
        const body = await encryptPayload(s.p256dh, s.auth, text);
        const r = await fetch(s.endpoint, { method: 'POST', headers: { TTL: '3600', Urgency: 'high', 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', Authorization: await vapidAuth(env, s.endpoint) }, body });
        st.push(r.status);
        if (r.status === 404 || r.status === 410) await fetch(`${SB}/rest/v1/push_subs?id=eq.${s.id}`, { method: 'DELETE', headers: H });
        else if (r.ok) sent++;
      } catch (e) { st.push('err'); }
    }
    return json({ sent, st });
  } catch (e) { return json({ error: 'server' }, 500); }
}
