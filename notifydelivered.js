// POST /notifydelivered  { id }  -- called by a Postgres trigger (server-to-server), not by the browser.
// Tells the customer their order is delivered: by Telegram if they've linked it (tg_links),
// and/or by web push if they turned notifications on (push_subs). No email access of any kind.
export async function onRequestPost({ request, env }) {
  const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json' } });
  try {
    if (!env.NOTIFY_SECRET || request.headers.get('x-notify-secret') !== env.NOTIFY_SECRET) return json({ error: 'forbidden' }, 403);
    const SB = env.SUPABASE_URL, K = env.SUPABASE_SERVICE_KEY;
    const H = { apikey: K, Authorization: 'Bearer ' + K, 'content-type': 'application/json' };
    const { id } = await request.json();
    if (!id) return json({ error: 'bad' }, 400);

    const os = await (await fetch(`${SB}/rest/v1/orders?id=eq.${Number(id)}&select=id,code,user_id,product,package,amount,status`, { headers: H })).json();
    const o = Array.isArray(os) && os[0];
    if (!o || o.status !== 'delivered') return json({ skipped: 'not-delivered' });

    // one notification per order (safe if the trigger fires more than once)
    const dd = await fetch(`${SB}/rest/v1/customer_notified`, { method: 'POST', headers: { ...H, Prefer: 'return=representation,resolution=ignore-duplicates' }, body: JSON.stringify({ k: `delivered:${o.code}` }) });
    const ins = await dd.json();
    if (!Array.isArray(ins) || !ins.length) return json({ skipped: 'dup' });

    const what = `${o.package || o.product || 'Order'} · ${o.amount} ETB`;
    const textEn = `✅ Delivered! Your order ${o.code} (${what}) has been completed. Thank you for shopping with eFootballET!`;
    const textAm = `✅ ትዕዛዝ ${o.code} (${what}) ደርሷል! ከeFootballET ስለገዙ እናመሰግናለን።`;
    let tg = 0, push = 0;

    if (o.user_id) {
      const lk = await (await fetch(`${SB}/rest/v1/tg_links?user_id=eq.${o.user_id}&select=tg_id`, { headers: H })).json();
      const tgId = Array.isArray(lk) && lk[0] && lk[0].tg_id;
      if (tgId && env.BOT_TOKEN) {
        const r = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ chat_id: tgId, text: `${textAm}\n\n${textEn}` }),
        });
        if (r.ok) tg = 1;
      }

      if (env.VAPID_PUBLIC && env.VAPID_PRIVATE_JWK) {
        let subs = await (await fetch(`${SB}/rest/v1/push_subs?user_id=eq.${o.user_id}&app=neq.admin&select=id,endpoint`, { headers: H })).json();
        subs = Array.isArray(subs) ? subs : [];
        for (const s of subs) {
          try {
            const aud = new URL(s.endpoint).origin;
            const enc = new TextEncoder();
            const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
            const h = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
            const p = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 43200, sub: 'mailto:samisanta7990@gmail.com' })));
            const key = await crypto.subtle.importKey('jwk', JSON.parse(env.VAPID_PRIVATE_JWK), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
            const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(h + '.' + p));
            const r2 = await fetch(s.endpoint, { method: 'POST', headers: { TTL: '86400', Urgency: 'high', Authorization: `vapid t=${h}.${p}.${b64u(sig)}, k=${env.VAPID_PUBLIC}`, 'Content-Length': '0' } });
            if (r2.ok) push++;
            else if (r2.status === 404 || r2.status === 410) await fetch(`${SB}/rest/v1/push_subs?id=eq.${s.id}`, { method: 'DELETE', headers: H });
          } catch (e) {}
        }
      }
    }
    return json({ tg, push });
  } catch (e) { return json({ error: 'server' }, 500); }
}
