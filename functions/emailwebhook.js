// POST /emailwebhook?key=SECRET
// An email-forwarding automation (e.g. IFTTT/Gmail filter, or a phone forwarder app) sends the
// text of Konami's verification-code email here. We read the 6-digit code and drop it straight
// onto whichever order is currently waiting for one — the same instant-popup the admin app
// already shows for a code entered by a customer.

function readCode(text) {
  // "526918 is the verification code for Samuel." / "verification code: 526918" / standalone 6 digits
  let m = text.match(/\b(\d{6})\b\s+is the verification code/i);
  if (!m) m = text.match(/verification code[^0-9]{0,20}(\d{6})\b/i);
  if (!m) m = text.match(/\b(\d{6})\b/);
  return m ? m[1] : '';
}

export async function onRequest({ request, env }) {
  const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json' } });
  try {
    const url = new URL(request.url);
    if (!env.WEBHOOK_SECRET || url.searchParams.get('key') !== env.WEBHOOK_SECRET) return json({ error: 'auth' }, 401);

    let b = {};
    if (request.method === 'POST') {
      const raw = await request.text();
      try { b = JSON.parse(raw); } catch (e) { b = Object.fromEntries(new URLSearchParams(raw)); }
    }
    for (const [k, v] of url.searchParams) if (k !== 'key' && !(k in b)) b[k] = v;
    const pick = (...ks) => { for (const k of ks) if (b[k] != null && String(b[k]).trim()) return String(b[k]); return ''; };
    // The notification title (often the sender name, e.g. "Konami") is joined with the body text,
    // so the Konami check still passes when only the title carries the sender name.
    const title = pick('title', 'subject', 'sender', 'from');
    const body = pick('text', 'body', 'content', 'message', 'subject_and_body');
    const text = (title + ' ' + body).trim().slice(0, 4000);
    if (!body) return json({ ignored: 'empty' });
    if (!/konami/i.test(text)) return json({ ignored: 'not a Konami email' });

    const code = readCode(text);
    if (!code) return json({ ignored: 'no 6-digit code found' });

    const SB = env.SUPABASE_URL, K = env.SUPABASE_SERVICE_KEY;
    const H = { apikey: K, Authorization: 'Bearer ' + K, 'content-type': 'application/json' };

    // Pick the order currently waiting for a code: approved, a code was requested, none entered yet.
    const waiting = await (await fetch(
      `${SB}/rest/v1/orders?status=eq.approved&code_req=eq.true&kcode=is.null&select=id&order=id.desc&limit=1`,
      { headers: H }
    )).json();
    const order = Array.isArray(waiting) && waiting[0];
    if (!order) return json({ ignored: 'no order is waiting for a code right now', code_seen: code });

    const upd = await fetch(`${SB}/rest/v1/orders?id=eq.${order.id}`, {
      method: 'PATCH', headers: { ...H, Prefer: 'return=minimal' },
      body: JSON.stringify({ kcode: code }),
    });
    if (!upd.ok) return json({ error: 'db' }, 500);
    return json({ applied: true, order_id: order.id, code });
  } catch (e) {
    return json({ error: 'server' }, 500);
  }
}
