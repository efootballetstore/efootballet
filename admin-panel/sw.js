// eFootballET ADMIN service worker: live site + push notifications
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', (e) => {
  if (e.request.mode !== 'navigate') return;
  e.respondWith(fetch(e.request).catch(() => new Response(
    '<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><body style="margin:0;display:grid;place-items:center;height:100vh;background:#120d2e;color:#ecedf3;font-family:system-ui;text-align:center"><div><h2>eFootballET ADMIN</h2><p>No internet connection.</p></div>',
    { headers: { 'content-type': 'text/html; charset=utf-8' } })));
});
self.addEventListener('push', (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (x) { d = {}; }
  e.waitUntil(self.registration.showNotification(d.title || 'eFootballET ADMIN', {
    body: d.body || '\u{1F4AC} New customer message',
    icon: '/admin-panel/icon-512.png', badge: '/admin-panel/badge-512.png',
    tag: d.tag || 'admin-panel', renotify: true, data: { url: d.url || '/admin-panel/#msgs' } }));
});
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || '/admin-panel/';
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
    for (const c of list) { if (c.url.includes('/admin-panel/') && 'focus' in c) { c.navigate(url); return c.focus(); } }
    return self.clients.openWindow(url);
  }));
});
