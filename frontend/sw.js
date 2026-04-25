const CACHE_NAME = 'rlv-cidatt-v3';
const APP_SHELL = ['/', '/index.html', '/panel.html', '/app.webmanifest'];

function isHtmlRequest(request) {
  return request.mode === 'navigate' || request.destination === 'document';
}

async function networkFirst(request, fallbackUrl = '/index.html') {
  const cache = await caches.open(CACHE_NAME);
  try {
    const response = await fetch(request);
    if (response && response.ok) {
      await cache.put(request, response.clone());
    }
    return response;
  } catch (_error) {
    const cached = await cache.match(request);
    if (cached) return cached;
    return cache.match(fallbackUrl);
  }
}

async function staleWhileRevalidate(request) {
  const cache = await caches.open(CACHE_NAME);
  const cached = await cache.match(request);
  const networkPromise = fetch(request)
    .then((response) => {
      if (response && response.ok) cache.put(request, response.clone());
      return response;
    })
    .catch(() => null);

  if (cached) return cached;
  const network = await networkPromise;
  return network || Response.error();
}

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL))
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  if (url.pathname.startsWith('/api/')) {
    event.respondWith(fetch(event.request));
    return;
  }

  if (isHtmlRequest(event.request) || APP_SHELL.includes(url.pathname)) {
    event.respondWith(networkFirst(event.request, '/index.html'));
    return;
  }

  event.respondWith(staleWhileRevalidate(event.request));
});
