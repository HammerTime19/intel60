// Offline support: the app shell is cached; stories load fresh and fall back to the last copy.
const SHELL = "intel60-shell-v7";
const ASSETS = ["./", "./index.html", "./manifest.json", "./icons/icon-192.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(SHELL).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== SHELL && k !== "intel60-data").map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET") return;
  // other sites (like the visit counter) go straight to the network; only Google Fonts is cached for offline use
  if (url.origin !== self.location.origin && !/^fonts\.(googleapis|gstatic)\.com$/.test(url.hostname)) return;

  const data = url.pathname.match(/\/(cards|deadlines)\.json$/);
  if (data) {
    // network first, so stories and deadlines are always current when online
    const key = `${data[1]}.json`;
    e.respondWith(
      fetch(e.request).then((res) => {
        const copy = res.clone();
        caches.open("intel60-data").then((c) => c.put(key, copy));
        return res;
      }).catch(() => caches.open("intel60-data").then((c) => c.match(key)).then((hit) => hit &&
        // marked as a saved copy, so the page doesn't call it live
        new Response(hit.body, { headers: { "Content-Type": "application/json", "X-Intel60-Saved": "1" } })))
    );
    return;
  }

  // the page itself: network first, so design updates show up without reinstalling.
  // "no-cache" makes the browser check with the server instead of reusing its own copy (GitHub Pages allows 10 minutes)
  if (e.request.mode === "navigate" || url.pathname.endsWith("/index.html")) {
    e.respondWith(
      fetch(e.request.url, { cache: "no-cache", credentials: "same-origin" }).then((res) => {
        if (res.ok) {
          const copy = res.clone();
          caches.open(SHELL).then((c) => c.put(e.request, copy));  // each page cached under its own URL
        }
        return res;
      }).catch(() => caches.match(e.request).then((hit) => hit || caches.match("./")))
    );
    return;
  }

  // everything else (icons, fonts): cache first, then network
  e.respondWith(
    caches.match(e.request).then((hit) => hit || fetch(e.request).then((res) => {
      if (res.ok || res.type === "opaque") {
        const copy = res.clone();
        caches.open(SHELL).then((c) => c.put(e.request, copy));
      }
      return res;
    }))
  );
});
