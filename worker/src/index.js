// Intel60 push subscriptions.
// The app saves a device's anonymous push subscription and alert choices here (/subscribe, /unsubscribe).
// The pipeline reads them to send alerts (/list) and removes dead ones (/remove), with ADMIN_TOKEN.
// Each subscription is one KV key (a hash of its endpoint), with everything in the key's metadata,
// so one list call returns up to 1,000 subscribers without extra reads.

const ORIGINS = ["https://intel60.app", "http://localhost:8773"];
const PUSH_HOSTS = [/(^|\.)googleapis\.com$/, /(^|\.)mozilla\.com$/, /(^|\.)push\.apple\.com$/, /(^|\.)notify\.windows\.com$/];
const TYPES = ["critical", "exploited", "vendors"];
const MAX_METADATA = 1024;  // KV limit per key

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const origin = req.headers.get("Origin") || "";
    const cors = ORIGINS.includes(origin)
      ? { "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type", "Vary": "Origin" }
      : {};
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    try {
      if (url.pathname === "/subscribe" && req.method === "POST") return json(await subscribe(await body(req), env), 200, cors);
      if (url.pathname === "/unsubscribe" && req.method === "POST") return json(await unsubscribe(await body(req), env), 200, cors);
      if (url.pathname === "/list" && req.method === "GET") return isAdmin(req, env) ? json(await list(env)) : json({ error: "unauthorized" }, 401);
      if (url.pathname === "/remove" && req.method === "POST") return isAdmin(req, env) ? json(await remove(await body(req), env)) : json({ error: "unauthorized" }, 401);
    } catch (err) {
      return json({ error: err.message }, 400, cors);
    }
    return json({ error: "not found" }, 404, cors);
  },
};

async function subscribe(data, env) {
  const sub = data.subscription || {};
  const endpoint = checkEndpoint(sub.endpoint);
  const keys = sub.keys || {};
  if (typeof keys.p256dh !== "string" || typeof keys.auth !== "string" || keys.p256dh.length > 200 || keys.auth.length > 50) {
    throw new Error("bad subscription keys");
  }
  const types = (Array.isArray(data.types) ? data.types : []).filter((t) => TYPES.includes(t));
  if (!types.length) throw new Error("pick at least one alert type");
  let vendors = types.includes("vendors") && Array.isArray(data.vendors)
    ? data.vendors.filter((v) => typeof v === "string").map((v) => v.trim().slice(0, 40)).filter((v) => v.length >= 2).slice(0, 20)
    : [];
  const meta = (v) => ({ e: endpoint, k: { p256dh: keys.p256dh, auth: keys.auth }, t: types, v, d: data.digest === true });
  while (vendors.length && JSON.stringify(meta(vendors)).length > MAX_METADATA) vendors = vendors.slice(0, -1);  // keep within the KV limit
  if (JSON.stringify(meta(vendors)).length > MAX_METADATA) throw new Error("subscription too large");
  await env.SUBS.put(await keyFor(endpoint), "", { metadata: meta(vendors) });
  return { ok: true, vendors: vendors.length };
}

async function unsubscribe(data, env) {
  await env.SUBS.delete(await keyFor(checkEndpoint(data.endpoint)));
  return { ok: true };
}

async function list(env) {
  const subs = [];
  let cursor;
  do {
    const page = await env.SUBS.list({ cursor });
    for (const k of page.keys) if (k.metadata) subs.push(k.metadata);
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return { subscriptions: subs };
}

async function remove(data, env) {
  const endpoints = (Array.isArray(data.endpoints) ? data.endpoints : []).filter((e) => typeof e === "string").slice(0, 500);
  for (const e of endpoints) await env.SUBS.delete(await keyFor(e));
  return { ok: true, removed: endpoints.length };
}

function checkEndpoint(endpoint) {
  let host;
  try {
    const u = new URL(endpoint);
    if (u.protocol !== "https:") throw new Error();
    host = u.hostname;
  } catch {
    throw new Error("bad endpoint");
  }
  if (endpoint.length > 600 || !PUSH_HOSTS.some((re) => re.test(host))) throw new Error("unknown push service");
  return endpoint;
}

function isAdmin(req, env) {
  const given = req.headers.get("Authorization") || "";
  const want = `Bearer ${env.ADMIN_TOKEN || ""}`;
  if (!env.ADMIN_TOKEN || given.length !== want.length) return false;
  let diff = 0;  // constant-time compare
  for (let i = 0; i < want.length; i++) diff |= given.charCodeAt(i) ^ want.charCodeAt(i);
  return diff === 0;
}

async function keyFor(endpoint) {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(endpoint));
  return "sub:" + [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function body(req) {
  const text = await req.text();
  if (text.length > 8000) throw new Error("request too large");
  try {
    return JSON.parse(text);
  } catch {
    throw new Error("bad JSON");
  }
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...headers } });
}
