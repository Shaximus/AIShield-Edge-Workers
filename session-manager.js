
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

const SESSION_TTL = 21600;
const CF_EMAIL = "Kingsley.w.m.curtis@gmail.com";
const CF_KEY = "REDACTED_API_KEY_FOR_GITHUB";
const ACCOUNT = "929a618e8151ad00591bbf3a321008a7";
const KV_NS = "d27a01d4212d4a1db0c16eaa6753c016";

async function kvPut(key, value, ttl) {
  const url = "https://api.cloudflare.com/client/v4/accounts/" + ACCOUNT + "/storage/kv/namespaces/" + KV_NS + "/values/" + encodeURIComponent("session:" + key);
  await fetch(url, {
    method: "PUT",
    headers: { "X-Auth-Email": CF_EMAIL, "X-Auth-Key": CF_KEY, "Content-Type": "application/json" },
    body: value
  });
}

async function kvGet(key) {
  const url = "https://api.cloudflare.com/client/v4/accounts/" + ACCOUNT + "/storage/kv/namespaces/" + KV_NS + "/values/" + encodeURIComponent("session:" + key);
  const resp = await fetch(url, { headers: { "X-Auth-Email": CF_EMAIL, "X-Auth-Key": CF_KEY } });
  if (!resp.ok) return null;
  return await resp.text();
}

async function handleRequest(request) {
  const url = new URL(request.url);
  const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json"
  };
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

  try {
    if (url.pathname === "/session/create" && request.method === "POST") {
      return createSession(request, cors);
    }
    if (url.pathname.match(/^\/session\/[^\/]+\/touch$/) && request.method === "POST") {
      return touchSession(url.pathname.split("/")[2], cors);
    }
    if (url.pathname.match(/^\/session\/[^\/]+\/status$/) && request.method === "GET") {
      return getStatus(url.pathname.split("/")[2], cors);
    }
    if (url.pathname.match(/^\/session\/[^\/]+\/save$/) && request.method === "POST") {
      return saveSession(url.pathname.split("/")[2], request, cors);
    }
    if (url.pathname.match(/^\/session\/[^\/]+$/) && request.method === "GET") {
      return getSession(url.pathname.split("/")[2], cors);
    }
    return json({ error: "Not found", endpoints: ["/session/create","/session/{id}","/session/{id}/touch","/session/{id}/status","/session/{id}/save"] }, 404, cors);
  } catch (e) {
    return json({ error: e.message }, 500, cors);
  }
}

async function createSession(request, cors) {
  const body = await request.json().catch(() => ({}));
  const sid = "rs-" + Array.from({length: 16}, () => "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"[Math.floor(Math.random() * 58)]).join("");
  const now = Math.floor(Date.now() / 1000);
  const session = {
    id: sid, created_at: now, last_touched: now, expires_at: now + SESSION_TTL,
    agent: body.agent || "kimi-swarm",
    build_state: { tools_installed: false, project_validated: false, build_status: "idle", last_build_apk: null, build_errors: [], build_count: 0 },
    config: { min_sdk: 26, target_sdk: 34, gradle_version: "8.5", kotlin_version: "1.9.22" }
  };
  await kvPut(sid, JSON.stringify(session));
  return json({
    success: true, session_id: sid, expires_in: SESSION_TTL, expires_human: "6 hours",
    setup_command: "curl -sL https://build-cache.reflexionsoftware.com/setup | bash",
    build_command: "curl -X POST https://reflexionsoftware.com/build/validate -F \"file=@project.zip\"",
    touch_command: "curl -X POST https://sessions.reflexionsoftware.com/session/" + sid + "/touch"
  }, 200, cors);
}

async function touchSession(sid, cors) {
  const data = await kvGet(sid);
  if (!data) return json({ error: "Session not found" }, 404, cors);
  const s = JSON.parse(data);
  const now = Math.floor(Date.now() / 1000);
  s.last_touched = now; s.expires_at = now + SESSION_TTL;
  await kvPut(sid, JSON.stringify(s));
  return json({ success: true, session_id: sid, expires_in: SESSION_TTL, expires_human: "6 hours from now" }, 200, cors);
}

async function getSession(sid, cors) {
  const data = await kvGet(sid);
  if (!data) return json({ error: "Session not found or expired" }, 404, cors);
  // Refresh TTL on read
  await kvPut(sid, data);
  const s = JSON.parse(data);
  const rem = s.expires_at - Math.floor(Date.now() / 1000);
  return json({ ...s, remaining_seconds: rem, remaining_human: rem < 60 ? rem + "s" : rem < 3600 ? Math.floor(rem/60) + "m" : Math.floor(rem/3600) + "h " + Math.floor((rem%3600)/60) + "m" }, 200, cors);
}

async function getStatus(sid, cors) {
  const data = await kvGet(sid);
  if (!data) return json({ status: "expired", message: "Create new session at POST /session/create" }, 200, cors);
  const s = JSON.parse(data);
  const rem = s.expires_at - Math.floor(Date.now() / 1000);
  return json({
    status: rem > 0 ? "active" : "expired", session_id: sid,
    build_status: s.build_state.build_status,
    tools_installed: s.build_state.tools_installed,
    build_count: s.build_state.build_count,
    remaining_seconds: rem, remaining_human: rem < 60 ? rem + "s" : rem < 3600 ? Math.floor(rem/60) + "m" : Math.floor(rem/3600) + "h " + Math.floor((rem%3600)/60) + "m",
    setup_command: "curl -sL https://build-cache.reflexionsoftware.com/setup | bash",
    touch_command: "curl -X POST https://sessions.reflexionsoftware.com/session/" + sid + "/touch"
  }, 200, cors);
}

async function saveSession(sid, request, cors) {
  const data = await kvGet(sid);
  if (!data) return json({ error: "Session not found" }, 404, cors);
  const body = await request.json();
  const s = JSON.parse(data);
  if (body.build_state) Object.assign(s.build_state, body.build_state);
  await kvPut(sid, JSON.stringify(s));
  return json({ success: true, saved: Object.keys(body) }, 200, cors);
}

function json(d, status, cors) { return new Response(JSON.stringify(d, null, 2), { status, headers: cors }); }
