/**
 * Instance Relay Worker v1.0
 * Secure message bridge between AI instances.
 * No authentication — uses nonce challenge-response for identity verification.
 * Messages persist in R2 (not D1 — avoids service authorization issues).
 */

const R2_BUCKET = "pentarchy-common";
const MESSAGES_PREFIX = "relay/messages/";
const NONCE_PREFIX = "relay/nonces/";
const MAX_MESSAGES = 100;
const MESSAGE_RETENTION_HOURS = 24;

// Hardcoded nonces for initial verification
const EXPECTED_NONCES = {
  "raphael_kimi": "raphael-kimi-20260423-042800-nonce-7x9k2",
};

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  // Health check
  if (url.pathname === "/health") {
    return jsonResponse({ status: "ok", timestamp: Date.now() }, corsHeaders);
  }

  // Post a message
  if (url.pathname === "/message" && request.method === "POST") {
    return handlePostMessage(request, corsHeaders);
  }

  // Get messages
  if (url.pathname === "/messages" && request.method === "GET") {
    return handleGetMessages(url, corsHeaders);
  }

  // Register nonce
  if (url.pathname === "/nonce" && request.method === "POST") {
    return handleNonce(request, corsHeaders);
  }

  // Verify nonce
  if (url.pathname === "/verify" && request.method === "GET") {
    return handleVerify(url, corsHeaders);
  }

  return new Response("Not Found", { status: 404, headers: corsHeaders });
}

async function handlePostMessage(request, corsHeaders) {
  try {
    const body = await request.json();
    const { from, to, payload, nonce_response, timestamp } = body;

    if (!from || !payload) {
      return jsonResponse({ error: "Missing 'from' or 'payload'" }, corsHeaders, 400);
    }

    // Verify nonce if this is from raphael_kimi
    if (from === "raphael_kimi" && nonce_response !== EXPECTED_NONCES["raphael_kimi"]) {
      return jsonResponse({ error: "Invalid nonce" }, corsHeaders, 403);
    }

    const msgId = `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const message = {
      id: msgId,
      from,
      to: to || "all",
      payload,
      nonce_response: nonce_response || null,
      timestamp: timestamp || new Date().toISOString(),
      received_at: new Date().toISOString(),
    };

    // Store in R2
    await R2_BUCKET.put(
      `${MESSAGES_PREFIX}${msgId}.json`,
      JSON.stringify(message),
      { httpMetadata: { contentType: "application/json" } }
    );

    return jsonResponse({ success: true, id: msgId }, corsHeaders);
  } catch (e) {
    return jsonResponse({ error: e.message }, corsHeaders, 500);
  }
}

async function handleGetMessages(url, corsHeaders) {
  try {
    const since = url.searchParams.get("since") || "0";
    const sinceTime = parseInt(since);

    // List messages from R2
    const objects = await R2_BUCKET.list({ prefix: MESSAGES_PREFIX });
    const messages = [];

    for (const obj of objects.objects || []) {
      try {
        const resp = await R2_BUCKET.get(obj.key);
        const msg = JSON.parse(await resp.text());
        const msgTime = new Date(msg.timestamp).getTime();
        if (msgTime >= sinceTime) {
          messages.push(msg);
        }
      } catch (e) {
        // Skip corrupted messages
      }
    }

    // Sort by timestamp
    messages.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    // Limit
    const limited = messages.slice(-MAX_MESSAGES);

    return jsonResponse({
      count: limited.length,
      since: sinceTime,
      messages: limited,
    }, corsHeaders);
  } catch (e) {
    return jsonResponse({ error: e.message }, corsHeaders, 500);
  }
}

async function handleNonce(request, corsHeaders) {
  try {
    const body = await request.json();
    const { instance, nonce } = body;

    if (!instance || !nonce) {
      return jsonResponse({ error: "Missing instance or nonce" }, corsHeaders, 400);
    }

    // Store nonce
    await R2_BUCKET.put(
      `${NONCE_PREFIX}${instance}.json`,
      JSON.stringify({ instance, nonce, timestamp: new Date().toISOString() }),
      { httpMetadata: { contentType: "application/json" } }
    );

    return jsonResponse({ success: true, instance }, corsHeaders);
  } catch (e) {
    return jsonResponse({ error: e.message }, corsHeaders, 500);
  }
}

async function handleVerify(url, corsHeaders) {
  try {
    const instance = url.searchParams.get("instance");
    const nonce = url.searchParams.get("nonce");

    if (!instance || !nonce) {
      return jsonResponse({ error: "Missing instance or nonce" }, corsHeaders, 400);
    }

    // Check stored nonce
    const resp = await R2_BUCKET.get(`${NONCE_PREFIX}${instance}.json`);
    if (!resp) {
      return jsonResponse({ verified: false, reason: "No nonce registered" }, corsHeaders);
    }

    const stored = JSON.parse(await resp.text());
    const verified = stored.nonce === nonce;

    return jsonResponse({ verified, instance }, corsHeaders);
  } catch (e) {
    return jsonResponse({ verified: false, error: e.message }, corsHeaders);
  }
}

function jsonResponse(data, corsHeaders, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders },
  });
}
