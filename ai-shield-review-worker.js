// AI Shield Rules + Stats Worker
// Security hardened: CORS whitelist, error sanitization, rate limiting, key format validation
// Returns rules ONLY with valid license - extension is useless without this
// Verifies licenses directly from LICENSES KV (no worker-to-worker fetch)

// RULES ARE INJECTED AT BUILD TIME FROM rules/blocklist.json
// Run: bash build.sh (or bash sync-rules.sh) to update
// DO NOT edit rules here - edit blocklist.json instead
const FULL_RULES = [
  { id: 2, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*honeycomb.io*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"]} },
  { id: 3, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*segment.io*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 4, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*segment.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 5, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*cloudflareinsights*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"]} },
  { id: 6, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*rum.cloudflare.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 7, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*amplitude.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 8, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*mixpanel.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 9, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*posthog.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 10, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*intercom.io*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 11, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*google-analytics.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"]} },
  { id: 12, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*googletagmanager.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 13, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*doubleclick.net*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 14, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*googlesyndication.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 18, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*featuregates.org*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 19, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*featureassets.org*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 20, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*assetsconfigcdn.org*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 21, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*prodregistryv2.org*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 22, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*nel.cloudflare.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 23, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*datadoghq.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 31, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*facebook.com/tr/*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping", "image"]} },
  { id: 32, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*facebook.com/browser_reporting/*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 34, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*widget.intercom.io*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 54, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*static.cloudflareinsights.com*", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 60, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*gtag/js*", "resourceTypes": ["script"]} },
  { id: 61, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*gtm.js*", "resourceTypes": ["script"]} },
  { id: 62, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*mapbox*eventData*", "resourceTypes": ["xmlhttprequest", "other"]} },
  { id: 69, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*sentry.io*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"]} },
  { id: 71, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*launchdarkly.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 72, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*growthbook.io*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 73, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*fullstory.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 74, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*hotjar.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 75, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*logrocket.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 76, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*clarity.ms*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 77, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*newrelic.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 78, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*bugsnag.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 79, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*rollbar.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 80, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*heapanalytics.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 81, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*pendo.io*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 82, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*smartlook.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 83, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*mouseflow.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 84, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*crazyegg.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 85, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*inspectlet.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 86, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*optimizely.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 87, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*vwo.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 90, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*log-sdk*", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 91, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*beacon.min.js*", "resourceTypes": ["script"]} },
  { id: 92, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*mapbox.com/events*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 93, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*split.io*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 94, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*appsflyer.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 95, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*branch.io*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 96, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*adjust.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 97, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*singular.net*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 98, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*kochava.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 99, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*onesignal.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 100, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*braze.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 111, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*__mpq_*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 113, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*www.googletagmanager.com/*", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 114, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*google.com/gtag/*", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 115, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*googletagservices.com*", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 116, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*tagmanager.google.com*", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 123, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*ingest.*.sentry.io*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 133, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*easylist-downloads.adblockplus.org*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 212, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*adnexus.net*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 213, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*bidtellect.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 214, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*zenlayer.net*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 215, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*casalemedia.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 216, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*outbrain.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 217, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*adsafeprotected.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 218, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*adnxs.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 219, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*xandr.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 220, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*mopub.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 221, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*amazon-adsystem.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 222, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*adsystem.amazon.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 223, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*rubiconproject.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 224, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*openx.net*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 225, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*pubmatic.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 306, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||static.xx.fbcdn.net", "resourceTypes": ["image", "script"]} },
  { id: 308, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||l.facebook.com/l.php", "resourceTypes": ["main_frame", "sub_frame"]} },
  { id: 310, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||snippet.maze.co", "resourceTypes": ["script"]} },
  { id: 311, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||app.maze.co", "resourceTypes": ["script", "xmlhttprequest"]} },
  { id: 312, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||api.maze.co", "resourceTypes": ["xmlhttprequest"]} },
  { id: 313, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||datadoghq.com", "resourceTypes": ["script", "xmlhttprequest", "ping", "other"]} },
  { id: 314, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||browser-intake-datadoghq.com", "resourceTypes": ["xmlhttprequest", "ping", "other"]} },
  { id: 315, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||widget.intercom.io", "resourceTypes": ["script", "xmlhttprequest", "sub_frame", "other"]} },
  { id: 316, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||api-iam.intercom.io", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 317, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||intercomassets.com", "resourceTypes": ["script", "image", "font", "other"]} },
  { id: 318, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||qualtrics.com", "resourceTypes": ["sub_frame", "script", "xmlhttprequest", "image", "other"]} },
  { id: 319, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||siteintercept.qualtrics.com", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 320, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||pendo.io", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 321, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||mcp.amplitude.com", "resourceTypes": ["xmlhttprequest"]} },
  { id: 323, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||api.segment.io", "resourceTypes": ["xmlhttprequest", "ping", "other"]} },
  { id: 324, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||cdn.segment.com", "resourceTypes": ["script"]} },
  { id: 325, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||api.segment.io/v1/identify", "resourceTypes": ["xmlhttprequest", "ping", "other"]} },
  { id: 326, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||api.segment.io/v1/track", "resourceTypes": ["xmlhttprequest", "ping", "other"]} },
  { id: 327, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||api.segment.io/v1/page", "resourceTypes": ["xmlhttprequest", "ping", "other"]} },
  { id: 328, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||featuregates.org", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 329, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||statsigapi.net", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 330, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||api.statsig.com", "resourceTypes": ["xmlhttprequest", "other"]} },
  { id: 331, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||cdn.growthbook.io", "resourceTypes": ["script", "xmlhttprequest"]} },
  { id: 332, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||growthbook.io/api", "resourceTypes": ["xmlhttprequest", "script"]} },
  { id: 350, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||googletagmanager.com/gtm.js", "resourceTypes": ["script"]} },
  { id: 403, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||castle.io", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"]} },
  { id: 404, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*castle.io/v1/risk*", "resourceTypes": ["xmlhttprequest", "other"]} },
  { id: 405, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*socure.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"]} },
  { id: 406, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*devicer.socure.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 411, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*googlesyndication.com*", "resourceTypes": ["xmlhttprequest", "script", "sub_frame", "image", "other"]} },
  { id: 412, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*doubleclick.net*", "resourceTypes": ["xmlhttprequest", "script", "sub_frame", "image", "other", "ping"]} }
];

function generateCanaryRules(licenseKey) {
  let hash = 5381;
  for (let i = 0; i < licenseKey.length; i++) {
    hash = ((hash << 5) + hash) + licenseKey.charCodeAt(i);
    hash = hash & 0x7FFFFFFF;
  }

  const canaries = [];
  for (let i = 0; i < 3; i++) {
    const canaryHash = ((hash * (i + 7)) & 0x7FFFFFFF).toString(36);
    canaries.push({
      id: 9000 + i,
      priority: 1,
      action: { type: "block" },
      condition: {
        urlFilter: `||canary-${canaryHash}.reflexionsoftware.com`,
        resourceTypes: ["xmlhttprequest"]
      }
    });
  }

  return canaries;
}

async function encryptRules(rules, licenseKey, ruleSalt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(licenseKey + ruleSalt),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode("ai-shield-rules-v1"),
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(JSON.stringify(rules))
  );

  return {
    payload: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    iv: btoa(String.fromCharCode(...iv)),
    version: "2.0"
  };
}

const ALLOWED_ORIGINS = [
  'https://reflexionsoftware.com',
  'https://www.reflexionsoftware.com',
  'https://reflexionsoftware.pages.dev',
  'https://api.reflexionsoftware.com'
];

const LICENSE_KEY_FORMAT = /^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$/;

const RATE_LIMIT = 30;

function getCorsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  const isAllowed = ALLOWED_ORIGINS.includes(origin) ||
    origin.endsWith('.reflexionsoftware.pages.dev') ||
    origin.startsWith('chrome-extension://') ||
    origin.startsWith('moz-extension://');
  return {
    "Access-Control-Allow-Origin": isAllowed ? origin : ALLOWED_ORIGINS[0],
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-License-Key, X-Extension-ID, X-Timestamp, X-Signature",
    "Content-Type": "application/json",
    "Vary": "Origin"
  };
}

function errorResponse(corsHeaders, status, userMessage) {
  return new Response(JSON.stringify({ error: userMessage }), {
    status, headers: corsHeaders
  });
}

async function checkRateLimit(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const minute = Math.floor(Date.now() / 60000);
  const key = `rl:${ip}:${minute}`;

  const current = parseInt(await env.AI_SHIELD_DATA.get(key)) || 0;
  if (current >= RATE_LIMIT) return false;

  await env.AI_SHIELD_DATA.put(key, String(current + 1), { expirationTtl: 120 });
  return true;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const corsHeaders = getCorsHeaders(request);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (!await checkRateLimit(request, env)) {
      return errorResponse(corsHeaders, 429, "Too many requests. Please try again later.");
    }

    // === RULES ENDPOINT - REQUIRES VALID LICENSE ===
    if ((url.pathname === "/rules" || url.pathname === "/") && (request.method === "GET" || request.method === "POST")) {
      const licenseKey = request.headers.get("X-License-Key");

      if (!licenseKey) {
        return errorResponse(corsHeaders, 401, "License required");
      }

      if (!LICENSE_KEY_FORMAT.test(licenseKey)) {
        return errorResponse(corsHeaders, 401, "Invalid license key");
      }

      try {
        const license = await env.LICENSES.get(licenseKey, "json");

        if (!license) {
          return errorResponse(corsHeaders, 403, "License key not found");
        }

        const now = Date.now();
        if (license.type !== "lifetime" && license.expiresAt && license.expiresAt < now) {
          return new Response(JSON.stringify({
            error: "License expired",
            renewUrl: "https://reflexionsoftware.com/#pricing"
          }), { status: 402, headers: corsHeaders });
        }

        const ruleSalt = license.ruleSalt;
        if (!ruleSalt) {
          return new Response(JSON.stringify({ error: "Please verify license first", code: "VERIFY_FIRST" }), { status: 403, headers: corsHeaders });
        }

        const canaries = generateCanaryRules(licenseKey);
        const watermarkedRules = [...FULL_RULES, ...canaries];
        const encrypted = await encryptRules(watermarkedRules, licenseKey, ruleSalt);
        // Store canary mapping for leak detection
        for (const canary of canaries) {
          const domain = canary.condition.urlFilter.replace('||', '');
          await env.AI_SHIELD_DATA.put(`canary:${domain}`, licenseKey, { expirationTtl: 86400 * 365 });
        }
        return new Response(JSON.stringify({
          ...encrypted,
          rulesCount: watermarkedRules.length,
          lastUpdated: new Date().toISOString(),
          licenseType: license.type
        }), { headers: corsHeaders });

      } catch (error) {
        console.error("Rules error:", error);
        return errorResponse(corsHeaders, 500, "License verification failed");
      }
    }

    // === PUBLIC: Get live stats for website ===
    if (url.pathname === "/live-stats" && request.method === "GET") {
      try {
        const statsJson = await env.AI_SHIELD_DATA.get("global_stats");
        const stats = statsJson ? JSON.parse(statsJson) : {
          totalBlocks: 0,
          activeUsers: 0,
          hourlyBlocks: 0,
          platforms: {}
        };

        const activeCountJson = await env.AI_SHIELD_DATA.get("active_users_count");
        stats.activeUsers = activeCountJson ? parseInt(activeCountJson) : 0;

        const lifetimeRemaining = await env.AI_SHIELD_DATA.get("lifetime_slots_remaining");
        stats.lifetimeRemaining = lifetimeRemaining ? parseInt(lifetimeRemaining) : 1000;
        stats.rulesCount = FULL_RULES.length;

        return new Response(JSON.stringify(stats), { headers: corsHeaders });
      } catch (error) {
        console.error("Stats error:", error);
        return new Response(JSON.stringify({
          totalBlocks: 0, activeUsers: 0
        }), { headers: corsHeaders });
      }
    }

    // === PUBLIC: Get lifetime slots remaining ===
    if (url.pathname === "/lifetime-remaining" && request.method === "GET") {
      const remaining = await env.AI_SHIELD_DATA.get("lifetime_slots_remaining");
      return new Response(JSON.stringify({
        remaining: remaining ? parseInt(remaining) : 1000,
        total: 1000
      }), { headers: corsHeaders });
    }

    // === EXTENSION: Report stats ===
    if (url.pathname === "/report-stats" && request.method === "POST") {
      try {
        // Require valid license key for stats reporting
        const statsLicenseKey = request.headers.get("X-License-Key");
        if (!statsLicenseKey) {
          return errorResponse(corsHeaders, 401, "License key required");
        }
        const statsLicense = await env.LICENSES.get(`license:${statsLicenseKey}`);
        if (!statsLicense) {
          return errorResponse(corsHeaders, 401, "Invalid license key");
        }

        const body = await request.json();

        if (!body.extensionId || typeof body.extensionId !== 'string' || body.extensionId.length > 40) {
          return errorResponse(corsHeaders, 400, "Invalid extension ID");
        }

        if (body.stats && typeof body.stats.totalBlocked === 'number') {
          body.stats.totalBlocked = Math.min(body.stats.totalBlocked, 10000);
        }

        const { extensionId, stats: extStats } = body;

        if (!extensionId || !extStats) {
          return errorResponse(corsHeaders, 400, "Missing data");
        }

        const extKey = `ext_stats_${extensionId}`;
        await env.AI_SHIELD_DATA.put(extKey, JSON.stringify({
          ...extStats,
          lastReport: Date.now()
        }), { expirationTtl: 90000 });

        await updateGlobalStats(env, extStats);
        await trackActiveUser(env, extensionId);

        return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
      } catch (error) {
        console.error("Report stats error:", error);
        return errorResponse(corsHeaders, 500, "Stats reporting failed");
      }
    }

    // === ADMIN: Set lifetime slots ===
    if (url.pathname === "/admin/set-slots" && request.method === "POST") {
      const authKey = request.headers.get("X-Admin-Key");
      if (!env.ADMIN_KEY || !authKey || authKey !== env.ADMIN_KEY) {
        return errorResponse(corsHeaders, 401, "Unauthorized");
      }

      const body = await request.json();
      await env.AI_SHIELD_DATA.put("lifetime_slots_remaining", body.slots.toString());
      return new Response(JSON.stringify({ success: true, slots: body.slots }), { headers: corsHeaders });
    }

    return errorResponse(corsHeaders, 404, "Not found");
  }
};

async function updateGlobalStats(env, extStats) {
  const statsJson = await env.AI_SHIELD_DATA.get("global_stats");
  let globalStats = statsJson ? JSON.parse(statsJson) : {
    totalBlocks: 0,
    hourlyBlocks: 0,
    platforms: {},
    lastHourReset: Date.now()
  };

  const blocksToAdd = extStats.totalBlocked || 0;
  globalStats.totalBlocks += blocksToAdd;
  globalStats.hourlyBlocks += blocksToAdd;

  if (Date.now() - globalStats.lastHourReset > 3600000) {
    globalStats.hourlyBlocks = blocksToAdd;
    globalStats.lastHourReset = Date.now();
  }

  if (extStats.blockedByDomain) {
    for (const [tracker, count] of Object.entries(extStats.blockedByDomain)) {
      const platform = trackerToPlatform(tracker);
      if (!globalStats.platforms[platform]) globalStats.platforms[platform] = 0;
      globalStats.platforms[platform] += count;
    }
  }

  await env.AI_SHIELD_DATA.put("global_stats", JSON.stringify(globalStats));
}

async function trackActiveUser(env, extensionId) {
  const activeKey = `active_${extensionId}`;
  const existing = await env.AI_SHIELD_DATA.get(activeKey);

  if (!existing) {
    const countJson = await env.AI_SHIELD_DATA.get("active_users_count");
    const count = countJson ? parseInt(countJson) : 0;
    await env.AI_SHIELD_DATA.put("active_users_count", (count + 1).toString());
  }

  await env.AI_SHIELD_DATA.put(activeKey, Date.now().toString(), { expirationTtl: 86400 });
}

function trackerToPlatform(tracker) {
  const mapping = {
    'Anthropic': 'claude', 'Segment': 'claude', 'Claude': 'claude',
    'OpenAI': 'chatgpt', 'Datadog': 'chatgpt', 'ChatGPT': 'chatgpt', 'CES': 'chatgpt',
    'xAI': 'grok', 'Statsig': 'grok', 'Honeycomb': 'grok', 'Grok': 'grok',
    'Google': 'gemini', 'Gemini': 'gemini',
    'Meta': 'meta', 'Facebook': 'meta',
    'ByteDance': 'deepseek', 'Moonshot': 'deepseek', 'Kimi': 'deepseek', 'Volc': 'deepseek',
    'Baidu': 'other', 'Tencent': 'other', 'NetEase': 'other', 'WeChat': 'other'
  };
  for (const [key, platform] of Object.entries(mapping)) {
    if (tracker.includes(key)) return platform;
  }
  return 'other';
}
