/**
 * kimi.com Reverse Proxy Worker
 * Routes traffic through Cloudflare's North American edge nodes
 * to bypass geo-blocking and reveal Google OAuth login option.
 * 
 * Deploy at: kimi-proxy.kingsley-w-m-curtis.workers.dev
 */

const UPSTREAM = "https://www.kimi.com";
const UPSTREAM_API = "https://api.moonshot.cn";

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  
  // Health check
  if (url.pathname === "/health") {
    return jsonResponse({ status: "ok", upstream: UPSTREAM });
  }
  
  // Determine target URL
  let targetUrl;
  if (url.pathname.startsWith("/api/")) {
    // API requests go to api.moonshot.cn
    targetUrl = UPSTREAM_API + url.pathname + url.search;
  } else {
    // Everything else goes to kimi.com
    targetUrl = UPSTREAM + url.pathname + url.search;
  }
  
  // Clone request with modifications
  const modifiedHeaders = new Headers(request.headers);
  modifiedHeaders.set("Host", "www.kimi.com");
  modifiedHeaders.delete("CF-Connecting-IP");
  modifiedHeaders.delete("CF-Visitor");
  modifiedHeaders.delete("CF-Ray");
  
  // Set North American locale headers
  modifiedHeaders.set("Accept-Language", "en-US,en;q=0.9");
  modifiedHeaders.set("CF-IPCountry", "US");
  
  try {
    const response = await fetch(targetUrl, {
      method: request.method,
      headers: modifiedHeaders,
      body: request.body,
      redirect: "manual",
    });
    
    // Create modified response
    const modifiedResponse = new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
    
    // Add CORS headers
    modifiedResponse.headers.set("Access-Control-Allow-Origin", "*");
    modifiedResponse.headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    modifiedResponse.headers.set("Access-Control-Allow-Headers", "*");
    
    // Remove security headers that might block embedding
    modifiedResponse.headers.delete("X-Frame-Options");
    modifiedResponse.headers.delete("Content-Security-Policy");
    
    return modifiedResponse;
    
  } catch (e) {
    return jsonResponse({ error: e.message, target: targetUrl }, 500);
  }
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
