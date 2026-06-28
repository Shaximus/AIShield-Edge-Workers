// AI Shield API Proxy Worker
// Routes api.reflexionsoftware.com → actual backend workers
// Hides backend worker hostnames from extension source code

const LICENSE_WORKER = 'https://ai-shield-license.kingsley-w-m-curtis.workers.dev';
const RULES_WORKER = 'https://ai-shield-rules.kingsley-w-m-curtis.workers.dev';
const AURIS_WORKER = 'https://auris-edge.kingsley-w-m-curtis.workers.dev';

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': request.headers.get('Origin') || '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, X-License-Key, X-Extension-Id, X-Timestamp, X-Signature, Stripe-Signature, X-Reflexion-Auth',
          'Access-Control-Max-Age': '86400'
        }
      });
    }

    let requestPath = url.pathname;
    if (requestPath.startsWith('/v1')) {
      requestPath = requestPath.substring(3);
    }

    let target;

    // Route /license/* → license worker
    if (requestPath.startsWith('/license/')) {
      const targetPath = requestPath.slice('/license'.length);
      target = `${LICENSE_WORKER}${targetPath}${url.search}`;
    }
    // Route /rules/* → stats/rules worker
    else if (requestPath.startsWith('/rules/')) {
      const targetPath = requestPath.slice('/rules'.length);
      target = `${RULES_WORKER}${targetPath}${url.search}`;
    }
    // Route /webhook → license worker (Stripe webhooks)
    else if (requestPath === '/webhook') {
      target = `${LICENSE_WORKER}/webhook`;
    }
    // Route /auris/* → auris worker
    else if (requestPath.startsWith('/auris/')) {
      const targetPath = requestPath.slice('/auris'.length);
      target = `${AURIS_WORKER}${targetPath}${url.search}`;
    }
    else {
      return new Response(JSON.stringify({ error: 'Not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Forward the request, preserving headers and body
    const proxyRequest = new Request(target, {
      method: request.method,
      headers: request.headers,
      body: request.body
    });

    const response = await fetch(proxyRequest);

    // Clone response and ensure CORS headers are set
    const newHeaders = new Headers(response.headers);
    const origin = request.headers.get('Origin') || '';
    if (origin.startsWith('chrome-extension://') || origin.startsWith('moz-extension://') ||
        origin.includes('reflexionsoftware')) {
      newHeaders.set('Access-Control-Allow-Origin', origin);
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    });
  }
};
