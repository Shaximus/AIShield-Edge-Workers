
addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  if (url.pathname === '/health') {
    event.respondWith(new Response(JSON.stringify({
      status: 'healthy',
      timestamp: Date.now(),
      version: 'minimal-test'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    }));
    return;
  }

  event.respondWith(new Response(JSON.stringify({
    error: 'Not found',
    path: url.pathname
  }), {
    status: 404,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  }));
});
