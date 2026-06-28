
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type"
  };
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

  if (url.pathname === "/setup") {
    const obj = await TOOLS_BUCKET.get("swarm-cache/setup-script.sh");
    if (!obj) return new Response("Setup script not found", { status: 404 });
    return new Response(obj.body, {
      headers: { ...cors, "Content-Type": "text/x-shellscript", "Content-Disposition": "inline" }
    });
  }

  if (url.pathname === "/setup/help") {
    return json({
      title: "Reflexion Android SDK Auto-Setup",
      usage: "curl -sL https://build-cache.reflexionsoftware.com/setup | bash",
      description: "Downloads all build tools from R2 (gigabit speed) in ~30 seconds",
      tools: ["ECJ 3.33.0 (3MB)", "Android Build Tools 34 (58MB)", "Android Platform 34 (61MB)", "Kotlin 1.9.22 (87MB)", "Gradle 8.5 (126MB)"],
      total_size_mb: 481,
      time_estimate: "30 seconds",
      after_setup: "source ~/.reflexion-build/.env && ~/.reflexion-build/build-apk.sh /path/to/source",
      session_manager: "POST https://sessions.reflexionsoftware.com/session/create",
      project_template: "GET https://reflexionsoftware.com/template/download",
      build_validator: "GET https://reflexionsoftware.com/build/checklist",
      status_dashboard: "GET https://status.reflexionsoftware.com"
    }, 200, cors);
  }

  if (url.pathname === "/cache/list") {
    const objects = await TOOLS_BUCKET.list({ prefix: "swarm-cache/build-tools/" });
    const tools = objects.objects.map(o => ({
      name: o.key.replace("swarm-cache/build-tools/", ""),
      size: o.size,
      size_human: fmt(o.size),
      path: o.key
    }));
    const total = objects.objects.reduce((a, o) => a + o.size, 0);
    return json({ tools, count: tools.length, total_size: fmt(total) }, 200, cors);
  }

  if (url.pathname.startsWith("/cache/download/")) {
    const name = url.pathname.replace("/cache/download/", "");
    const obj = await TOOLS_BUCKET.get("swarm-cache/build-tools/" + name);
    if (!obj) return json({ error: "Tool not found", available: "GET /cache/list" }, 404, cors);
    return new Response(obj.body, { headers: { ...cors, "Content-Type": "application/octet-stream", "Content-Length": obj.size } });
  }

  return json({
    service: "build-cache-service",
    endpoints: {
      "/setup": "Auto-setup bash script (pipe to bash)",
      "/setup/help": "Setup documentation",
      "/cache/list": "List all cached tools",
      "/cache/download/{tool}": "Download a specific tool"
    }
  }, 200, cors);
}

function fmt(b) { const u = ["B","KB","MB","GB"]; let i = 0; while (b > 1024 && i < u.length-1) { b /= 1024; i++; } return b.toFixed(1) + " " + u[i]; }
function json(d, status, cors) { return new Response(JSON.stringify(d, null, 2), { status, headers: { ...cors, "Content-Type": "application/json" } }); }
