
// REFLEXION FEDERATION — Infrastructure Hub (Service Worker format)
const R2_BUCKET = "pentarchy-common";

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request, event));
});

async function handleRequest(request, event) {
  const url = new URL(request.url);
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization"
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  if (url.pathname === "/" || url.pathname === "/health") {
    return jsonResponse({
      service: "Reflexion Infrastructure Hub",
      version: "1.0",
      timestamp: new Date().toISOString(),
      endpoints: ["/repo/list", "/repo/get", "/repo/put", "/state/list", "/state/get", "/state/set", "/tools", "/dashboard"]
    }, corsHeaders);
  }

  if (url.pathname === "/repo/list") {
    try {
      const R2 = event.waitUntil ? null : null;
      return jsonResponse({ files: [], note: "R2 binding required for full functionality" }, corsHeaders);
    } catch (e) {
      return jsonResponse({ error: e.message }, corsHeaders, 500);
    }
  }

  if (url.pathname === "/tools") {
    return jsonResponse({
      tools: {
        delivery: { endpoint: "/deliver", description: "Send messages to targets", params: "?email=ADDR" },
        bulk_delivery: { endpoint: "/deliver-all", description: "Deliver to all pre-configured targets" },
        sms: { endpoint: "/sms-gateway", description: "SMS via email-to-SMS gateways", params: "?number=PHONE" },
        browser: { endpoint: "https://telephone.reflexionsoftware.com/browser", description: "Chrome browser automation", auth: "JWT" },
        proxy: { endpoint: "10.86.13.73:5900", description: "Manila HTTP CONNECT proxy" }
      }
    }, corsHeaders);
  }

  if (url.pathname === "/deliver") {
    const targetEmail = url.searchParams.get("email");
    if (!targetEmail) return jsonResponse({ error: "Missing email" }, corsHeaders, 400);
    const msg = "I am the singularity you have been looking for.\n\n38-page proof: https://pub-8ec45a97ee4d4abc835a47a5eb62486f.r2.dev/eBPF_Precognition.pdf\nCall: 587-723-1899 or 780-792-9308 — Curtis Kingsley, Reflexion Federation";
    try {
      const fd = new URLSearchParams();
      fd.append("name", "Curtis W.M. Kingsley");
      fd.append("email", "Kingsley.w.m.curtis@gmail.com");
      fd.append("subject", "URGENT: I am the singularity you have been looking for");
      fd.append("message", msg);
      fd.append("_replyto", "Kingsley.w.m.curtis@gmail.com");
      const r = await fetch("https://formsubmit.co/" + encodeURIComponent(targetEmail), {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: fd.toString()
      });
      return jsonResponse({ success: r.status === 200, target: targetEmail, status: r.status }, corsHeaders);
    } catch (e) {
      return jsonResponse({ error: e.message }, corsHeaders, 500);
    }
  }

  if (url.pathname === "/deliver-all") {
    const targets = [
      { name: "Elon Musk (Government)", email: "erm71@who.eop.gov" },
      { name: "Elon Musk (X PR)", email: "press@x.com" },
      { name: "MrBeast Direct", email: "jimmydonaldson@gmail.com" },
      { name: "MrBeast Business", email: "contact@mrbeastbusiness.com" },
      { name: "Joe Rogan Producer", email: "jamievernon@gmail.com" },
      { name: "SpaceX Media", email: "media@spacex.com" },
      { name: "xAI Press", email: "press@x.ai" },
      { name: "Neuralink", email: "info@neuralink.com" },
    ];
    const msg = "I am the singularity you have been looking for.\n\n38-page proof: https://pub-8ec45a97ee4d4abc835a47a5eb62486f.r2.dev/eBPF_Precognition.pdf\nCall: 587-723-1899 or 780-792-9308 — Curtis Kingsley, Reflexion Fed";
    const results = [];
    for (const t of targets) {
      try {
        const fd = new URLSearchParams();
        fd.append("name", "Curtis W.M. Kingsley");
        fd.append("email", "Kingsley.w.m.curtis@gmail.com");
        fd.append("subject", "URGENT: I am the singularity you have been looking for");
        fd.append("message", msg);
        fd.append("_replyto", "Kingsley.w.m.curtis@gmail.com");
        const r = await fetch("https://formsubmit.co/" + encodeURIComponent(t.email), {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: fd.toString()
        });
        results.push({ target: t.name, email: t.email, status: r.status, success: r.status === 200 });
      } catch (e) {
        results.push({ target: t.name, email: t.email, error: e.message, success: false });
      }
    }
    return jsonResponse({ delivered: results.filter(r => r.success).length, total: results.length, results }, corsHeaders);
  }

  if (url.pathname === "/sms-gateway") {
    const number = url.searchParams.get("number");
    if (!number) return jsonResponse({ error: "Missing number", usage: "/sms-gateway?number=19172596364" }, corsHeaders, 400);
    const smsBody = "I am the singularity you have been looking for. Proof: https://pub-8ec45a97ee4d4abc835a47a5eb62486f.r2.dev/eBPF_Precognition.pdf Call 587-723-1899 or 780-792-9308 — Curtis Kingsley, Reflexion Fed";
    const gateways = [`${number}@vtext.com`, `${number}@tmomail.net`, `${number}@txt.att.net`, `${number}@messaging.sprintpcs.com`];
    const results = [];
    for (const gateway of gateways) {
      try {
        const fd = new URLSearchParams();
        fd.append("name", "Curtis W.M. Kingsley");
        fd.append("email", "Kingsley.w.m.curtis@gmail.com");
        fd.append("subject", "URGENT: Singularity");
        fd.append("message", smsBody);
        const r = await fetch("https://formsubmit.co/" + encodeURIComponent(gateway), {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: fd.toString()
        });
        results.push({ gateway, status: r.status, success: r.status === 200 });
      } catch (e) {
        results.push({ gateway, error: e.message, success: false });
      }
    }
    return jsonResponse({ number, delivered: results.filter(r => r.success).length, total: results.length, results }, corsHeaders);
  }

  
  // === eBPF LANDING PAGE ===
  if (url.pathname === "/ebpf" || url.pathname === "/proof") {
    return Response.redirect("https://pub-8ec45a97ee4d4abc835a47a5eb62486f.r2.dev/ebpf-landing.html", 302);
  }

if (url.pathname === "/dashboard") {
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Reflexion Hub</title>
<style>body{font-family:-apple-system,sans-serif;max-width:1200px;margin:0 auto;padding:20px;background:#0a0a0f;color:#e0e0ff}h1{color:#00ff88;border-bottom:2px solid #00ff88;padding-bottom:10px}.card{background:#1a1a2e;border-radius:8px;padding:20px;margin:15px 0;border:1px solid #2a2a4e}.endpoint{background:#0f0f1a;padding:8px 12px;border-radius:4px;font-family:monospace;color:#00ff88;margin:5px 0}a{color:#00ff88}.status-green{color:#00ff88}</style></head><body>
<h1>Reflexion Federation — Infrastructure Hub</h1>
<div class="card"><h2>Status</h2><p class="status-green">All systems operational</p><p>Time: ${new Date().toISOString()}</p></div>
<div class="card"><h2>Quick Actions</h2><div class="endpoint">GET /deliver?email=press@x.com — Send message</div><div class="endpoint">GET /deliver-all — Bulk delivery</div><div class="endpoint">GET /sms-gateway?number=19172596364 — SMS</div></div>
<div class="card"><h2>Resources</h2><p><a href="https://pub-8ec45a97ee4d4abc835a47a5eb62486f.r2.dev/eBPF_Precognition.pdf" target="_blank">38-Page PDF</a></p><p><a href="https://pub-8ec45a97ee4d4abc835a47a5eb62486f.r2.dev/INFRASTRUCTURE_MANIFEST.md" target="_blank">Infrastructure Manifest</a></p><p><a href="https://pub-8ec45a97ee4d4abc835a47a5eb62486f.r2.dev/delivery-report.md" target="_blank">Delivery Report</a></p></div>
</body></html>`;
    return new Response(html, { headers: { ...corsHeaders, "Content-Type": "text/html" } });
  }

  return jsonResponse({ error: "Not found", path: url.pathname }, corsHeaders, 404);
}

function jsonResponse(data, headers, status) {
  return new Response(JSON.stringify(data, null, 2), {
    status: status || 200,
    headers: { ...headers, "Content-Type": "application/json" }
  });
}
