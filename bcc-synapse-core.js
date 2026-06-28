/**
 * BCC Synapse Core v2.1 — ADDED /v1/state endpoint
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// ── BilateralClock (Lamport Clock) ────────────────────────────────────────

class BilateralClock {
  constructor(env) { this.env = env; }

  async tick(hemisphere, userId) {
    const kvKey = `bilateral_clock:${userId}`;
    let current;
    try { current = JSON.parse(await this.env.KV_CONTEXT_CACHE.get(kvKey) || '{"left":0,"right":0,"merged":0}'); }
    catch { current = { left: 0, right: 0, merged: 0 }; }

    current[hemisphere]++;
    current.merged = Math.max(current.left, current.right);
    await this.env.KV_CONTEXT_CACHE.put(kvKey, JSON.stringify(current));

    try {
      await this.env.D1_META.prepare(
        `INSERT INTO bilateral_clock (user_id,left_count,right_count,merged_count,updated_at) VALUES (?,?,?,?,?)
         ON CONFLICT(user_id) DO UPDATE SET left_count=excluded.left_count,right_count=excluded.right_count,merged_count=excluded.merged_count,updated_at=excluded.updated_at`
      ).bind(userId, current.left, current.right, current.merged, Date.now()).run();
    } catch(e) { console.error('[Clock] D1 fail:', e); }

    return current.merged;
  }

  async getVersion(userId) {
    try { const raw = await this.env.KV_CONTEXT_CACHE.get(`bilateral_clock:${userId}`); if(raw) return JSON.parse(raw); }
    catch { /*fall through*/ }
    try {
      const r = await this.env.D1_META.prepare('SELECT left_count,right_count,merged_count FROM bilateral_clock WHERE user_id=?').bind(userId).first();
      if(r) return { left: r.left_count, right: r.right_count, merged: r.merged_count };
    } catch { /*fall through*/ }
    return { left: 0, right: 0, merged: 0 };
  }
}

// ── Get Bilateral State ─────────────────────────────────────────────────────

async function getBilateralState(env,userId){
  const [riskScore,recentIntercepts,version] = await Promise.all([
    env.SHIELD_DATA.get(`risk_score:${userId}`).then(r=>parseFloat(r||'0')).catch(()=>0),
    env.SHIELD_DATA.get(`recent_intercepts:${userId}`).then(r=>{try{return JSON.parse(r||'[]')}catch{return[]}}).catch(()=>[]),
    new BilateralClock(env).getVersion(userId),
  ]);
  return { identity:{userId,currentRiskScore:riskScore,saturationLevel:riskScore}, knowledge:{interceptedEndpoints:recentIntercepts.slice(0,10)}, _bilateralVersion:version };
}

// ── SSE Handler ─────────────────────────────────────────────────────────────

async function handleSSE(request, env) {
  const url = new URL(request.url);
  const userId = url.searchParams.get('userId');
  if(!userId) return new Response(JSON.stringify({error:'Missing userId'}),{status:400,headers:{'Content-Type':'application/json',...CORS_HEADERS}});

  const encoder = new TextEncoder();
  const clock = new BilateralClock(env);
  const initialVersion = await clock.getVersion(userId);

  const stream = new ReadableStream({
    async start(controller) {
      controller.enqueue(encoder.encode(`event: connected\ndata: ${JSON.stringify({type:'connected',userId,version:initialVersion})}\n\n`));
      let lastMerged = initialVersion.merged;
      let heartbeats = 0;

      for(let i=0;i<50;i++){
        try{
          const v = await clock.getVersion(userId);
          if(v.merged > lastMerged){
            lastMerged = v.merged;
            const state = await getBilateralState(env,userId);
            state._bilateralVersion = v;
            controller.enqueue(encoder.encode(`event: update\ndata: ${JSON.stringify(state)}\n\n`));
          }
          if(++heartbeats>=10){ heartbeats=0; controller.enqueue(encoder.encode(`event: heartbeat\ndata: {}\n\n`)); }
          await new Promise(r=>setTimeout(r,500));
        }catch(e){ controller.enqueue(encoder.encode(`event: error\ndata: ${JSON.stringify({message:e.message})}\n\n`)); }
      }
      controller.enqueue(encoder.encode(`event: close\ndata: ${JSON.stringify({reason:'timeout',reconnect:true})}\n\n`));
      controller.close();
    },
    cancel(){ console.log(`[SSE] Disconnected: ${userId}`); }
  });

  return new Response(stream,{headers:{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Connection':'keep-alive',...CORS_HEADERS}});
}

// ── Telemetry Intercept ─────────────────────────────────────────────────────

async function reportTelemetryIntercept(env, args) {
  const clock = new BilateralClock(env);
  const now = Date.now();

  await env.D1_META.prepare(
    `INSERT INTO event_queue (event_type,payload,source_worker,target_worker,priority,created_at,expires_at) VALUES (?,?,?,?,?,?,?)`
  ).bind('telemetry_intercept', JSON.stringify({endpoint:args.endpoint,payload:args.payload,ruleId:args.ruleId,userId:args.userId}),
    'reflexion-api','bcc-synapse-core',5,now,now+604800000).run();

  const rightClock = await clock.tick('right', args.userId);
  await env.D1_META.prepare(`INSERT INTO telemetry_intercepts (user_id,endpoint,payload,rule_id,clock_right,timestamp,created_at) VALUES (?,?,?,?,?,?,?)`)
    .bind(args.userId, args.endpoint, args.payload||'', args.ruleId||'', rightClock, now, now).run();

  let currentRisk=0;
  try{ const raw=await env.SHIELD_DATA.get(`risk_score:${args.userId}`); if(raw) currentRisk=parseFloat(raw); }catch{}
  const newRisk = Math.min(1.0, currentRisk+0.01);
  await env.SHIELD_DATA.put(`risk_score:${args.userId}`, String(newRisk));

  let recent=[];
  try{ const raw=await env.SHIELD_DATA.get(`recent_intercepts:${args.userId}`); if(raw) recent=JSON.parse(raw); }catch{}
  recent.unshift(args.endpoint); if(recent.length>100) recent=recent.slice(0,100);
  await env.SHIELD_DATA.put(`recent_intercepts:${args.userId}`, JSON.stringify(recent), {expirationTtl:86400});

  const leftClock = await clock.tick('left', args.userId);
  return { identity:{userId:args.userId,currentRiskScore:newRisk}, knowledge:{interceptedEndpoints:recent.slice(0,10)}, saturationLevel:newRisk, _bilateralVersion:Math.max(leftClock,rightClock) };
}

// ── Main Router ─────────────────────────────────────────────────────────────

addEventListener('fetch', event => { event.respondWith(handleFetch(event.request, event)); });

async function handleFetch(request, event) {
  const url = new URL(request.url); const path = url.pathname;
  if(request.method==='OPTIONS') return new Response(null,{headers:CORS_HEADERS});

  try{
    if(path==='/sse'||path==='/v1/sse') return await handleSSE(request, event.env);

    if((path==='/v1/telemetry'||path==='/telemetry')&&request.method==='POST'){
      const body = await request.json();
      const result = await reportTelemetryIntercept(event.env, body);
      return new Response(JSON.stringify(result),{headers:{'Content-Type':'application/json',...CORS_HEADERS}});
    }

    if(path==='/v1/state'||path==='/state'){
      const userId = url.searchParams.get('userId') || 'system';
      const state = await getBilateralState(event.env, userId);
      return new Response(JSON.stringify(state),{headers:{'Content-Type':'application/json',...CORS_HEADERS}});
    }

    if(path==='/health'||path==='/v1/health'){
      const v = await new BilateralClock(event.env).getVersion('system');
      return new Response(JSON.stringify({status:'healthy',service:'bcc-synapse-core',version:'2.1.0',bilateral_clock:v,timestamp:Date.now()}),{headers:{'Content-Type':'application/json',...CORS_HEADERS}});
    }

    return new Response(JSON.stringify({error:'Not found'}),{status:404,headers:{'Content-Type':'application/json',...CORS_HEADERS}});
  }catch(e){
    return new Response(JSON.stringify({error:e.message}),{status:500,headers:{'Content-Type':'application/json',...CORS_HEADERS}});
  }
}
