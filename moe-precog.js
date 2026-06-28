// moe-precog worker — JavaScript deployment version
// Compiled from TypeScript sources for direct API upload
// Date: 2026-05-07

// ===== Logger =====
class Logger {
  constructor(module) { this.module = module; }
  debug(action, data) { console.debug(`[${this.module}.${action}]`, data || ''); }
  error(action, message, context) {
    console.error(`[${this.module}.${action}] ERROR: ${message}`, context || '');
  }
}

// ===== Temporal Model =====
class TemporalModelManager {
  constructor(env) { this.env = env; }

  async recordEvent(entry) {
    const key = `temporal:${entry.domain}:${entry.eventType}`;
    let model = await this.getModel(entry.domain, entry.eventType);

    if (model) {
      const interval = entry.timestamp - model.lastSeen;
      model.intervals.push(interval);
      if (model.intervals.length > 100) model.intervals.shift();

      // EMA with alpha=0.3 (Hannah correction)
      const alpha = 0.3;
      model.avgInterval = alpha * interval + (1 - alpha) * model.avgInterval;

      const variance = model.intervals.reduce((sum, iv) => sum + Math.pow(iv - model.avgInterval, 2), 0) / model.intervals.length;
      model.stdDev = Math.sqrt(variance);
      model.lastSeen = entry.timestamp;
      model.nextPredicted = entry.timestamp + model.avgInterval;
      model.confidence = Math.max(0, Math.min(1, 1 - (model.stdDev / (model.avgInterval + 1))));
      model.observationCount = model.intervals.length;
    } else {
      model = {
        eventType: entry.eventType,
        intervals: [],
        timestamps: [entry.timestamp],
        avgInterval: 30000,
        stdDev: 15000,
        lastSeen: entry.timestamp,
        nextPredicted: entry.timestamp + 30000,
        confidence: 0.1,
        observationCount: 1
      };
    }

    await this.env.BCC_CONTEXT_CACHE.put(key, JSON.stringify(model), { expirationTtl: 86400 });
    return model;
  }

  async getModel(domain, eventType) {
    const key = `temporal:${domain}:${eventType}`;
    try {
      const data = await this.env.BCC_CONTEXT_CACHE.get(key);
      return data ? JSON.parse(data) : null;
    } catch { return null; }
  }

  async getDomainPredictions(domain) {
    const prefix = `temporal:${domain}:`;
    const models = [];
    try {
      const list = await this.env.BCC_CONTEXT_CACHE.list({ prefix });
      for (const k of list.keys) {
        const eventType = k.name.substring(prefix.length);
        const model = await this.getModel(domain, eventType);
        if (model) models.push(model);
      }
    } catch (e) { console.error('list failed:', e.message); }
    return models;
  }
}

// ===== Precog Worker =====
const logger = new Logger('PrecogWorker');

const SUSPICIOUS_PATTERNS = [
  { pattern: /analytics|telemetry|tracking|metrics|stats/i, weight: 0.4 },
  { pattern: /fingerprint|device.*id|visitor.*id/i, weight: 0.5 },
  { pattern: /beacon|ping|event.*log/i, weight: 0.3 },
  { pattern: /collect|gather|send.*data/i, weight: 0.3 },
  { pattern: /third.*party|external|cdn.*tracker/i, weight: 0.4 },
  { pattern: /crypto.*miner|wasm.*mine/i, weight: 0.9 },
  { pattern: /canvas.*finger|webgl.*finger/i, weight: 0.8 },
];

const TRUSTED_PATTERNS = [
  { pattern: /jquery|react|vue|angular/i, weight: -0.3 },
  { pattern: /bootstrap|tailwind|fontawesome/i, weight: -0.2 },
  { pattern: /google.*fonts|fonts.*google/i, weight: -0.2 },
  { pattern: /cdnjs|unpkg|jsdelivr/i, weight: -0.1 },
];

async function checkKVCache(env, event) {
  if (!event.url) return null;
  try {
    const exactKey = `precog:url:${event.url}`;
    const cached = await env.AI_SHIELD_RULES.get(exactKey);
    if (cached) {
      const result = JSON.parse(cached);
      return { eventType: event.type, url: event.url, confidence: 0.99, reason: 'kv_exact_match', expert: 'kv_cache', pattern: event.url, resourceTypes: result.resourceTypes };
    }
    const url = new URL(event.url);
    const domainKey = `precog:domain:${url.hostname}`;
    const domainCached = await env.AI_SHIELD_RULES.get(domainKey);
    if (domainCached) {
      const result = JSON.parse(domainCached);
      return { eventType: event.type, url: event.url, confidence: result.confidence * 0.9, reason: 'kv_domain_match', expert: 'kv_cache', pattern: `*://${url.hostname}/*`, resourceTypes: result.resourceTypes };
    }
  } catch (e) { logger.error('checkKVCache', e.message); }
  return null;
}

async function checkHeuristic(env, event) {
  if (!event.url) return null;
  const url = event.url.toLowerCase();
  let score = 0.5;
  let matched = [];

  for (const { pattern, weight } of SUSPICIOUS_PATTERNS) {
    if (pattern.test(url)) { score += weight; matched.push(pattern.source); }
  }
  for (const { pattern, weight } of TRUSTED_PATTERNS) {
    if (pattern.test(url)) { score += weight; matched.push(`!${pattern.source}`); }
  }

  try {
    const u = new URL(event.url);
    const depth = u.pathname.split('/').filter(Boolean).length;
    if (depth > 4) score += 0.05 * (depth - 4);
    const params = Array.from(u.searchParams.keys()).length;
    if (params > 5) score += 0.05 * (params - 5);
  } catch {}

  score = Math.max(0, Math.min(1, score));
  return { eventType: event.type, url: event.url, confidence: score, reason: `heuristic: ${matched.slice(0, 3).join(', ')}`, expert: 'heuristic', pattern: event.url, resourceTypes: ['script', 'xmlhttprequest'] };
}

async function checkEmbedding(env, event) {
  if (!event.url) return null;
  try {
    const normalized = event.url.toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\?.*$/, '').replace(/\/+$/, '');
    const embedding = await env.AI.run('@cf/baai/bge-base-en-v1.5', { text: normalized });
    const matches = await env.VECTORIZE.query(embedding.data[0], { topK: 3, namespace: 'surveillance_patterns' });
    if (!matches.matches.length) return null;
    const best = matches.matches[0];
    if (best.score > 0.92) {
      return { eventType: event.type, url: event.url, confidence: best.score, reason: `embedding: ${best.metadata?.url || 'unknown'}`, expert: 'embedding', pattern: event.url, resourceTypes: ['script', 'xmlhttprequest'] };
    }
  } catch (e) { logger.error('checkEmbedding', e.message); }
  return null;
}

// ===== Main Export =====
async function handleRequest(request, env, ctx) {
    const start = Date.now();
    if (request.method !== 'POST') return new Response('Method not allowed', { status: 405 });

    const licenseKey = request.headers.get('X-License-Key');
    if (!licenseKey) return new Response('License key required', { status: 401 });

    try {
      const body = await request.json();
      const { events, domain, pageUrl } = body;
      if (!events || !Array.isArray(events) || !events.length) {
        return new Response('No events', { status: 400 });
      }

      logger.debug('fetch', `Received ${events.length} events from ${domain}`);
      const predictions = [];
      const temporal = new TemporalModelManager(env);

      for (const event of events) {
        // Level 1: KV lookup — exact match, return immediately
        const kvResult = await checkKVCache(env, event);
        if (kvResult && kvResult.confidence >= 0.99) {
          predictions.push(kvResult);
          continue;
        }

        // Level 2: Heuristic scoring
        const heuristicResult = await checkHeuristic(env, event);

        // Level 2: Block if confidence > 0.90, allow if < 0.10
        if (heuristicResult) {
          if (heuristicResult.confidence > 0.90) {
            predictions.push({ ...heuristicResult, reason: 'heuristic_block' });
            continue;
          }
          if (heuristicResult.confidence < 0.10) {
            predictions.push({ ...heuristicResult, confidence: 0.02, reason: 'heuristic_allow' });
            continue;
          }
        }

        // Level 3: Workers AI embedding — only for 0.10 ≤ confidence ≤ 0.90
        if (heuristicResult && heuristicResult.confidence >= 0.10 && heuristicResult.confidence <= 0.90) {
          const embeddingResult = await checkEmbedding(env, event);
          if (embeddingResult) {
            predictions.push(embeddingResult);
            continue;
          }
        }

        // Record temporal data
        if (event.type && event.domain) {
          await temporal.recordEvent({
            domain: event.domain,
            eventType: event.type,
            timestamp: event.timestamp,
            timeSincePageLoad: event.timestamp - (event.navigationStart || 0),
            metadata: event.metadata || {}
          });
        }
      }

      const temporalPredictions = await temporal.getDomainPredictions(domain);
      const now = Date.now();
      const imminentBlocks = temporalPredictions
        .filter(p => p.nextPredicted - now < 10000 && p.confidence > 0.5)
        .map(p => ({
          eventType: p.eventType,
          url: '/*',
          confidence: p.confidence,
          reason: `temporal: fires in ${Math.round((p.nextPredicted - now) / 1000)}s`,
          expert: 'temporal',
          pattern: '*://*/*',
          resourceTypes: ['script', 'xmlhttprequest']
        }));

      const allBlocks = [...predictions.filter(p => p.confidence > 0.8), ...imminentBlocks];

      return new Response(JSON.stringify({
        predictions,
        blocks: allBlocks,
        temporalPredictions: temporalPredictions.filter(p => p.confidence > 0.3),
        processingTimeMs: Date.now() - start
      }), { headers: { 'Content-Type': 'application/json' } });

    } catch (e) {
      logger.error('fetch', e.message);
      return new Response(JSON.stringify({ error: e.message }), { status: 500 });
    }
}

addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request, event.env || {}, event));
});
