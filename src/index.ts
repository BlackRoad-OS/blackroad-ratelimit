// BlackRoad Rate Limiting Service
// Protect APIs with configurable rate limits and quotas

interface Env {
  ENVIRONMENT: string;
}

interface RateLimitRule {
  id: string;
  name: string;
  description: string;
  matcher: { type: 'path' | 'ip' | 'api_key' | 'user'; pattern: string };
  limit: number;
  window: number; // seconds
  windowHuman: string;
  action: 'block' | 'throttle' | 'log';
  enabled: boolean;
  stats: { requests: number; blocked: number; throttled: number };
}

interface UsageRecord {
  key: string;
  requests: number;
  windowStart: number;
  blocked: number;
}

// In-memory storage (use KV in production)
const usage: Map<string, UsageRecord> = new Map();
let rules: RateLimitRule[] = [];

function initRules() {
  if (rules.length > 0) return;
  rules = [
    {
      id: 'rule_global',
      name: 'Global Rate Limit',
      description: 'Default limit for all API requests',
      matcher: { type: 'path', pattern: '/api/*' },
      limit: 1000,
      window: 3600,
      windowHuman: '1 hour',
      action: 'block',
      enabled: true,
      stats: { requests: 45231, blocked: 234, throttled: 0 },
    },
    {
      id: 'rule_graphql',
      name: 'GraphQL Queries',
      description: 'Higher limit for GraphQL endpoint',
      matcher: { type: 'path', pattern: '/graphql' },
      limit: 5000,
      window: 3600,
      windowHuman: '1 hour',
      action: 'throttle',
      enabled: true,
      stats: { requests: 23456, blocked: 0, throttled: 89 },
    },
    {
      id: 'rule_auth',
      name: 'Auth Endpoints',
      description: 'Strict limit on authentication',
      matcher: { type: 'path', pattern: '/api/auth/*' },
      limit: 10,
      window: 60,
      windowHuman: '1 minute',
      action: 'block',
      enabled: true,
      stats: { requests: 1234, blocked: 56, throttled: 0 },
    },
    {
      id: 'rule_webhook',
      name: 'Webhook Triggers',
      description: 'Rate limit webhook triggers',
      matcher: { type: 'path', pattern: '/api/webhooks/trigger' },
      limit: 100,
      window: 60,
      windowHuman: '1 minute',
      action: 'block',
      enabled: true,
      stats: { requests: 5678, blocked: 12, throttled: 0 },
    },
    {
      id: 'rule_free',
      name: 'Free Tier',
      description: 'Rate limit for free tier API keys',
      matcher: { type: 'api_key', pattern: 'br_test_*' },
      limit: 100,
      window: 3600,
      windowHuman: '1 hour',
      action: 'block',
      enabled: true,
      stats: { requests: 8934, blocked: 423, throttled: 0 },
    },
  ];
}

// Sliding window rate limiter
function checkRateLimit(key: string, limit: number, windowSeconds: number): { allowed: boolean; remaining: number; resetAt: number } {
  const now = Date.now();
  const windowMs = windowSeconds * 1000;
  const record = usage.get(key);

  if (!record || now - record.windowStart > windowMs) {
    usage.set(key, { key, requests: 1, windowStart: now, blocked: 0 });
    return { allowed: true, remaining: limit - 1, resetAt: now + windowMs };
  }

  if (record.requests >= limit) {
    record.blocked++;
    return { allowed: false, remaining: 0, resetAt: record.windowStart + windowMs };
  }

  record.requests++;
  return { allowed: true, remaining: limit - record.requests, resetAt: record.windowStart + windowMs };
}

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-API-Key',
};

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BlackRoad Rate Limiting</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #000; color: #fff; min-height: 100vh; }
    .header { background: linear-gradient(135deg, #111 0%, #000 100%); border-bottom: 1px solid #333; padding: 21px 34px; display: flex; justify-content: space-between; align-items: center; }
    .logo { font-size: 21px; font-weight: bold; background: linear-gradient(135deg, #F5A623 0%, #FF1D6C 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .btn { padding: 10px 21px; border-radius: 8px; border: none; font-weight: 600; cursor: pointer; }
    .btn-primary { background: linear-gradient(135deg, #FF1D6C 0%, #9C27B0 100%); color: #fff; }
    .container { max-width: 1200px; margin: 0 auto; padding: 34px; }
    .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 21px; margin-bottom: 34px; }
    .stat-card { background: #111; border: 1px solid #333; border-radius: 13px; padding: 21px; text-align: center; }
    .stat-value { font-size: 34px; font-weight: bold; background: linear-gradient(135deg, #FF1D6C 0%, #F5A623 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .stat-label { color: #888; font-size: 13px; margin-top: 8px; }
    .section-title { font-size: 21px; margin-bottom: 21px; display: flex; align-items: center; gap: 8px; }
    .section-title span { color: #FF1D6C; }
    .rules-list { display: flex; flex-direction: column; gap: 13px; }
    .rule-card { background: #111; border: 1px solid #333; border-radius: 13px; padding: 21px; }
    .rule-card:hover { border-color: #FF1D6C; }
    .rule-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 13px; }
    .rule-name { font-size: 18px; font-weight: 600; }
    .rule-action { padding: 4px 12px; border-radius: 4px; font-size: 11px; font-weight: 600; }
    .rule-action.block { background: #EF444433; color: #EF4444; }
    .rule-action.throttle { background: #F5A62333; color: #F5A623; }
    .rule-action.log { background: #2979FF33; color: #2979FF; }
    .rule-desc { color: #888; font-size: 14px; margin-bottom: 13px; }
    .rule-config { display: flex; gap: 21px; flex-wrap: wrap; margin-bottom: 13px; }
    .rule-config-item { background: #0a0a0a; padding: 8px 16px; border-radius: 8px; }
    .rule-config-label { color: #666; font-size: 11px; display: block; margin-bottom: 4px; }
    .rule-config-value { font-family: monospace; color: #10B981; font-size: 14px; }
    .rule-matcher { font-family: monospace; color: #2979FF; background: #2979FF11; padding: 8px 16px; border-radius: 6px; display: inline-block; margin-bottom: 13px; }
    .rule-stats { display: flex; gap: 21px; padding-top: 13px; border-top: 1px solid #222; }
    .rule-stat { text-align: center; }
    .rule-stat-value { font-size: 16px; font-weight: 600; }
    .rule-stat-value.blocked { color: #EF4444; }
    .rule-stat-label { font-size: 11px; color: #666; }
    .toggle { position: relative; width: 44px; height: 24px; }
    .toggle input { opacity: 0; width: 0; height: 0; }
    .toggle .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background: #333; border-radius: 24px; transition: 0.3s; }
    .toggle .slider:before { position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px; background: #666; border-radius: 50%; transition: 0.3s; }
    .toggle input:checked + .slider { background: linear-gradient(135deg, #10B981 0%, #2979FF 100%); }
    .toggle input:checked + .slider:before { transform: translateX(20px); background: #fff; }
    .test-section { background: #111; border: 1px solid #333; border-radius: 13px; padding: 21px; margin-top: 34px; }
    .test-input { display: flex; gap: 13px; }
    .test-input input { flex: 1; padding: 13px; border-radius: 8px; border: 1px solid #333; background: #0a0a0a; color: #fff; }
    .test-result { margin-top: 13px; padding: 13px; border-radius: 8px; font-family: monospace; font-size: 13px; }
    .test-result.allowed { background: #10B98122; color: #10B981; }
    .test-result.blocked { background: #EF444422; color: #EF4444; }
    .footer { border-top: 1px solid #333; padding: 21px 34px; text-align: center; color: #666; font-size: 13px; margin-top: 34px; }
    .footer a { color: #FF1D6C; text-decoration: none; }
  </style>
</head>
<body>
  <header class="header">
    <div class="logo">BlackRoad Rate Limiting</div>
    <button class="btn btn-primary" onclick="showCreate()">+ Create Rule</button>
  </header>
  <div class="container">
    <div class="stats-grid" id="stats"></div>
    <h2 class="section-title"><span>//</span> Rate Limit Rules</h2>
    <div class="rules-list" id="rules-list"></div>
    <div class="test-section">
      <h3 class="section-title"><span>//</span> Test Rate Limit</h3>
      <div class="test-input">
        <input type="text" id="test-key" placeholder="API Key or IP (e.g., br_test_abc123)">
        <input type="text" id="test-path" placeholder="Path (e.g., /api/users)">
        <button class="btn btn-primary" onclick="testLimit()">Check Limit</button>
      </div>
      <div id="test-result"></div>
    </div>
  </div>
  <footer class="footer">
    <p>Powered by <a href="https://blackroad.io">BlackRoad OS</a> &bull; <a href="https://blackroad-dev-portal.amundsonalexa.workers.dev">Developer Portal</a></p>
  </footer>
  <script>
    async function loadRules() {
      const resp = await fetch('/api/rules');
      const data = await resp.json();
      const totalReq = data.rules.reduce((s, r) => s + r.stats.requests, 0);
      const totalBlocked = data.rules.reduce((s, r) => s + r.stats.blocked, 0);
      const activeRules = data.rules.filter(r => r.enabled).length;

      document.getElementById('stats').innerHTML = \`
        <div class="stat-card"><div class="stat-value">\${data.rules.length}</div><div class="stat-label">Rules</div></div>
        <div class="stat-card"><div class="stat-value">\${activeRules}</div><div class="stat-label">Active</div></div>
        <div class="stat-card"><div class="stat-value">\${(totalReq/1000).toFixed(1)}K</div><div class="stat-label">Requests</div></div>
        <div class="stat-card"><div class="stat-value">\${totalBlocked}</div><div class="stat-label">Blocked</div></div>
      \`;

      document.getElementById('rules-list').innerHTML = data.rules.map(r => \`
        <div class="rule-card">
          <div class="rule-header">
            <div style="display:flex;align-items:center;gap:13px;">
              <span class="rule-name">\${r.name}</span>
              <span class="rule-action \${r.action}">\${r.action}</span>
            </div>
            <label class="toggle">
              <input type="checkbox" \${r.enabled ? 'checked' : ''} onchange="toggleRule('\${r.id}', this.checked)">
              <span class="slider"></span>
            </label>
          </div>
          <p class="rule-desc">\${r.description}</p>
          <div class="rule-matcher">\${r.matcher.type}: \${r.matcher.pattern}</div>
          <div class="rule-config">
            <div class="rule-config-item">
              <span class="rule-config-label">Limit</span>
              <span class="rule-config-value">\${r.limit} requests</span>
            </div>
            <div class="rule-config-item">
              <span class="rule-config-label">Window</span>
              <span class="rule-config-value">\${r.windowHuman}</span>
            </div>
          </div>
          <div class="rule-stats">
            <div class="rule-stat"><div class="rule-stat-value">\${r.stats.requests.toLocaleString()}</div><div class="rule-stat-label">Requests</div></div>
            <div class="rule-stat"><div class="rule-stat-value blocked">\${r.stats.blocked}</div><div class="rule-stat-label">Blocked</div></div>
            <div class="rule-stat"><div class="rule-stat-value">\${r.stats.throttled}</div><div class="rule-stat-label">Throttled</div></div>
          </div>
        </div>
      \`).join('');
    }

    async function toggleRule(id, enabled) {
      await fetch('/api/rules/' + id, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled })
      });
      loadRules();
    }

    async function testLimit() {
      const key = document.getElementById('test-key').value || 'test_user';
      const path = document.getElementById('test-path').value || '/api/test';
      const resp = await fetch('/api/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key, path })
      });
      const data = await resp.json();
      document.getElementById('test-result').innerHTML = \`
        <div class="test-result \${data.allowed ? 'allowed' : 'blocked'}">
          \${data.allowed ? '✓ ALLOWED' : '✗ BLOCKED'} | Remaining: \${data.remaining} | Resets: \${new Date(data.resetAt).toLocaleTimeString()}
        </div>
      \`;
    }

    function showCreate() { alert('Create rule modal coming soon!'); }
    loadRules();
  </script>
</body>
</html>`;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    initRules();
    const url = new URL(request.url);
    const method = request.method;

    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // List rules
    if (url.pathname === '/api/rules' && method === 'GET') {
      return Response.json({ rules }, { headers: corsHeaders });
    }

    // Update rule
    if (url.pathname.match(/^\/api\/rules\/[\w]+$/) && method === 'PUT') {
      const id = url.pathname.split('/').pop()!;
      const rule = rules.find(r => r.id === id);
      if (!rule) return Response.json({ error: 'Rule not found' }, { status: 404, headers: corsHeaders });
      const body = await request.json() as any;
      if (body.enabled !== undefined) rule.enabled = body.enabled;
      if (body.limit !== undefined) rule.limit = body.limit;
      return Response.json({ success: true, rule }, { headers: corsHeaders });
    }

    // Check rate limit
    if (url.pathname === '/api/check' && method === 'POST') {
      const body = await request.json() as any;
      const key = body.key || request.headers.get('X-API-Key') || request.headers.get('CF-Connecting-IP') || 'anonymous';
      const path = body.path || '/';

      // Find matching rule
      const matchedRule = rules.find(r => r.enabled && path.startsWith(r.matcher.pattern.replace('*', '')));
      if (!matchedRule) {
        return Response.json({ allowed: true, remaining: -1, resetAt: 0, rule: null }, { headers: corsHeaders });
      }

      const result = checkRateLimit(key + ':' + matchedRule.id, matchedRule.limit, matchedRule.window);
      matchedRule.stats.requests++;
      if (!result.allowed) matchedRule.stats.blocked++;

      return Response.json({
        ...result,
        rule: matchedRule.id,
        ruleName: matchedRule.name,
        action: matchedRule.action,
      }, {
        headers: {
          ...corsHeaders,
          'X-RateLimit-Limit': matchedRule.limit.toString(),
          'X-RateLimit-Remaining': result.remaining.toString(),
          'X-RateLimit-Reset': Math.floor(result.resetAt / 1000).toString(),
        },
      });
    }

    // Stats
    if (url.pathname === '/api/stats') {
      const totalReq = rules.reduce((s, r) => s + r.stats.requests, 0);
      const totalBlocked = rules.reduce((s, r) => s + r.stats.blocked, 0);
      return Response.json({
        rules: rules.length,
        activeRules: rules.filter(r => r.enabled).length,
        totalRequests: totalReq,
        totalBlocked,
        blockRate: ((totalBlocked / totalReq) * 100).toFixed(2),
      }, { headers: corsHeaders });
    }

    // Health
    if (url.pathname === '/api/health') {
      return Response.json({ status: 'healthy', version: '1.0.0', rules: rules.length }, { headers: corsHeaders });
    }

    return new Response(dashboardHTML, { headers: { 'Content-Type': 'text/html' } });
  },
};
