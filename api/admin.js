// /api/admin.js — Password-protected analytics retrieval
export const config = { runtime: 'edge' };

export default async function handler(req) {
  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };

  if (req.method === 'OPTIONS') return new Response(null, { status: 200, headers: cors });

  // Admin password check
  const authHeader = req.headers.get('Authorization') || '';
  const [, b64] = authHeader.split(' ');
  let authorized = false;
  if (b64) {
    try {
      const decoded = atob(b64);
      const [user, pass] = decoded.split(':');
      const adminUser = process.env.ADMIN_USER || 'peter';
      const adminPass = process.env.ADMIN_PASS || 'stavros2026';
      authorized = user === adminUser && pass === adminPass;
    } catch {}
  }

  if (!authorized) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { ...cors, 'Content-Type': 'application/json', 'WWW-Authenticate': 'Basic realm="MealDesk Admin"' },
    });
  }

  const kvUrl = process.env.KV_REST_API_URL;
  const kvToken = process.env.KV_REST_API_TOKEN;

  if (!kvUrl || !kvToken) {
    // Return mock data if KV not configured
    return new Response(JSON.stringify({
      ok: true,
      kvConfigured: false,
      message: 'Add KV_REST_API_URL and KV_REST_API_TOKEN in Vercel environment variables to enable real tracking.',
      mockData: true,
    }), { status: 200, headers: { ...cors, 'Content-Type': 'application/json' } });
  }

  try {
    const today = new Date().toISOString().slice(0, 10);
    const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);

    // Fetch last 7 days of events
    const days = Array.from({ length: 7 }, (_, i) =>
      new Date(Date.now() - i * 86400000).toISOString().slice(0, 10)
    );

    const eventFetches = days.map(day =>
      fetch(`${kvUrl}/lrange/mdf:events:${day}/0/199`, {
        headers: { Authorization: `Bearer ${kvToken}` },
      }).then(r => r.json()).then(r => ({ day, events: (r.result || []).map(e => { try { return JSON.parse(e); } catch { return null; } }).filter(Boolean) }))
    );

    const dayResults = await Promise.all(eventFetches);
    const allEvents = dayResults.flatMap(d => d.events);

    // Aggregate stats
    const stats = {
      totalEvents: allEvents.length,
      byUser: {},
      byTab: {},
      byFeature: {},
      byDay: {},
      recentEvents: allEvents.slice(0, 30),
    };

    allEvents.forEach(e => {
      // By user
      const u = e.user || 'unknown';
      if (!stats.byUser[u]) stats.byUser[u] = { events: 0, tabs: {}, features: {}, lastSeen: 0 };
      stats.byUser[u].events++;
      if (e.ts > stats.byUser[u].lastSeen) stats.byUser[u].lastSeen = e.ts;

      // By tab
      if (e.event === 'tab_view') {
        stats.byTab[e.data] = (stats.byTab[e.data] || 0) + 1;
        stats.byUser[u].tabs[e.data] = (stats.byUser[u].tabs[e.data] || 0) + 1;
      }

      // By feature
      if (e.event === 'feature_use') {
        stats.byFeature[e.data] = (stats.byFeature[e.data] || 0) + 1;
        stats.byUser[u].features[e.data] = (stats.byUser[u].features[e.data] || 0) + 1;
      }

      // By day
      const day = new Date(e.ts).toISOString().slice(0, 10);
      stats.byDay[day] = (stats.byDay[day] || 0) + 1;
    });

    return new Response(JSON.stringify({ ok: true, kvConfigured: true, stats }), {
      status: 200,
      headers: { ...cors, 'Content-Type': 'application/json' },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }
}
