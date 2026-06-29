// /api/track.js — Analytics ingestion edge function
// Receives events from the app, stores in Vercel KV

export const config = { runtime: 'edge' };

const ALLOWED_ORIGINS = [
  'https://mealdesk-family.vercel.app',
  'http://localhost:3000',
  'http://localhost:5500',
];

const CORS = (origin) => ({
  'Access-Control-Allow-Origin': ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-App-Token',
  'Vary': 'Origin',
});

export default async function handler(req) {
  const origin = req.headers.get('origin') || '';
  const cors = CORS(origin);

  if (req.method === 'OPTIONS') return new Response(null, { status: 200, headers: cors });

  const appToken = req.headers.get('X-App-Token');
  const expectedToken = process.env.APP_TOKEN || 'mdf-2026';
  if (appToken !== expectedToken) {
    return new Response('Unauthorized', { status: 401, headers: cors });
  }

  if (req.method !== 'POST') return new Response('Method not allowed', { status: 405, headers: cors });

  try {
    const { event, data, user, ts } = await req.json();
    if (!event) return new Response('Missing event', { status: 400, headers: cors });

    // Store in Vercel KV if available
    const kvUrl = process.env.KV_REST_API_URL;
    const kvToken = process.env.KV_REST_API_TOKEN;

    if (kvUrl && kvToken) {
      const day = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
      const key = `mdf:events:${day}`;
      const entry = JSON.stringify({ event, data, user: user || 'unknown', ts: ts || Date.now() });

      // LPUSH to a daily list — keep last 500 events per day
      await fetch(`${kvUrl}/lpush/${key}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${kvToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify([entry]),
      });

      // Expire daily key after 30 days
      await fetch(`${kvUrl}/expire/${key}/2592000`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${kvToken}` },
      });

      // Increment counters for fast dashboard queries
      const counterKey = `mdf:counters:${event}:${day}`;
      await fetch(`${kvUrl}/incr/${counterKey}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${kvToken}` },
      });
      await fetch(`${kvUrl}/expire/${counterKey}/2592000`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${kvToken}` },
      });

      // Track unique users
      const userKey = `mdf:users:${user || 'unknown'}:lastSeen`;
      await fetch(`${kvUrl}/set/${userKey}/${Date.now()}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${kvToken}` },
      });
    }

    return new Response(JSON.stringify({ ok: true }), {
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
