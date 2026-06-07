export const config = { runtime: 'edge' };

// Allowed origins — only your app
const ALLOWED_ORIGINS = [
  'https://mealdesk-family.vercel.app',
  'http://localhost:3000',
  'http://localhost:5500',
];

// Simple in-memory rate limit (edge runtime — per isolate, resets on cold start)
// For production use Vercel KV. This blocks naive abuse.
const rateLimitMap = new Map();
const RATE_LIMIT = 20;       // max requests
const RATE_WINDOW = 60000;   // per 60 seconds per IP

function getRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip) || { count: 0, start: now };
  if (now - entry.start > RATE_WINDOW) {
    rateLimitMap.set(ip, { count: 1, start: now });
    return false; // not limited
  }
  entry.count++;
  rateLimitMap.set(ip, entry);
  return entry.count > RATE_LIMIT;
}

export default async function handler(req) {
  const origin = req.headers.get('origin') || '';
  const corsOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];

  const corsHeaders = {
    'Access-Control-Allow-Origin': corsOrigin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-App-Token',
    'Vary': 'Origin',
  };

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  }

  // App token check — simple shared secret
  const appToken = req.headers.get('X-App-Token');
  const expectedToken = process.env.APP_TOKEN || 'mdf-2026';
  if (appToken !== expectedToken) {
    return new Response(JSON.stringify({ error: { message: 'Unauthorized' } }), {
      status: 401,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  // Rate limit by IP
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
  if (getRateLimit(ip)) {
    return new Response(JSON.stringify({ error: { message: 'Rate limit exceeded. Please wait.' } }), {
      status: 429,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return new Response(JSON.stringify({ error: { message: 'AI not configured.' } }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  try {
    const body = await req.json();

    // Cap max_tokens to prevent abuse
    const maxTokens = Math.min(body.max_tokens || 600, 1000);

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: maxTokens,
        system: body.system || '',
        messages: body.messages || [],
      }),
    });

    const data = await response.json();
    return new Response(JSON.stringify(data), {
      status: response.status,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: { message: err.message } }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
}
