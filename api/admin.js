// /api/admin.js — Auth + analytics + password management
export const config = { runtime: 'edge' };

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Action',
};

// Simple SHA-256 hash using Web Crypto (available in edge runtime)
async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Generate a secure random token
function genToken(len = 32) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

// KV helpers
function kvFetch(kvUrl, kvToken, path, method = 'GET', body = null) {
  const opts = { method, headers: { Authorization: `Bearer ${kvToken}`, 'Content-Type': 'application/json' } };
  if (body !== null) opts.body = JSON.stringify(body);
  return fetch(`${kvUrl}${path}`, opts).then(r => r.json());
}

export default async function handler(req) {
  if (req.method === 'OPTIONS') return new Response(null, { status: 200, headers: CORS });

  const action = req.headers.get('X-Action') || 'dashboard';
  const kvUrl = process.env.KV_REST_API_URL;
  const kvToken = process.env.KV_REST_API_TOKEN;
  const sendgridKey = process.env.SENDGRID_API_KEY; // optional — for email recovery

  // ── ACTION: SETUP (first-time password creation) ─────────────────────────
  if (action === 'setup' && req.method === 'POST') {
    const { password, email, setupKey } = await req.json();
    // Require a setup key to prevent unauthorized setup
    const validSetupKey = process.env.SETUP_KEY || 'mealdesk-setup-2026';
    if (setupKey !== validSetupKey) {
      return json({ error: 'Invalid setup key' }, 403);
    }
    if (!password || password.length < 8) {
      return json({ error: 'Password must be at least 8 characters' }, 400);
    }
    const hash = await sha256(password + (process.env.SALT || 'mdf-salt-2026'));
    if (kvUrl && kvToken) {
      await kvFetch(kvUrl, kvToken, `/set/mdf:admin:passhash`, 'POST', [hash]);
      await kvFetch(kvUrl, kvToken, `/set/mdf:admin:email`, 'POST', [email || '']);
      return json({ ok: true, message: 'Password set successfully. You can now sign in with your new password.' });
    } else {
      // No KV — can't persist the password. Tell the user.
      return json({
        ok: false,
        error: 'Storage (Vercel KV) is not configured. Password cannot be saved without KV. To use a custom password without KV, set ADMIN_PASS in your Vercel environment variables and redeploy.',
        noKV: true
      });
    }
  }

  // ── ACTION: FORGOT PASSWORD (send reset email) ────────────────────────────
  if (action === 'forgot' && req.method === 'POST') {
    const { email } = await req.json();
    if (!kvUrl || !kvToken) return json({ ok: true }); // silent fail — don't reveal KV status

    // Check email matches stored email
    const storedEmailResp = await kvFetch(kvUrl, kvToken, `/get/mdf:admin:email`);
    const storedEmail = storedEmailResp.result;

    if (!storedEmail || storedEmail !== email) {
      return json({ ok: true }); // Always return ok — security: don't reveal if email exists
    }

    // Generate reset token valid 30 min
    const token = genToken(24);
    const expires = Date.now() + 30 * 60 * 1000;
    await kvFetch(kvUrl, kvToken, `/set/mdf:admin:resettoken`, 'POST', [token]);
    await kvFetch(kvUrl, kvToken, `/set/mdf:admin:resetexpiry`, 'POST', [String(expires)]);
    await kvFetch(kvUrl, kvToken, `/expire/mdf:admin:resettoken/1800`);
    await kvFetch(kvUrl, kvToken, `/expire/mdf:admin:resetexpiry/1800`);

    // Send email via SendGrid if configured
    if (sendgridKey) {
      const resetUrl = `https://mealdesk-family.vercel.app/admin.html?reset=${token}`;
      await fetch('https://api.sendgrid.com/v3/mail/send', {
        method: 'POST',
        headers: { Authorization: `Bearer ${sendgridKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          personalizations: [{ to: [{ email }] }],
          from: { email: 'admin@mealdesk-family.app', name: 'MealDesk Admin' },
          subject: 'MealDesk Admin — Password Reset',
          content: [{
            type: 'text/html',
            value: `
              <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:24px">
                <h2 style="color:#4a7c59">MealDesk Family Admin</h2>
                <p style="color:#374151;margin:16px 0">You requested a password reset. Click the link below to set a new password. This link expires in 30 minutes.</p>
                <a href="${resetUrl}" style="display:inline-block;background:#4a7c59;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;margin:8px 0">Reset Password</a>
                <p style="color:#9ca3af;font-size:12px;margin-top:20px">If you did not request this, ignore this email. Your password has not changed.</p>
                <hr style="border:none;border-top:1px solid #e5e7eb;margin:20px 0">
                <p style="color:#9ca3af;font-size:11px">Stavros Research Labs LLC · MealDesk Family</p>
              </div>
            `
          }]
        })
      });
    }

    return json({ ok: true, message: 'If that email is registered, a reset link has been sent.' });
  }

  // ── ACTION: RESET PASSWORD (with token) ──────────────────────────────────
  if (action === 'reset' && req.method === 'POST') {
    const { token, newPassword } = await req.json();
    if (!token || !newPassword || newPassword.length < 8) {
      return json({ error: 'Invalid request' }, 400);
    }
    if (!kvUrl || !kvToken) return json({ error: 'Storage not configured' }, 503);

    const storedToken = (await kvFetch(kvUrl, kvToken, `/get/mdf:admin:resettoken`)).result;
    const storedExpiry = (await kvFetch(kvUrl, kvToken, `/get/mdf:admin:resetexpiry`)).result;

    if (!storedToken || storedToken !== token) return json({ error: 'Invalid or expired reset token' }, 400);
    if (!storedExpiry || Date.now() > Number(storedExpiry)) return json({ error: 'Reset token has expired. Request a new one.' }, 400);

    // Valid — set new password
    const hash = await sha256(newPassword + (process.env.SALT || 'mdf-salt-2026'));
    await kvFetch(kvUrl, kvToken, `/set/mdf:admin:passhash`, 'POST', [hash]);
    // Invalidate token
    await kvFetch(kvUrl, kvToken, `/del/mdf:admin:resettoken`);
    await kvFetch(kvUrl, kvToken, `/del/mdf:admin:resetexpiry`);

    return json({ ok: true, message: 'Password reset successfully. You can now log in.' });
  }

  // ── ACTION: CHANGE PASSWORD (logged in) ───────────────────────────────────
  if (action === 'changepass' && req.method === 'POST') {
    // Verify current session first
    const sessionToken = req.headers.get('Authorization')?.replace('Bearer ', '');
    if (!sessionToken || !kvUrl || !kvToken) return json({ error: 'Unauthorized' }, 401);

    const storedSession = (await kvFetch(kvUrl, kvToken, `/get/mdf:admin:session:${sessionToken}`)).result;
    if (!storedSession) return json({ error: 'Session expired. Please log in again.' }, 401);

    const { currentPassword, newPassword } = await req.json();
    if (!newPassword || newPassword.length < 8) return json({ error: 'New password must be at least 8 characters' }, 400);

    // Verify current password
    const currentHash = await sha256(currentPassword + (process.env.SALT || 'mdf-salt-2026'));
    const storedHash = (await kvFetch(kvUrl, kvToken, `/get/mdf:admin:passhash`)).result;
    if (currentHash !== storedHash) return json({ error: 'Current password is incorrect' }, 400);

    const newHash = await sha256(newPassword + (process.env.SALT || 'mdf-salt-2026'));
    await kvFetch(kvUrl, kvToken, `/set/mdf:admin:passhash`, 'POST', [newHash]);
    return json({ ok: true, message: 'Password changed successfully.' });
  }

  // ── ACTION: UPDATE EMAIL ───────────────────────────────────────────────────
  if (action === 'updateemail' && req.method === 'POST') {
    const sessionToken = req.headers.get('Authorization')?.replace('Bearer ', '');
    if (!sessionToken || !kvUrl || !kvToken) return json({ error: 'Unauthorized' }, 401);
    const storedSession = (await kvFetch(kvUrl, kvToken, `/get/mdf:admin:session:${sessionToken}`)).result;
    if (!storedSession) return json({ error: 'Session expired' }, 401);

    const { email } = await req.json();
    if (!email || !email.includes('@')) return json({ error: 'Invalid email' }, 400);
    await kvFetch(kvUrl, kvToken, `/set/mdf:admin:email`, 'POST', [email]);
    return json({ ok: true, message: 'Recovery email updated.' });
  }

  // ── ACTION: LOGIN ──────────────────────────────────────────────────────────
  if (action === 'login' && req.method === 'POST') {
    const { password } = await req.json();
    if (!password) return json({ error: 'Password required' }, 400);

    const salt = process.env.SALT || 'mdf-salt-2026';
    const hash = await sha256(password + salt);
    let authorized = false;

    if (kvUrl && kvToken) {
      // KV configured — check stored hash first
      const stored = (await kvFetch(kvUrl, kvToken, `/get/mdf:admin:passhash`)).result;
      if (stored) {
        // Hash exists — this is the authoritative check
        authorized = (hash === stored);
      } else {
        // No hash stored in KV yet (setup not done) — fall back to env var
        const envPass = process.env.ADMIN_PASS || 'stavros2026';
        // Try both hashed and plain comparison for flexibility
        const envHash = await sha256(envPass + salt);
        authorized = (hash === envHash) || (password === envPass);
      }
    } else {
      // No KV at all — use ADMIN_PASS env var
      // Support both plain comparison and hashed comparison
      const envPass = process.env.ADMIN_PASS || 'stavros2026';
      const envHash = await sha256(envPass + salt);
      authorized = (hash === envHash) || (password === envPass);
    }

    if (!authorized) return json({ error: 'Incorrect password' }, 401);

    // Create session token (24h)
    const sessionToken = genToken(32);
    if (kvUrl && kvToken) {
      await kvFetch(kvUrl, kvToken, `/set/mdf:admin:session:${sessionToken}`, 'POST', ['1']);
      await kvFetch(kvUrl, kvToken, `/expire/mdf:admin:session:${sessionToken}/86400`);
    }

    // Get recovery email
    const emailResp = kvUrl && kvToken ? await kvFetch(kvUrl, kvToken, `/get/mdf:admin:email`) : { result: null };

    return json({ ok: true, sessionToken, recoveryEmail: emailResp.result || '', kvConfigured: !!(kvUrl && kvToken) });
  }

  // ── ACTION: LOGOUT ─────────────────────────────────────────────────────────
  if (action === 'logout' && req.method === 'POST') {
    const sessionToken = req.headers.get('Authorization')?.replace('Bearer ', '');
    if (sessionToken && kvUrl && kvToken) {
      await kvFetch(kvUrl, kvToken, `/del/mdf:admin:session:${sessionToken}`);
    }
    return json({ ok: true });
  }

  // ── ACTION: DASHBOARD (default) ────────────────────────────────────────────
  if (req.method !== 'GET') return json({ error: 'Method not allowed' }, 405);

  // Verify session
  const sessionToken = req.headers.get('Authorization')?.replace('Bearer ', '');
  if (!sessionToken) return json({ error: 'No session token' }, 401);

  if (kvUrl && kvToken) {
    const storedSession = (await kvFetch(kvUrl, kvToken, `/get/mdf:admin:session:${sessionToken}`)).result;
    if (!storedSession) return json({ error: 'Session expired. Please log in again.' }, 401);
  } else {
    // No KV — trust the token for demo mode
    if (!sessionToken.startsWith('demo-')) return json({ error: 'Unauthorized' }, 401);
  }

  if (!kvUrl || !kvToken) {
    return json({ ok: true, kvConfigured: false, mockData: true });
  }

  try {
    const days7 = Array.from({ length: 7 }, (_, i) =>
      new Date(Date.now() - i * 86400000).toISOString().slice(0, 10)
    );

    const dayFetches = days7.map(day =>
      kvFetch(kvUrl, kvToken, `/lrange/mdf:events:${day}/0/199`)
        .then(r => (r.result || []).map(e => { try { return JSON.parse(e); } catch { return null; } }).filter(Boolean))
    );

    const dayEventsArr = await Promise.all(dayFetches);
    const allEvents = dayEventsArr.flat();

    const stats = { totalEvents: allEvents.length, byUser: {}, byTab: {}, byFeature: {}, byDay: {}, recentEvents: allEvents.slice(0, 30) };

    allEvents.forEach(e => {
      const u = e.user || 'unknown';
      const day = new Date(e.ts).toISOString().slice(0, 10);
      if (!stats.byUser[u]) stats.byUser[u] = { events: 0, tabs: {}, features: {}, lastSeen: 0 };
      stats.byUser[u].events++;
      if (e.ts > stats.byUser[u].lastSeen) stats.byUser[u].lastSeen = e.ts;
      if (e.event === 'tab_view') { stats.byTab[e.data] = (stats.byTab[e.data] || 0) + 1; stats.byUser[u].tabs[e.data] = (stats.byUser[u].tabs[e.data] || 0) + 1; }
      if (e.event === 'feature_use') { stats.byFeature[e.data] = (stats.byFeature[e.data] || 0) + 1; stats.byUser[u].features[e.data] = (stats.byUser[u].features[e.data] || 0) + 1; }
      stats.byDay[day] = (stats.byDay[day] || 0) + 1;
    });

    const emailResp = await kvFetch(kvUrl, kvToken, `/get/mdf:admin:email`);
    return json({ ok: true, kvConfigured: true, stats, recoveryEmail: emailResp.result || '' });
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });
}
