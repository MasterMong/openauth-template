import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

// This value should be shared between the OpenAuth server Worker and other
// client Workers that you connect to it, so the types and schema validation are
// consistent.
const subjects = createSubjects({
  user: object({
    id: string(),
  }),
});

/**
 * OpenAuth Template Worker with Google OAuth Support
 * Enhanced authentication system with D1 database integration
 */

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method;

      // CORS headers for API endpoints
      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      };

      // Handle preflight requests
      if (method === 'OPTIONS') {
        return new Response(null, { headers: corsHeaders });
      }

      // Router
      switch (path) {
        case '/auth/google':
          return handleGoogleAuthRedirect(env);
        
        case '/auth/google/callback':
          return handleGoogleCallback(request, env);
        
        case '/auth/logout':
          return handleLogout();
        
        case '/auth/me':
          return handleMe(request, env, corsHeaders);
        
        case '/api/users':
          return handleUsersAPI(request, env, corsHeaders);
        
        case '/health':
          return handleHealth(env);
        
        case '/':
          return handleHome(request, env);
        
        default:
          return new Response('Not Found', { status: 404 });
      }
    } catch (error) {
      console.error('Worker error:', error);
      return new Response('Internal Server Error', { status: 500 });
    }
  },
};

/**
 * Generate a cryptographically secure random state parameter
 */
function generateState() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode.apply(null, array))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Generate a secure random string for JWT secret if not provided
 */
function generateSecureSecret() {
  const array = new Uint8Array(64);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode.apply(null, array));
}

/**
 * Handle Google OAuth redirect - starts the OAuth flow
 */
async function handleGoogleAuthRedirect(env) {
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_REDIRECT_URI) {
    return new Response('Google OAuth not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_REDIRECT_URI environment variables.', { 
      status: 500 
    });
  }

  const state = generateState();
  const scopes = ['openid', 'email', 'profile'];
  
  const params = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: env.GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: scopes.join(' '),
    state: state,
    access_type: 'offline',
    prompt: 'consent'
  });

  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
  
  // Store state in a secure cookie for verification
  const response = Response.redirect(authUrl, 302);
  response.headers.set('Set-Cookie', `oauth_state=${state}; HttpOnly; Secure; SameSite=Lax; Max-Age=600; Path=/`);
  
  return response;
}

/**
 * Handle Google OAuth callback - processes the authorization code
 */
async function handleGoogleCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  if (error) {
    console.error('OAuth error:', error);
    return createErrorPage(`OAuth Error: ${error}. Please try again.`);
  }

  if (!code || !state) {
    return createErrorPage('Missing authorization code or state parameter. Please try again.');
  }

  // Verify state parameter to prevent CSRF attacks
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const storedState = cookies.oauth_state;
  
  if (!storedState || storedState !== state) {
    return createErrorPage('Invalid state parameter. This may be a security issue. Please try again.');
  }

  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET || !env.GOOGLE_REDIRECT_URI) {
    return createErrorPage('Google OAuth not properly configured on server.');
  }

  try {
    // Exchange authorization code for access token
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        code: code,
        grant_type: 'authorization_code',
        redirect_uri: env.GOOGLE_REDIRECT_URI,
      }),
    });

    if (!tokenResponse.ok) {
      const errorData = await tokenResponse.text();
      console.error('Token exchange failed:', errorData);
      return createErrorPage('Failed to exchange authorization code for token. Please try again.');
    }

    const tokens = await tokenResponse.json();
    
    if (!tokens.access_token) {
      console.error('No access token received:', tokens);
      return createErrorPage('No access token received from Google. Please try again.');
    }
    
    // Get user information from Google API
    const userResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: {
        'Authorization': `Bearer ${tokens.access_token}`,
      },
    });

    if (!userResponse.ok) {
      console.error('Failed to get user info:', await userResponse.text());
      return createErrorPage('Failed to retrieve user information from Google. Please try again.');
    }

    const googleUser = await userResponse.json();
    
    if (!googleUser.email) {
      return createErrorPage('No email address received from Google. Please ensure your Google account has an email address.');
    }
    
    // Create or update user in database
    const user = await createOrUpdateUser(env, googleUser);
    
    if (!user) {
      return createErrorPage('Failed to create or update user in database. Please try again.');
    }
    
    // Create session token
    const sessionToken = await createSessionToken(user, env);
    
    // Set session cookie and redirect to home
    const response = Response.redirect('/', 302);
    response.headers.set('Set-Cookie', `session=${sessionToken}; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000; Path=/`); // 30 days
    response.headers.set('Set-Cookie', `oauth_state=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/`); // Clear state cookie
    
    return response;

  } catch (error) {
    console.error('OAuth callback error:', error);
    return createErrorPage('Authentication failed due to a server error. Please try again.');
  }
}

/**
 * Create or update user in D1 database
 */
async function createOrUpdateUser(env, googleUser) {
  if (!env.DB) {
    console.error('Database not configured');
    return null;
  }

  const { email, name, picture, id: googleId } = googleUser;
  
  try {
    // Check if user exists by email
    const existingUser = await env.DB.prepare(
      'SELECT * FROM user WHERE email = ?'
    ).bind(email).first();

    if (existingUser) {
      // Update existing user with Google information
      const updateResult = await env.DB.prepare(
        'UPDATE user SET google_id = ?, name = ?, picture = ?, updated_at = CURRENT_TIMESTAMP WHERE email = ? RETURNING *'
      ).bind(googleId, name, picture, email).first();
      
      return updateResult || { ...existingUser, google_id: googleId, name, picture };
    } else {
      // Create new user
      const insertResult = await env.DB.prepare(
        'INSERT INTO user (email, google_id, name, picture) VALUES (?, ?, ?, ?) RETURNING *'
      ).bind(email, googleId, name, picture).first();
      
      return insertResult;
    }
  } catch (error) {
    console.error('Database error in createOrUpdateUser:', error);
    return null;
  }
}

/**
 * Create a JWT session token
 */
async function createSessionToken(user, env) {
  const secret = env.JWT_SECRET || generateSecureSecret();
  
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };

  const payload = {
    userId: user.id,
    email: user.email,
    name: user.name,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60), // 30 days
  };

  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  
  const signatureInput = `${headerB64}.${payloadB64}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signatureInput));
  const signatureB64 = base64UrlEncode(new Uint8Array(signature));
  
  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

/**
 * Verify JWT session token
 */
async function verifySessionToken(token, env) {
  if (!token) return null;
  
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  
  try {
    const secret = env.JWT_SECRET || generateSecureSecret();
    const [headerB64, payloadB64, signatureB64] = parts;
    
    // Verify signature
    const signatureInput = `${headerB64}.${payloadB64}`;
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    const signature = base64UrlDecode(signatureB64);
    const isValid = await crypto.subtle.verify(
      'HMAC',
      key,
      signature,
      new TextEncoder().encode(signatureInput)
    );
    
    if (!isValid) return null;
    
    // Parse and validate payload
    const payload = JSON.parse(base64UrlDecodeString(payloadB64));
    
    // Check expiration
    if (payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    
    return payload;
  } catch (error) {
    console.error('Token verification error:', error);
    return null;
  }
}

/**
 * Handle logout - clear session cookie
 */
async function handleLogout() {
  const response = Response.redirect('/', 302);
  response.headers.set('Set-Cookie', 'session=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/');
  return response;
}

/**
 * Handle /auth/me endpoint - returns current user info
 */
async function handleMe(request, env, corsHeaders) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const sessionToken = cookies.session;
  
  const session = await verifySessionToken(sessionToken, env);
  if (!session) {
    return new Response(JSON.stringify({ error: 'Not authenticated' }), { 
      status: 401,
      headers: { 
        'Content-Type': 'application/json',
        ...corsHeaders
      }
    });
  }
  
  try {
    const user = await env.DB.prepare(
      'SELECT id, email, name, picture, created_at, updated_at FROM user WHERE id = ?'
    ).bind(session.userId).first();
    
    if (!user) {
      return new Response(JSON.stringify({ error: 'User not found' }), { 
        status: 404,
        headers: { 
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    }
    
    return new Response(JSON.stringify(user), {
      headers: { 
        'Content-Type': 'application/json',
        ...corsHeaders
      }
    });
  } catch (error) {
    console.error('Database error in handleMe:', error);
    return new Response(JSON.stringify({ error: 'Database error' }), {
      status: 500,
      headers: { 
        'Content-Type': 'application/json',
        ...corsHeaders
      }
    });
  }
}

/**
 * Handle users API endpoint - list users (admin functionality)
 */
async function handleUsersAPI(request, env, corsHeaders) {
  const method = request.method;
  
  if (method === 'GET') {
    try {
      const users = await env.DB.prepare(
        'SELECT id, email, name, picture, created_at, updated_at FROM user ORDER BY created_at DESC LIMIT 50'
      ).all();
      
      return new Response(JSON.stringify(users.results || []), {
        headers: { 
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    } catch (error) {
      console.error('Database error in handleUsersAPI:', error);
      return new Response(JSON.stringify({ error: 'Database error' }), {
        status: 500,
        headers: { 
          'Content-Type': 'application/json',
          ...corsHeaders
        }
      });
    }
  }
  
  return new Response(JSON.stringify({ error: 'Method not allowed' }), {
    status: 405,
    headers: { 
      'Content-Type': 'application/json',
      ...corsHeaders
    }
  });
}

/**
 * Handle health check endpoint
 */
async function handleHealth(env) {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    database: 'unknown',
    environment: {
      hasGoogleClientId: !!env.GOOGLE_CLIENT_ID,
      hasGoogleClientSecret: !!env.GOOGLE_CLIENT_SECRET,
      hasGoogleRedirectUri: !!env.GOOGLE_REDIRECT_URI,
      hasJwtSecret: !!env.JWT_SECRET,
      hasDatabase: !!env.DB
    }
  };
  
  // Test database connection
  if (env.DB) {
    try {
      await env.DB.prepare('SELECT 1').first();
      health.database = 'connected';
    } catch (error) {
      health.database = 'error';
      health.status = 'degraded';
    }
  } else {
    health.database = 'not_configured';
    health.status = 'degraded';
  }
  
  const status = health.status === 'healthy' ? 200 : 503;
  
  return new Response(JSON.stringify(health, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

/**
 * Handle home page with authentication UI
 */
async function handleHome(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const sessionToken = cookies.session;
  
  const session = await verifySessionToken(sessionToken, env);
  let user = null;
  
  if (session && env.DB) {
    try {
      user = await env.DB.prepare(
        'SELECT id, email, name, picture, created_at FROM user WHERE id = ?'
      ).bind(session.userId).first();
    } catch (error) {
      console.error('Database error in handleHome:', error);
    }
  }
  
  const isConfigured = !!(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET && env.GOOGLE_REDIRECT_URI);
  
  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>OpenAuth Template - Google OAuth</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
          line-height: 1.6; 
          color: #333; 
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          min-height: 100vh;
          padding: 20px;
        }
        .container { 
          max-width: 800px; 
          margin: 0 auto; 
          background: white;
          border-radius: 10px;
          box-shadow: 0 10px 30px rgba(0,0,0,0.2);
          overflow: hidden;
        }
        .header {
          background: #4285f4;
          color: white;
          padding: 30px;
          text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { opacity: 0.9; font-size: 1.1em; }
        .content { padding: 30px; }
        .user-info { 
          background: #f8f9fa; 
          padding: 30px; 
          border-radius: 10px; 
          margin: 20px 0;
          border-left: 4px solid #4285f4;
        }
        .user-avatar { 
          width: 60px; 
          height: 60px; 
          border-radius: 50%; 
          margin-right: 20px; 
          vertical-align: middle;
          border: 3px solid #4285f4;
        }
        .btn { 
          background: #4285f4; 
          color: white; 
          border: none; 
          padding: 15px 30px; 
          border-radius: 5px; 
          cursor: pointer;
          font-size: 16px;
          text-decoration: none;
          display: inline-block;
          transition: background 0.3s;
        }
        .btn:hover { background: #357ae8; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .api-section { margin-top: 30px; }
        .endpoint { 
          background: #f8f9fa; 
          padding: 15px; 
          border-radius: 5px; 
          margin: 10px 0;
          border-left: 3px solid #6c757d;
        }
        .status { 
          display: inline-block; 
          padding: 5px 10px; 
          border-radius: 3px; 
          font-size: 12px; 
          font-weight: bold;
        }
        .status.success { background: #d4edda; color: #155724; }
        .status.error { background: #f8d7da; color: #721c24; }
        .alert { 
          padding: 15px; 
          margin: 20px 0; 
          border-radius: 5px; 
          border-left: 4px solid #f39c12;
          background: #fef9e7;
          color: #8a6d3b;
        }
        .footer { 
          text-align: center; 
          padding: 20px; 
          color: #666; 
          border-top: 1px solid #eee;
          background: #f8f9fa;
        }
        code { 
          background: #e9ecef; 
          padding: 2px 6px; 
          border-radius: 3px; 
          font-family: 'Monaco', 'Consolas', monospace;
        }
        .user-details { margin-top: 15px; }
        .user-details p { margin: 5px 0; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>🔐 OpenAuth Template</h1>
          <p>Google OAuth Integration for Cloudflare Workers</p>
        </div>
        
        <div class="content">
          ${!isConfigured ? `
            <div class="alert">
              <strong>⚠️ Configuration Required</strong><br>
              Please set up your Google OAuth credentials in environment variables:
              <ul style="margin: 10px 0; padding-left: 20px;">
                <li><code>GOOGLE_CLIENT_ID</code></li>
                <li><code>GOOGLE_CLIENT_SECRET</code></li>
                <li><code>GOOGLE_REDIRECT_URI</code></li>
              </ul>
            </div>
          ` : ''}
          
          ${user ? `
            <div class="user-info">
              <h2>🎉 Welcome back, ${user.name || user.email}!</h2>
              <div style="display: flex; align-items: center; margin: 20px 0;">
                ${user.picture ? `<img src="${user.picture}" alt="Profile" class="user-avatar">` : ''}
                <div class="user-details">
                  <p><strong>📧 Email:</strong> ${user.email}</p>
                  <p><strong>🆔 User ID:</strong> ${user.id}</p>
                  <p><strong>📅 Member since:</strong> ${new Date(user.created_at).toLocaleDateString()}</p>
                </div>
              </div>
              <a href="/auth/logout" class="btn btn-danger">🚪 Sign Out</a>
            </div>
          ` : `
            <div class="user-info">
              <h2>👋 Welcome to OpenAuth Template</h2>
              <p style="margin: 15px 0;">Secure authentication with Google OAuth 2.0</p>
              ${isConfigured ? `
                <a href="/auth/google" class="btn">🔑 Sign in with Google</a>
              ` : `
                <button class="btn" disabled>🔑 Sign in with Google (Not Configured)</button>
              `}
            </div>
          `}
          
          <div class="api-section">
            <h2>📡 API Endpoints</h2>
            <div class="endpoint">
              <strong>GET <code>/auth/google</code></strong> - Start Google OAuth flow
              <span class="status ${isConfigured ? 'success' : 'error'}">${isConfigured ? 'Ready' : 'Not Configured'}</span>
            </div>
            <div class="endpoint">
              <strong>GET <code>/auth/google/callback</code></strong> - OAuth callback handler
            </div>
            <div class="endpoint">
              <strong>GET <code>/auth/me</code></strong> - Get current user info (JSON)
              <button onclick="testAPI('/auth/me')" class="btn" style="margin-left: 10px; padding: 5px 15px; font-size: 14px;">Test</button>
            </div>
            <div class="endpoint">
              <strong>GET <code>/auth/logout</code></strong> - Clear session and logout
            </div>
            <div class="endpoint">
              <strong>GET <code>/api/users</code></strong> - List all users (demo)
              <button onclick="testAPI('/api/users')" class="btn" style="margin-left: 10px; padding: 5px 15px; font-size: 14px;">Test</button>
            </div>
            <div class="endpoint">
              <strong>GET <code>/health</code></strong> - System health check
              <button onclick="testAPI('/health')" class="btn" style="margin-left: 10px; padding: 5px 15px; font-size: 14px;">Test</button>
            </div>
          </div>
          
          <div id="api-response" style="margin-top: 20px;"></div>
        </div>
        
        <div class="footer">
          <p>Built with ❤️ using Cloudflare Workers, D1 Database, and Google OAuth 2.0</p>
          <p>OpenAuth Template - Secure, Fast, Serverless Authentication</p>
        </div>
      </div>
      
      <script>
        async function testAPI(endpoint) {
          const responseDiv = document.getElementById('api-response');
          responseDiv.innerHTML = '<p>🔄 Testing endpoint...</p>';
          
          try {
            const response = await fetch(endpoint);
            const data = await response.json();
            const statusColor = response.ok ? '#155724' : '#721c24';
            const statusBg = response.ok ? '#d4edda' : '#f8d7da';
            
            responseDiv.innerHTML = \`
              <div style="background: \${statusBg}; color: \${statusColor}; padding: 15px; border-radius: 5px; margin: 10px 0;">
                <strong>\${endpoint}</strong> - Status: \${response.status}<br>
                <pre style="margin-top: 10px; white-space: pre-wrap;">\${JSON.stringify(data, null, 2)}</pre>
              </div>
            \`;
          } catch (error) {
            responseDiv.innerHTML = \`
              <div style="background: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; margin: 10px 0;">
                <strong>Error testing \${endpoint}:</strong><br>
                \${error.message}
              </div>
            \`;
          }
        }
      </script>
    </body>
    </html>
  `;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html' }
  });
}

/**
 * Create an error page for OAuth failures
 */
function createErrorPage(message) {
  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Authentication Error</title>
      <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
        .error-container { 
          background: white; 
          padding: 40px; 
          border-radius: 10px; 
          box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
          max-width: 500px; 
          margin: 0 auto; 
        }
        .error-icon { font-size: 4em; margin-bottom: 20px; }
        h1 { color: #dc3545; margin-bottom: 20px; }
        p { margin-bottom: 30px; color: #666; }
        .btn { 
          background: #4285f4; 
          color: white; 
          padding: 12px 24px; 
          border: none; 
          border-radius: 5px; 
          text-decoration: none; 
          display: inline-block;
        }
      </style>
    </head>
    <body>
      <div class="error-container">
        <div class="error-icon">❌</div>
        <h1>Authentication Error</h1>
        <p>${message}</p>
        <a href="/" class="btn">← Back to Home</a>
      </div>
    </body>
    </html>
  `;
  
  return new Response(html, {
    status: 400,
    headers: { 'Content-Type': 'text/html' }
  });
}

/**
 * Utility function to parse cookies from request headers
 */
function parseCookies(cookieHeader) {
  const cookies = {};
  if (cookieHeader) {
    cookieHeader.split(';').forEach(cookie => {
      const [name, value] = cookie.trim().split('=');
      if (name && value) {
        cookies[name] = decodeURIComponent(value);
      }
    });
  }
  return cookies;
}

/**
 * Base64 URL encode (RFC 4648)
 */
function base64UrlEncode(data) {
  if (typeof data === 'string') {
    data = new TextEncoder().encode(data);
  }
  return btoa(String.fromCharCode.apply(null, data))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Base64 URL decode to Uint8Array
 */
function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) {
    str += '=';
  }
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Base64 URL decode to string
 */
function base64UrlDecodeString(str) {
  return new TextDecoder().decode(base64UrlDecode(str));
}
