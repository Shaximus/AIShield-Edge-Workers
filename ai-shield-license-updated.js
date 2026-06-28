// AI Shield License Worker - With Customer Portal
// Security hardened: CORS whitelist, error sanitization, rate limiting, key format validation

const ALLOWED_ORIGINS = [
  'https://reflexionsoftware.com',
  'https://www.reflexionsoftware.com',
  'https://reflexionsoftware.pages.dev',
  'https://api.reflexionsoftware.com'
];

const LICENSE_KEY_FORMAT = /^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$/;

const RATE_LIMIT = 30;

async function checkRateLimit(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const minute = Math.floor(Date.now() / 60000);
  const key = `rl:${ip}:${minute}`;

  const current = parseInt(await env.LICENSES.get(key)) || 0;
  if (current >= RATE_LIMIT) return false;

  await env.LICENSES.put(key, String(current + 1), { expirationTtl: 120 });
  return true;
}

function getCorsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  // Allow any reflexionsoftware subdomain (covers pages.dev preview URLs)
  const isAllowed = ALLOWED_ORIGINS.includes(origin) ||
    origin.endsWith('.reflexionsoftware.pages.dev') ||
    origin.startsWith('chrome-extension://') ||
    origin.startsWith('moz-extension://');
  return {
    "Access-Control-Allow-Origin": isAllowed ? origin : ALLOWED_ORIGINS[0],
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-License-Key, Stripe-Signature, X-Signature, X-Timestamp, X-Extension-Id",
    "Content-Type": "application/json",
    "Vary": "Origin"
  };
}

function errorResponse(corsHeaders, status, userMessage) {
  return new Response(JSON.stringify({ error: userMessage }), {
    status, headers: corsHeaders
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const corsHeaders = getCorsHeaders(request);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // Rate limiting (skip for Stripe webhooks - they come from Stripe IPs)
    if (url.pathname !== "/webhook" && !await checkRateLimit(request, env)) {
      return errorResponse(corsHeaders, 429, "Too many requests. Please try again later.");
    }

    // === Customer Portal - Manage Subscription ===
    if (url.pathname === "/manage" && request.method === "POST") {
      try {
        const body = await request.json();
        const { licenseKey, email } = body;

        if (!licenseKey && !email) {
          return errorResponse(corsHeaders, 400, "License key or email required");
        }

        // Validate key format if provided
        if (licenseKey && !LICENSE_KEY_FORMAT.test(licenseKey)) {
          return errorResponse(corsHeaders, 400, "Invalid license key format");
        }

        let license = null;

        if (licenseKey) {
          license = await env.LICENSES.get(licenseKey, "json");
        } else if (email) {
          const emailIndex = await env.LICENSES.get(`email_${email.toLowerCase()}`, "json");
          if (emailIndex && emailIndex.length > 0) {
            for (const key of emailIndex) {
              const l = await env.LICENSES.get(key, "json");
              if (l && l.stripeCustomerId) { license = l; break; }
            }
          }
        }

        if (!license || !license.stripeCustomerId) {
          return errorResponse(corsHeaders, 404, "No subscription found");
        }

        const portalSession = await fetch("https://api.stripe.com/v1/billing_portal/sessions", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${env.STRIPE_SECRET_KEY}`,
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: `customer=${license.stripeCustomerId}&return_url=https://reflexionsoftware.com`
        });

        const portal = await portalSession.json();

        if (portal.url) {
          return new Response(JSON.stringify({ url: portal.url }), { headers: corsHeaders });
        } else {
          return errorResponse(corsHeaders, 500, "Could not create portal session");
        }
      } catch (error) {
        console.error("Manage error:", error);
        return errorResponse(corsHeaders, 500, "Service temporarily unavailable");
      }
    }

    // === Recover License Key ===
    if (url.pathname === "/recover" && request.method === "POST") {
      try {
        const body = await request.json();
        const { email } = body;

        if (!email) {
          return errorResponse(corsHeaders, 400, "Email required");
        }

        const emailIndex = await env.LICENSES.get(`email_${email.toLowerCase()}`, "json");
        if (!emailIndex || emailIndex.length === 0) {
          return errorResponse(corsHeaders, 404, "No license found for this email");
        }

        const results = [];
        for (const key of emailIndex) {
          const license = await env.LICENSES.get(key, "json");
          if (license) {
            const parts = key.split("-");
            const masked = parts.length === 4
              ? `${parts[0]}-*****-*****-${parts[3]}`
              : key.substring(0, 5) + "-***-" + key.substring(key.length - 5);
            results.push({ maskedKey: masked, type: license.type, createdAt: license.createdAt });
          }
        }

        return new Response(JSON.stringify({ licenses: results }), { headers: corsHeaders });
      } catch (error) {
        console.error("Recover error:", error);
        return errorResponse(corsHeaders, 500, "Service temporarily unavailable");
      }
    }

    // === Get license by Stripe session ID ===
    if (url.pathname === "/get-license-by-session" && request.method === "GET") {
      const sessionId = url.searchParams.get("session_id");
      if (!sessionId) {
        return errorResponse(corsHeaders, 400, "Missing session_id");
      }

      const sessionKey = `session_${sessionId}`;
      const licenseKey = await env.LICENSES.get(sessionKey);

      if (!licenseKey) {
        return new Response(JSON.stringify({
          error: "License not found",
          message: "License may still be processing. Check your email."
        }), { status: 404, headers: corsHeaders });
      }

      const license = await env.LICENSES.get(licenseKey, "json");
      if (!license) {
        return errorResponse(corsHeaders, 404, "License data not found");
      }

      return new Response(JSON.stringify({
        licenseKey: licenseKey,
        email: license.email,
        type: license.type
      }), { headers: corsHeaders });
    }

    // === Stripe Webhook ===
    if (url.pathname === "/webhook" && request.method === "POST") {
      try {
        const body = await request.text();
        const signature = request.headers.get("stripe-signature");

        if (!signature || !env.STRIPE_WEBHOOK_SECRET) {
          console.error("Missing signature or webhook secret");
          return errorResponse(corsHeaders, 401, "Webhook verification failed");
        }

        const event = await verifyStripeWebhook(body, signature, env.STRIPE_WEBHOOK_SECRET);
        if (!event) {
          console.error("Invalid webhook signature");
          return errorResponse(corsHeaders, 401, "Invalid signature");
        }

        console.log("Webhook verified:", event.type);

        if (event.type === "checkout.session.completed") {
          const session = event.data.object;
          const stripeSession = await fetchStripeSession(session.id, env.STRIPE_SECRET_KEY);

          if (!stripeSession) {
            return errorResponse(corsHeaders, 500, "Processing error");
          }

          const customerEmail = stripeSession.customer_email || stripeSession.customer_details?.email;
          const lineItems = stripeSession.line_items?.data || [];
          const licenseType = determineLicenseType(lineItems);

          if (!licenseType) {
            return errorResponse(corsHeaders, 400, "Unknown product");
          }

          const licenseKey = generateLicenseKey();
          let expiresAt = null;
          if (licenseType === "monthly") {
            expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
          } else if (licenseType === "annual") {
            expiresAt = Date.now() + 365 * 24 * 60 * 60 * 1000;
          }

          const licenseData = {
            key: licenseKey,
            email: customerEmail,
            type: licenseType,
            stripeSessionId: session.id,
            stripeCustomerId: stripeSession.customer,
            createdAt: Date.now(),
            expiresAt,
            machines: 3,
            activations: []
          };

          await env.LICENSES.put(licenseKey, JSON.stringify(licenseData));
          await env.LICENSES.put(`session_${session.id}`, licenseKey, { expirationTtl: 86400 * 7 });

          if (stripeSession.customer) {
            const customerKey = `customer_${stripeSession.customer}`;
            const existingLicenses = await env.LICENSES.get(customerKey, "json") || [];
            existingLicenses.push(licenseKey);
            await env.LICENSES.put(customerKey, JSON.stringify(existingLicenses));
          }

          if (customerEmail) {
            const emailKey = `email_${customerEmail.toLowerCase()}`;
            const emailLicenses = await env.LICENSES.get(emailKey, "json") || [];
            emailLicenses.push(licenseKey);
            await env.LICENSES.put(emailKey, JSON.stringify(emailLicenses));
          }

          console.log(`License created: ${licenseKey} for ${customerEmail} (${licenseType})`);

          return new Response(JSON.stringify({ received: true }), { headers: corsHeaders });
        }

        if (event.type === "customer.subscription.updated") {
          const subscription = event.data.object;
          const customerId = subscription.customer;

          const licenses = await findLicensesByCustomer(customerId, env);
          for (const license of licenses) {
            license.expiresAt = subscription.current_period_end * 1000;
            await env.LICENSES.put(license.key, JSON.stringify(license));
            console.log(`License renewed: ${license.key}`);
          }

          return new Response(JSON.stringify({ received: true }), { headers: corsHeaders });
        }

        if (event.type === "customer.subscription.deleted") {
          const subscription = event.data.object;
          const customerId = subscription.customer;

          const licenses = await findLicensesByCustomer(customerId, env);
          for (const license of licenses) {
            license.expiresAt = Date.now();
            await env.LICENSES.put(license.key, JSON.stringify(license));
            console.log(`License expired: ${license.key}`);
          }

          return new Response(JSON.stringify({ received: true }), { headers: corsHeaders });
        }

        return new Response(JSON.stringify({ received: true }), { headers: corsHeaders });
      } catch (error) {
        console.error("Webhook error:", error);
        return errorResponse(corsHeaders, 500, "Webhook processing failed");
      }
    }

    // === Verify License ===
    if (url.pathname === "/verify-license" && request.method === "POST") {
      const licenseKey = request.headers.get("X-License-Key");
      if (!licenseKey) {
        return new Response(JSON.stringify({ valid: false, error: "No license key provided" }), {
          status: 401, headers: corsHeaders
        });
      }

      // Validate format before hitting KV
      if (!LICENSE_KEY_FORMAT.test(licenseKey)) {
        return new Response(JSON.stringify({ valid: false, error: "Invalid license key" }), {
          status: 401, headers: corsHeaders
        });
      }

      const license = await env.LICENSES.get(licenseKey, "json");
      if (!license) {
        return new Response(JSON.stringify({ valid: false, error: "Invalid license key" }), {
          status: 401, headers: corsHeaders
        });
      }

      const now = Date.now();

      // Check expiry first (before device enforcement)
      const isLifetime = license.type === "lifetime";
      const isActive = isLifetime || (license.expiresAt && license.expiresAt > now);

      if (!isActive) {
        return new Response(JSON.stringify({
          valid: false, error: "License expired", renewUrl: "https://reflexionsoftware.com/#pricing"
        }), { status: 402, headers: corsHeaders });
      }

      // === Device limit enforcement ===
      const extensionId = request.headers.get("X-Extension-Id");
      const activations = license.activations || [];
      const maxDevices = license.machines || 3;
      let licenseModified = false;

      if (extensionId) {
        const alreadyActivated = activations.some(a => a.extensionId === extensionId);

        if (!alreadyActivated) {
          if (activations.length >= maxDevices) {
            return new Response(JSON.stringify({
              valid: false,
              error: "Device limit reached. Maximum " + maxDevices + " devices per license.",
              devicesUsed: activations.length,
              devicesAllowed: maxDevices
            }), { status: 403, headers: corsHeaders });
          }

          // Auto-activate this device
          activations.push({ extensionId, activatedAt: Date.now() });
          license.activations = activations;
          licenseModified = true;
        }
      } else {
        // No X-Extension-Id header — old extension version. Allow but log warning.
        console.warn("verify-license: No X-Extension-Id header. Skipping device enforcement for backwards compatibility. Key:", licenseKey.substring(0, 5) + "...");
      }

      // Generate ruleSalt and persist
      const ruleSalt = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('');
      license.ruleSalt = ruleSalt;
      license.ruleSaltCreated = Date.now();
      await env.LICENSES.put(licenseKey, JSON.stringify(license));

      if (isLifetime) {
        return new Response(JSON.stringify({
          valid: true, type: "lifetime", email: license.email, createdAt: license.createdAt, ruleSalt
        }), { headers: corsHeaders });
      }

      return new Response(JSON.stringify({
        valid: true, type: license.type, expiresAt: license.expiresAt, email: license.email, ruleSalt
      }), { headers: corsHeaders });
    }

    // === Activate License ===
    if (url.pathname === "/activate" && request.method === "POST") {
      try {
        const body = await request.json();
        const { licenseKey, machineId } = body;

        if (!licenseKey || !machineId) {
          return errorResponse(corsHeaders, 400, "Missing data");
        }

        if (!LICENSE_KEY_FORMAT.test(licenseKey)) {
          return errorResponse(corsHeaders, 400, "Invalid license key format");
        }

        const license = await env.LICENSES.get(licenseKey, "json");
        if (!license) {
          return new Response(JSON.stringify({ success: false, error: "Invalid license" }), {
            status: 404, headers: corsHeaders
          });
        }

        const activations = license.activations || [];
        if (activations.find(a => a.machineId === machineId)) {
          return new Response(JSON.stringify({ success: true, message: "Already activated" }), {
            headers: corsHeaders
          });
        }

        if (activations.length >= license.machines) {
          return new Response(JSON.stringify({
            success: false,
            error: `Max ${license.machines} machines reached`
          }), { status: 403, headers: corsHeaders });
        }

        activations.push({ machineId, activatedAt: Date.now() });
        license.activations = activations;
        await env.LICENSES.put(licenseKey, JSON.stringify(license));

        return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
      } catch (error) {
        console.error("Activate error:", error);
        return errorResponse(corsHeaders, 500, "Activation failed");
      }
    }

    return errorResponse(corsHeaders, 404, "Not found");
  }
};

function generateLicenseKey() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 31 chars
  // Rejection threshold: largest multiple of 31 that fits in a byte (31 * 8 = 248)
  const rejectThreshold = 248;
  let key = "";
  for (let i = 0; i < 20; i++) {
    if (i > 0 && i % 5 === 0) key += "-";
    let byte;
    do {
      byte = crypto.getRandomValues(new Uint8Array(1))[0];
    } while (byte >= rejectThreshold); // Re-sample to eliminate modular bias
    key += chars[byte % chars.length];
  }
  return key;
}

async function fetchStripeSession(sessionId, stripeSecretKey) {
  try {
    const response = await fetch(
      `https://api.stripe.com/v1/checkout/sessions/${sessionId}?expand[]=line_items`,
      {
        headers: {
          "Authorization": `Bearer ${stripeSecretKey}`,
          "Content-Type": "application/x-www-form-urlencoded"
        }
      }
    );
    if (!response.ok) return null;
    return await response.json();
  } catch (error) {
    return null;
  }
}

function determineLicenseType(lineItems) {
  if (!lineItems || lineItems.length === 0) return null;
  const item = lineItems[0];
  const productName = item.description?.toLowerCase() || "";

  if (productName.includes("monthly")) return "monthly";
  if (productName.includes("annual") || productName.includes("yearly")) return "annual";
  if (productName.includes("lifetime") || productName.includes("founder")) return "lifetime";

  if (item.price?.recurring) {
    const interval = item.price.recurring.interval;
    if (interval === "month") return "monthly";
    if (interval === "year") return "annual";
  }

  const amount = item.price?.unit_amount || 0;
  if (amount === 999) return "monthly";
  if (amount === 9900) return "annual";
  if (amount >= 24900) return "lifetime";

  return "lifetime";
}

async function findLicensesByCustomer(customerId, env) {
  const customerKey = `customer_${customerId}`;
  const licenseKeys = await env.LICENSES.get(customerKey, "json") || [];

  const licenses = [];
  for (const key of licenseKeys) {
    const license = await env.LICENSES.get(key, "json");
    if (license) licenses.push(license);
  }
  return licenses;
}

async function verifyStripeWebhook(payload, signature, secret) {
  try {
    const parts = signature.split(',').reduce((acc, part) => {
      const [key, value] = part.split('=');
      acc[key] = value;
      return acc;
    }, {});

    const timestamp = parts['t'];
    const sig = parts['v1'];

    if (!timestamp || !sig) {
      console.error("Missing timestamp or signature in header");
      return null;
    }

    const tolerance = 300;
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - parseInt(timestamp)) > tolerance) {
      console.error("Webhook timestamp too old");
      return null;
    }

    const signedPayload = `${timestamp}.${payload}`;
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const signatureBytes = await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(signedPayload)
    );

    const expectedSig = Array.from(new Uint8Array(signatureBytes))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    if (expectedSig.length !== sig.length) {
      console.error("Signature length mismatch");
      return null;
    }

    let result = 0;
    for (let i = 0; i < expectedSig.length; i++) {
      result |= expectedSig.charCodeAt(i) ^ sig.charCodeAt(i);
    }

    if (result !== 0) {
      console.error("Signature mismatch");
      return null;
    }

    return JSON.parse(payload);
  } catch (error) {
    console.error("Webhook verification error:", error);
    return null;
  }
}
