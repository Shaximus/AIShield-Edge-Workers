
addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

const PUBLIC_JWK = {"kty": "EC", "key_ops": ["verify"], "ext": true, "crv": "P-256", "x": "VJXsknsZ7Xl3zms8l9pZtjkKirm6lwWs2ZI3_39WuwQ", "y": "nxR1DuMyiQQmi--wTDDU9vsv0jC6eVatA57V6a9fKmA"};

async function handleRequest(request) {
  const url = new URL(request.url);
  const token = url.searchParams.get("token");

  if (!token) {
    return new Response(JSON.stringify({error: "No token"}), {headers:{"Content-Type":"application/json"}});
  }

  const publicKey = await crypto.subtle.importKey("jwk", PUBLIC_JWK, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);

  const parts = token.split('.');
  if (parts.length !== 3) {
    return new Response(JSON.stringify({error: "Invalid JWT format"}), {headers:{"Content-Type":"application/json"}});
  }

  const signingInput = parts[0] + "." + parts[1];
  const encodedSignature = parts[2];

  let str = encodedSignature.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const binary = atob(str);
  const signatureBytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    signatureBytes[i] = binary.charCodeAt(i);
  }

  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    publicKey,
    signatureBytes,
    new TextEncoder().encode(signingInput)
  );

  if (!valid) {
    return new Response(JSON.stringify({error: "Invalid signature", sig_length: signatureBytes.length}), {headers:{"Content-Type":"application/json"}});
  }

  let pstr = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  while (pstr.length % 4) pstr += "=";
  const payload = JSON.parse(atob(pstr));

  const now = Math.floor(Date.now() / 1000);

  if (payload.exp && now >= payload.exp) {
    return new Response(JSON.stringify({error: "Token expired", now, exp: payload.exp}), {headers:{"Content-Type":"application/json"}});
  }

  if (payload.iat && Math.abs(now - payload.iat) > 60) {
    return new Response(JSON.stringify({error: "iat too far", now, iat: payload.iat, diff: Math.abs(now - payload.iat)}), {headers:{"Content-Type":"application/json"}});
  }

  if (payload.aud !== "telephone-proxy-api") {
    return new Response(JSON.stringify({error: "Invalid audience", aud: payload.aud}), {headers:{"Content-Type":"application/json"}});
  }

  return new Response(JSON.stringify({valid: true, payload}), {headers:{"Content-Type":"application/json"}});
}
