export async function onRequest({ request }) {
  const headers = request.headers;
  const cf = request.cf || {};
  const forwardedFor = headers.get("X-Forwarded-For");
  const fallbackIp = forwardedFor ? forwardedFor.split(",")[0].trim() : null;

  const body = {
    ip: headers.get("CF-Connecting-IP") || fallbackIp || null,
    userAgent: headers.get("User-Agent") || null,
    country: cf.country || null,
    asn: cf.asn || null,
    asOrganization: cf.asOrganization || null,
    colo: cf.colo || null,
    city: cf.city || null,
    region: cf.region || null,
    timezone: cf.timezone || null,
    httpProtocol: cf.httpProtocol || null,
    tlsVersion: cf.tlsVersion || null,
    timestamp: new Date().toISOString()
  };

  return new Response(JSON.stringify(body, null, 2), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}
