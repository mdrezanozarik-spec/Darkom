export const config = { runtime: "edge" };

const DESTINATION_BASE = (process.env.UPSTREAM_URL || "").replace(/\/$/, "");

// اگر خواستی IP کاربر پاس داده بشه، اینو true کن
const FORWARD_CLIENT_IP = false;

const BLOCKED_HEADERS = new Set([
  "host",
  "connection",
  "keep-alive",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "forwarded",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-port",
  "x-real-ip",
  "cf-connecting-ip",
  "true-client-ip",
]);

export default async function requestHandler(request) {
  if (!DESTINATION_BASE) {
    return new Response("UPSTREAM_URL not set", { status: 500 });
  }

  try {
    const incomingUrl = new URL(request.url);
    const destinationUrl =
      DESTINATION_BASE + incomingUrl.pathname + incomingUrl.search;

    const outgoingHeaders = new Headers();

    let detectedIp;

    for (const [headerName, headerValue] of request.headers) {
      const key = headerName.toLowerCase();

      if (BLOCKED_HEADERS.has(key)) continue;
      if (key.startsWith("x-vercel-")) continue;

      if (
        FORWARD_CLIENT_IP &&
        (key === "x-forwarded-for" || key === "x-real-ip")
      ) {
        detectedIp ||= headerValue;
        continue;
      }

      outgoingHeaders.set(headerName, headerValue);
    }

    if (FORWARD_CLIENT_IP && detectedIp) {
      outgoingHeaders.set("x-forwarded-for", detectedIp);
    }

    const hasBody =
      request.method !== "GET" && request.method !== "HEAD";

    const upstreamResponse = await fetch(destinationUrl, {
      method: request.method,
      headers: outgoingHeaders,
      body: hasBody ? request.body : undefined,
      redirect: "manual",
    });

    const responseHeaders = new Headers(upstreamResponse.headers);

    responseHeaders.delete("x-powered-by");
    responseHeaders.delete("server");

    responseHeaders.set("x-frame-options", "DENY");
    responseHeaders.set("x-content-type-options", "nosniff");
    responseHeaders.set("referrer-policy", "no-referrer");

    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      headers: responseHeaders,
    });
  } catch (error) {
    console.error("Request failed:", error);

    return new Response("Bad Gateway", {
      status: 502,
      headers: {
        "content-type": "text/plain",
      },
    });
  }
}