const SECURITY_HEADERS = {
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Resource-Policy": "same-origin",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/code") {
      url.pathname = "/code/";
      return Response.redirect(url.toString(), 308);
    }

    if (!url.pathname.startsWith("/code/")) {
      return withHeaders(new Response("Not found", { status: 404 }), url);
    }

    const assetRequest =
      request.method === "HEAD"
        ? new Request(request, { method: "GET" })
        : request;

    let response = await env.ASSETS.fetch(assetRequest);

    if (response.status === 404 && isNavigation(request)) {
      const indexUrl = new URL("/code/index.html", request.url);
      response = await env.ASSETS.fetch(indexUrl);
    }

    return withHeaders(response, url, request.method === "HEAD");
  },
};

function isNavigation(request) {
  return (
    request.method === "GET" &&
    (request.headers.get("Sec-Fetch-Mode") === "navigate" ||
      request.headers.get("Accept")?.includes("text/html"))
  );
}

function withHeaders(response, url, headOnly = false) {
  const headers = new Headers(response.headers);

  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    headers.set(name, value);
  }

  if (url.pathname.endsWith(".wasm")) {
    headers.set("Content-Type", "application/wasm");
  }

  if (url.pathname.match(/\.(js|wasm|png|ico|webmanifest|json|svg)$/)) {
    headers.set("Cache-Control", "public, max-age=604800");
  }

  return new Response(headOnly ? null : response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
