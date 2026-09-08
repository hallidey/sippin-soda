import http from "node:http";
import { once } from "node:events";
import { createGzip } from "node:zlib";

const server = http.createServer(async (request, response) => {
  if (request.url === "/large" || request.url === "/large-gzip") {
    const gzip = request.url === "/large-gzip";
    response.writeHead(200, {
      "Content-Type": "application/json; charset=utf-8",
      ...(gzip ? { "Content-Encoding": "gzip" } : {}),
    });
    const output = gzip ? createGzip() : response;
    if (gzip) output.pipe(response);
    response.on("close", () => {
      if (gzip) output.destroy();
    });
    const piece = "x".repeat(16 * 1024);
    try {
      output.write('{"payload":"');
      for (
        let remaining = 1800 * 1024;
        remaining > 0;
        remaining -= piece.length
      ) {
        if (response.destroyed) return;
        if (!output.write(piece.slice(0, remaining)))
          await once(output, "drain");
      }
      output.end('","tail":"END-OF-LARGE-RESPONSE"}');
    } catch {
      response.destroy();
    }
    return;
  }
  if (request.url === "/slow") {
    setTimeout(() => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end('{"status":"slow"}');
    }, 1500);
    return;
  }
  const status = request.url === "/error" ? 500 : 200;
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(
    JSON.stringify({
      status: status === 200 ? "ok" : "error",
      service: "sippin-soda-local-fixture",
    }),
  );
});
const port = Number(process.env.SIPPIN_FIXTURE_PORT || 9090);
server.listen(port, "127.0.0.1", () =>
  console.log(
    `Local HTTP fixture listening on http://127.0.0.1:${port} — /health, /slow, /error, /large, /large-gzip`,
  ),
);
