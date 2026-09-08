import http from "node:http";

const server = http.createServer((request, response) => {
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
server.listen(9090, "127.0.0.1", () =>
  console.log(
    "Local HTTP fixture listening on http://127.0.0.1:9090 — /health, /slow, /error",
  ),
);
