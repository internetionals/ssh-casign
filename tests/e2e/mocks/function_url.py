"""HTTP -> Lambda Function URL events (payload 2.0) -> the runtime interface
emulator; the way a Function URL invokes a function. Test tool only.
usage: function_url.py <port> <invoke URL>"""
import base64, json, sys, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN, INVOKE = int(sys.argv[1]), sys.argv[2]
CLIENT_IP = "203.0.113.5"   # what the Function URL front end would report

class Handler(BaseHTTPRequestHandler):
    def handle_any(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        path, _, query = self.path.partition("?")
        headers = {k.lower(): v for k, v in self.headers.items()}
        headers["x-forwarded-for"] = CLIENT_IP
        event = {
            "version": "2.0", "routeKey": "$default", "rawPath": path, "rawQueryString": query,
            "headers": headers,
            "requestContext": {
                "accountId": "anonymous", "apiId": "local", "domainName": "local.lambda-url.on.aws",
                "domainPrefix": "local", "requestId": str(time.time_ns()), "routeKey": "$default",
                "stage": "$default", "time": time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime()),
                "timeEpoch": int(time.time() * 1000),
                "http": {"method": self.command, "path": path, "protocol": "HTTP/1.1",
                         "sourceIp": CLIENT_IP, "userAgent": headers.get("user-agent", "")},
            },
            "body": base64.b64encode(body).decode() if body else None,
            "isBase64Encoded": bool(body),
        }
        req = urllib.request.Request(INVOKE, data=json.dumps(event).encode(), method="POST")
        result = json.load(urllib.request.urlopen(req, timeout=60))
        payload = result.get("body") or ""
        payload = base64.b64decode(payload) if result.get("isBase64Encoded") else payload.encode()
        self.send_response(result.get("statusCode", 502))
        for k, v in (result.get("headers") or {}).items():
            if k.lower() not in ("content-length", "transfer-encoding"):
                self.send_header(k, v)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    do_GET = do_POST = handle_any
    def log_message(self, *args): pass

ThreadingHTTPServer(("127.0.0.1", LISTEN), Handler).serve_forever()
