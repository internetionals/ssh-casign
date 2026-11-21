"""Stand-in for Azure's App Service managed identity endpoint
(IDENTITY_ENDPOINT / IDENTITY_HEADER), for Lowkey Vault, which accepts any
token. Test tool only.
usage: azure_identity.py <port>"""
import http.server, json, sys, time, urllib.parse


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(url.query)
        if url.path != "/msi/token" or self.headers.get("X-IDENTITY-HEADER") != "e2e":
            self.send_response(400)
            self.end_headers()
            return
        data = json.dumps({"access_token": "e2e-managed-identity-token",
                           "expires_on": str(int(time.time()) + 3600),
                           "resource": query.get("resource", [""])[0],
                           "token_type": "Bearer"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
