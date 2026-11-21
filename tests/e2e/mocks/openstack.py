"""Mock of Keystone v3 (POST /v3/auth/tokens: application credential and
password, project scope, catalog) and Barbican (GET /v1/secrets/<id> and its
payload), following the OpenStack API documentation. Test tool only.
usage: openstack.py <port> <private key file to serve> <dir with app-secret, password>"""
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
PORT, KEY, DIR = int(sys.argv[1]), sys.argv[2], sys.argv[3]
SECRET_ID = "5f6a2c1e-0000-4000-8000-ssh-casign-ca"
TOKEN = "gAAAAA-mock-keystone-token"
APP_SECRET = open(f"{DIR}/app-secret").read().strip()
PASSWORD = open(f"{DIR}/password").read().strip()
CATALOG = [
    {"type": "identity", "endpoints": [{"interface": "public", "region_id": "RegionOne", "url": f"http://localhost:{PORT}/v3"}]},
    {"type": "key-manager", "endpoints": [
        {"interface": "public", "region_id": "RegionOne", "region": "RegionOne", "url": f"http://localhost:{PORT}"},
        {"interface": "public", "region_id": "RegionTwo", "region": "RegionTwo", "url": "http://unreachable.invalid:9311"},
    ]},
]
class H(BaseHTTPRequestHandler):
    def reply(self, status, body, headers=(), raw=None, ctype="application/json"):
        data = raw if raw is not None else json.dumps(body).encode()
        self.send_response(status); self.send_header("content-type", ctype)
        for k, v in headers: self.send_header(k, v)
        self.send_header("content-length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        if self.path != "/v3/auth/tokens": return self.reply(404, {"error": "not found"})
        auth = json.loads(self.rfile.read(int(self.headers["content-length"])))["auth"]
        identity = auth["identity"]
        if identity["methods"] == ["application_credential"]:
            c = identity["application_credential"]
            ok = c.get("id") == "ac1" and c.get("secret") == APP_SECRET
            how = "application credential"
        elif identity["methods"] == ["password"]:
            u = identity["password"]["user"]
            scope = auth.get("scope", {}).get("project", {})
            ok = (u.get("name") == "ssh-casign" and u.get("domain", {}).get("name") == "Default"
                  and u.get("password") == PASSWORD and scope.get("name") == "ssh"
                  and scope.get("domain", {}).get("name") == "Default")
            how = "password"
        else:
            ok, how = False, "?"
        if not ok: return self.reply(401, {"error": {"code": 401, "message": "The request you have made requires authentication."}})
        print(f"keystone: token for {how}", file=sys.stderr, flush=True)
        self.reply(201, {"token": {"methods": identity["methods"], "catalog": CATALOG, "expires_at": "2099-01-01T00:00:00Z"}},
                   headers=[("X-Subject-Token", TOKEN)])
    def do_GET(self):
        if self.headers.get("x-auth-token") != TOKEN: return self.reply(401, {"error": "unauthorized"})
        base = f"/v1/secrets/{SECRET_ID}"
        if self.path == base:
            return self.reply(200, {"secret_ref": f"http://localhost:{PORT}{base}", "status": "ACTIVE", "secret_type": "private",
                                    "content_types": {"default": "application/octet-stream"}})
        if self.path == base + "/payload":
            if self.headers.get("accept") != "application/octet-stream":
                return self.reply(406, {"error": "Accept must match the payload content type"})
            print("barbican: payload served", file=sys.stderr, flush=True)
            return self.reply(200, None, raw=open(KEY, "rb").read(), ctype="application/octet-stream")
        self.reply(404, {"error": "not found"})
    def log_message(self, *a): pass
ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
