"""Stand-in for the Kubernetes API's TokenReview, for OpenBao's kubernetes
auth method: accepts the test service account token. Test tool only.
usage: tokenreview.py <port> <token file>"""
import http.server, json, sys

TOKEN = open(sys.argv[2]).read().strip()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        ok = body.get("spec", {}).get("token", "") == TOKEN
        status = {"authenticated": False}
        if ok:
            status = {"authenticated": True, "user": {
                "username": "system:serviceaccount:prod:ssh-casign", "uid": "uid-123",
                "groups": ["system:serviceaccounts"]}}
        data = json.dumps({"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                           "status": status}).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # readiness
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


http.server.HTTPServer(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()
