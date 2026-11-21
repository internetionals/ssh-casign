"""Mock of the Cloud KMS REST API (publicKey, asymmetricSign), the metadata
server's token endpoint and the OAuth token endpoint for service account JWTs,
following Google's documentation. Test tool only.
Also workload identity federation: STS token exchange (/sts) and
service account impersonation (generateAccessToken), and a subject token
URL (/subject). Every federation call is logged to stderr.
usage: gcp.py <port> <service-account-key-file to write> <subject token>"""
import base64, json, sys, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

PORT, SA_FILE, SUBJECT = int(sys.argv[1]), sys.argv[2], sys.argv[3]
AUDIENCE = "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/k8s/providers/cluster"
PREFIX = "projects/p/locations/europe-west1/keyRings/ssh/cryptoKeys"
KEYS = {
    "ed": ("EC_SIGN_ED25519", ed25519.Ed25519PrivateKey.generate()),
    "ec": ("EC_SIGN_P256_SHA256", ec.generate_private_key(ec.SECP256R1())),
    "ec384": ("EC_SIGN_P384_SHA384", ec.generate_private_key(ec.SECP384R1())),
    "rsa": ("RSA_SIGN_PKCS1_3072_SHA256", rsa.generate_private_key(65537, 3072)),
    "rsa-raw": ("RSA_SIGN_RAW_PKCS1_3072", rsa.generate_private_key(65537, 3072)),
}
VERSIONS = {f"{PREFIX}/{k}/cryptoKeyVersions/1": v for k, v in KEYS.items()}
TOKENS = {"mock-metadata-token", "mock-sa-token"}

sa_key = rsa.generate_private_key(65537, 2048)
SA_EMAIL = "ssh-ca@p.iam.gserviceaccount.com"
json.dump({
    "type": "service_account", "project_id": "p", "private_key_id": "kid1", "client_email": SA_EMAIL,
    "private_key": sa_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()).decode(),
    "token_uri": f"http://localhost:{PORT}/token",
}, open(SA_FILE, "w"))

def b64url(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def raw_pkcs1_sign(key, data):
    """RSASSA-PKCS1-v1_5 without DigestInfo encoding: pad the data as is."""
    n, d = key.private_numbers().public_numbers.n, key.private_numbers().d
    k = (n.bit_length() + 7) // 8
    if len(data) > k - 11: raise ValueError("data too long")
    em = b"\x00\x01" + b"\xff" * (k - 3 - len(data)) + b"\x00" + data
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")

class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status); self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def error(self, status, kind, message):
        self.reply(status, {"error": {"code": status, "status": kind, "message": message}})
    def authorized(self):
        auth = self.headers.get("authorization", "")
        if not (auth.startswith("Bearer ") and auth[7:] in TOKENS):
            self.error(401, "UNAUTHENTICATED", "invalid credentials"); return False
        return True
    def do_GET(self):
        if self.path == "/subject":
            if self.headers.get("x-test-header") != "yes":
                return self.error(403, "FORBIDDEN", "missing header")
            print("subject token served by URL", file=sys.stderr, flush=True)
            return self.reply(200, {"id_token": SUBJECT})
        if self.path.startswith("/computeMetadata/v1/instance/service-accounts/default/token"):
            if self.headers.get("metadata-flavor") != "Google":
                return self.error(403, "FORBIDDEN", "missing Metadata-Flavor")
            return self.reply(200, {"access_token": "mock-metadata-token", "expires_in": 3599, "token_type": "Bearer"})
        if self.path.startswith("/v1/") and self.path.endswith("/publicKey"):
            if not self.authorized(): return
            name = self.path[len("/v1/"):-len("/publicKey")]
            if name not in VERSIONS: return self.error(404, "NOT_FOUND", f"{name} not found")
            algorithm, key = VERSIONS[name]
            pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                                serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            return self.reply(200, {"pem": pem, "algorithm": algorithm, "name": name, "protectionLevel": "SOFTWARE"})
        self.error(404, "NOT_FOUND", self.path)
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length") or 0))
        if self.path == "/sts":
            form = {k: v[0] for k, v in urllib.parse.parse_qs(body.decode()).items()}
            want = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "audience": AUDIENCE,
                    "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt", "subject_token": SUBJECT}
            bad = [k for k, v in want.items() if form.get(k) != v]
            if bad: return self.error(400, "invalid_request", f"wrong {bad}")
            print(f"STS exchange, scope {form.get('scope')}", file=sys.stderr, flush=True)
            TOKENS.add("mock-federated-token") if "cloudkms" in form.get("scope", "") else None
            return self.reply(200, {"access_token": "mock-federated-token", "expires_in": 3599,
                                    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "token_type": "Bearer"})
        if self.path.endswith(":generateAccessToken"):
            if self.headers.get("authorization") != "Bearer mock-federated-token":
                return self.error(401, "UNAUTHENTICATED", "not the federated token")
            req = json.loads(body)
            print(f"impersonation {self.path.rsplit('/', 1)[-1]}, scope {req.get('scope')}", file=sys.stderr, flush=True)
            return self.reply(200, {"accessToken": "mock-sa-token", "expireTime": "2099-01-01T00:00:00Z"})
        if self.path == "/token":
            form = dict(p.split("=", 1) for p in body.decode().split("&"))
            jwt = form.get("assertion", "")
            header, claims, signature = jwt.split(".")
            try:
                sa_key.public_key().verify(b64url(signature), f"{header}.{claims}".encode(),
                                           padding.PKCS1v15(), hashes.SHA256())
            except Exception:
                return self.error(400, "invalid_grant", "invalid JWT signature")
            c = json.loads(b64url(claims))
            if c["iss"] != SA_EMAIL or c["aud"] != f"http://localhost:{PORT}/token" or c["exp"] < time.time():
                return self.error(400, "invalid_grant", f"invalid claims {c}")
            return self.reply(200, {"access_token": "mock-sa-token", "expires_in": 3599, "token_type": "Bearer"})
        if self.path.startswith("/v1/") and self.path.endswith(":asymmetricSign"):
            if not self.authorized(): return
            name = self.path[len("/v1/"):-len(":asymmetricSign")]
            if name not in VERSIONS: return self.error(404, "NOT_FOUND", f"{name} not found")
            algorithm, key = VERSIONS[name]
            request = json.loads(body)
            data = base64.b64decode(request["data"]) if "data" in request else None
            digest = request.get("digest")
            needs_data = algorithm in ("EC_SIGN_ED25519",) or algorithm.startswith("RSA_SIGN_RAW")
            if needs_data != (data is not None) or (digest is not None) == needs_data:
                return self.error(400, "INVALID_ARGUMENT", f"{algorithm} needs {'data' if needs_data else 'digest'}")
            if algorithm == "EC_SIGN_ED25519":
                signature = key.sign(data)
            elif algorithm.startswith("RSA_SIGN_RAW"):
                signature = raw_pkcs1_sign(key, data)
            else:
                field, hash_ = {"EC_SIGN_P256_SHA256": ("sha256", hashes.SHA256()),
                                "EC_SIGN_P384_SHA384": ("sha384", hashes.SHA384()),
                                "RSA_SIGN_PKCS1_3072_SHA256": ("sha256", hashes.SHA256())}[algorithm]
                if list(digest) != [field]:
                    return self.error(400, "INVALID_ARGUMENT", f"{algorithm} needs digest.{field}")
                value = base64.b64decode(digest[field])
                if algorithm.startswith("EC"):
                    signature = key.sign(value, ec.ECDSA(utils.Prehashed(hash_)))
                else:
                    signature = key.sign(value, padding.PKCS1v15(), utils.Prehashed(hash_))
            return self.reply(200, {"signature": base64.b64encode(signature).decode(), "name": name})
        self.error(404, "NOT_FOUND", self.path)
    def log_message(self, *args): pass

ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
