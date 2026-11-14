ssh-casign on AWS Lambda
========================

The service runs as an ordinary HTTP server. The
[Lambda Web Adapter](https://github.com/awslabs/aws-lambda-web-adapter), installed as an
extension, turns the function's invocations (from a Function URL, API Gateway or an ALB)
into HTTP requests to it, so the same binary runs on Lambda, Azure Functions and plain
servers.

CA keys live in AWS KMS; the function's execution role signs with them, so the
configuration contains no secrets.

Build
-----

```sh
CONFIG=path/to/config.toml deploy/aws-lambda/build.sh
# -> container image ssh-casign-lambda:latest (linux/arm64)
```

- `ARCH=arm64` (default, Graviton) or `ARCH=x86_64`; `IMAGE=name:tag`.
- The binary is static (musl, rustls), built by `deploy/build-static.sh` (natively on
  a machine of the same architecture, else cross-compiled with `cargo-zigbuild`).
  Features: `ca-aws-kms,tls-rustls`; extra features can be passed as the first
  argument.
- The image is `public.ecr.aws/lambda/provided:al2023` with the binary as
  `/var/runtime/bootstrap` and the adapter in `/opt/extensions/`. The service listens
  on port 8000 (`PORT`, `AWS_LWA_PORT`); the adapter checks readiness on
  `/.well-known/ssh-casign`.
- Put the configuration in the image (`CONFIG`): Lambda limits all environment
  variables together to 4 KB, which a configuration can exceed.
  `SSH_CASIGN_CONFIG_TOML` works for small ones.

AWS resources
-------------

```sh
REGION=eu-west-1; ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REPO=$ACCOUNT.dkr.ecr.$REGION.amazonaws.com/ssh-casign

# CA keys
aws kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY --region $REGION
aws kms create-alias --alias-name alias/ssh-ca-ec --target-key-id <key-id> --region $REGION
# also possible: ECC_NIST_EDWARDS25519, ECC_NIST_P384/P521, RSA_2048/3072/4096

# Image
aws ecr create-repository --repository-name ssh-casign --region $REGION
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin ${REPO%/*}
docker tag ssh-casign-lambda:latest $REPO:1 && docker push $REPO:1

# Execution role: CloudWatch Logs plus GetPublicKey and Sign on the CA keys
aws iam create-role --role-name ssh-casign --assume-role-policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam attach-role-policy --role-name ssh-casign \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
aws iam put-role-policy --role-name ssh-casign --policy-name kms-sign --policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["kms:GetPublicKey","kms:Sign"],"Resource":"arn:aws:kms:'$REGION:$ACCOUNT':key/<key-id>"}]}'

# Function with a public URL (the service does its own OIDC authentication)
aws lambda create-function --function-name ssh-casign --region $REGION \
  --package-type Image --code ImageUri=$REPO:1 --architectures arm64 \
  --role arn:aws:iam::$ACCOUNT:role/ssh-casign --timeout 30 --memory-size 256
aws lambda create-function-url-config --function-name ssh-casign --auth-type NONE --region $REGION
aws lambda add-permission --function-name ssh-casign --region $REGION \
  --statement-id public-url --action lambda:InvokeFunctionUrl --principal '*' \
  --function-url-auth-type NONE
```

Check the current Lambda documentation on public Function URLs: AWS has been
tightening which permissions they need (`lambda:InvokeFunction` as well as
`lambda:InvokeFunctionUrl`). API Gateway (HTTP API, payload format 2.0) in front of the
function works with the adapter too.

Configuration
-------------

```toml
server_id = "aws-euw1"     # set it: execution environments are anonymous

[oidc_provider]
issuer = "https://idp.example.com"
client_id = "ssh-casign"
scopes = ["openid", "profile", "offline_access"]

[profiles.default]
ssh_ca = ["kms-ed25519", "kms-ec"]
validity = 3600
principals = ["{{claim:preferred_username}}"]
allowed_principals = ["{{claim:preferred_username}}"]

[authorities.kms-ed25519]
provider = "aws_kms"
key_id = "alias/ssh-ca-ed25519"
cert_types = ["user"]

[authorities.kms-ec]
provider = "aws_kms"
key_id = "alias/ssh-ca-ec"
cert_types = ["user"]

[audit]
client_address_header = "x-forwarded-for"   # set by Function URLs and API Gateway

[[audit.sink]]
type = "stdout"
```

- **Credentials**: the execution role's, which Lambda passes in `AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`; the region comes from `AWS_REGION`.
- **Aliases** are resolved when the function starts (cold start), so the service signs
  with the key it advertises even if the alias is moved. KMS asymmetric keys have no
  versions; rotate by creating a new key, trusting it on servers, then listing it first.
- **`ssh-rsa`** (SHA-1) can't be signed by KMS. Profiles that need it require an
  authority on another backend.
- **Cold start** loads the IdP's keys and every authority's public key; Lambda allows
  10 seconds for that.

Audit log
---------

The `stdout` sink's CEF lines go to the function's CloudWatch Logs log group
(`/aws/lambda/<function>`); the service's own log goes there too, from stderr. Set a
retention period on the group, and use a subscription filter on `"CEF:0|"` to forward
audit records to a SIEM (via Kinesis Data Firehose or a forwarding function).

Local test
----------

The base image contains the Lambda runtime interface emulator: run the image and invoke
it with Function URL events (payload format 2.0) on port 8080:

```sh
docker run --rm -p 9000:8080 -e AWS_REGION=eu-west-1 -e AWS_ACCESS_KEY_ID=… \
  -e AWS_SECRET_ACCESS_KEY=… ssh-casign-lambda:latest
curl -s localhost:9000/2015-03-31/functions/function/invocations -d '{
  "version": "2.0", "rawPath": "/.well-known/ssh-casign", "rawQueryString": "", "headers": {},
  "requestContext": {"http": {"method": "GET", "path": "/.well-known/ssh-casign",
                              "sourceIp": "203.0.113.5", "protocol": "HTTP/1.1", "userAgent": "curl"}},
  "isBase64Encoded": false }'
```

This was tested end to end with Dex, LocalStack (KMS) and a small proxy that turns HTTP
requests into Function URL events: discovery, certificates signed through KMS, denials,
and the audit records in the function's log.
