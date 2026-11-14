ssh-casign on Azure Functions
=============================

The service runs as a Functions *custom handler*: the Functions host starts the
`ssh-casign-service` binary and forwards every HTTP request to it unchanged
(`enableForwardingHttpRequest`), on the port in `FUNCTIONS_CUSTOMHANDLER_PORT`. One
catch-all function (`ssh-casign/function.json`) with an empty route prefix keeps the
paths as they are: `/.well-known/ssh-casign` and `/sign`.

CA keys live in Azure Key Vault (or Managed HSM); the function app's managed identity
signs with them, so the configuration contains no secrets.

Build
-----

```sh
CONFIG=path/to/config.toml deploy/azure-functions/build.sh
# -> deploy/azure-functions/dist/ssh-casign-azure-functions.zip
```

The binary is static (x86-64 Linux, musl, rustls), so it doesn't depend on the OpenSSL
version of the Functions image. It is cross-compiled in a `rust` container with
`cargo-zigbuild` (no emulation; works on x86-64 and ARM hosts). Features:
`ca-azure-keyvault,tls-rustls`; extra features can be passed as the first argument, e.g.
`build.sh ca-file`.

Without `CONFIG`, set the configuration as the app setting `SSH_CASIGN_CONFIG_TOML`
instead.

Azure resources
---------------

```sh
RG=ssh-casign; LOC=westeurope; APP=ssh-casign-ca; ST=sshcasignfuncs; KV=ssh-casign-kv

az group create -n $RG -l $LOC
az storage account create -n $ST -g $RG -l $LOC --sku Standard_LRS
az functionapp create -n $APP -g $RG --storage-account $ST \
  --consumption-plan-location $LOC --os-type Linux \
  --runtime custom --functions-version 4 --assign-identity '[system]'

az keyvault create -n $KV -g $RG -l $LOC --enable-rbac-authorization true
az keyvault key create --vault-name $KV -n ssh-ca-ec  --kty EC  --curve P-256 --ops sign verify
az keyvault key create --vault-name $KV -n ssh-ca-rsa --kty RSA --size 3072   --ops sign verify

# Let the function app's identity read the keys and sign with them.
az role assignment create --role "Key Vault Crypto User" \
  --assignee "$(az functionapp identity show -n $APP -g $RG --query principalId -o tsv)" \
  --scope "$(az keyvault show -n $KV --query id -o tsv)"

az functionapp deployment source config-zip -n $APP -g $RG \
  --src deploy/azure-functions/dist/ssh-casign-azure-functions.zip
```

Custom handlers run on the Linux Consumption, Premium and Dedicated plans; check the
current documentation before using another plan. HSM-protected keys (`EC-HSM`,
`RSA-HSM`) need a Premium vault or Managed HSM.

Configuration
-------------

```toml
server_id = "azure-weu"    # set it: instance host names are random

[oidc_provider]
# Microsoft Entra ID, for example: an app registration with "Allow public client
# flows" (device flow) and a mobile/desktop redirect URI http://localhost (browser).
issuer = "https://login.microsoftonline.com/<tenant-id>/v2.0"
client_id = "<application-id>"
scopes = ["openid", "profile", "offline_access"]
id_claim = "oid"           # stable object ID; or "preferred_username"

[profiles.default]
ssh_ca = ["kv-ec", "kv-rsa"]
validity = 3600
principals = ["{{claim:preferred_username}}"]
allowed_principals = ["{{claim:preferred_username}}"]

[authorities.kv-ec]
provider = "azure_keyvault"
vault_url = "https://ssh-casign-kv.vault.azure.net"
key = "ssh-ca-ec"
cert_types = ["user"]

[authorities.kv-rsa]
provider = "azure_keyvault"
vault_url = "https://ssh-casign-kv.vault.azure.net"
key = "ssh-ca-rsa"
cert_types = ["user"]

[audit]
client_address_header = "x-forwarded-for"   # Azure's front end sets it ("IP:port")

[[audit.sink]]
type = "stdout"
```

- **Credentials**: with `credential = "auto"` (the default), the Key Vault backend uses
  the app's managed identity through `IDENTITY_ENDPOINT`/`IDENTITY_HEADER`. A
  user-assigned identity needs `client_id = "<its client ID>"` on the authority.
- **Key versions** are fixed at startup; after rotating a key, restart the app (and
  trust the new public key on servers first).
- **`ssh-rsa`** (SHA-1) can't be signed by Key Vault. Profiles that need it require an
  authority on another backend.

Audit log
---------

The Functions host captures the custom handler's output: stdout lines (the `stdout`
sink's CEF records) are logged as category `Host.Function.Console` at level
Information, and end up in Application Insights (`traces`) and Log Analytics.
`host.json` keeps that category at Information and turns sampling off, so no audit
record is filtered or sampled away. Filter on messages starting with `CEF:0|` to route
them, e.g. to Microsoft Sentinel. Application Insights is not a strict
audit store, though: daily caps and throttling can drop data. Where every record must
be kept, add a `syslog` sink over TCP to a SIEM collector (for example a Microsoft
Sentinel CEF collector).

Local test
----------

The Functions host image runs the package locally. It needs a reachable IdP and Key
Vault (an emulator such as Lowkey Vault works; give the service its CA certificate with
`ca_cert_file` and point `IDENTITY_ENDPOINT` at the emulator's token endpoint). This was
tested with Dex, Lowkey Vault and the host in one podman pod: discovery, certificates
signed by Key Vault through the managed identity flow, and audit records in the host's
log. Without Azure's front end there is no `X-Forwarded-For`, so the records show the
host's address.

```sh
podman run --rm -p 7071:80 \
  -v "$PWD/deploy/azure-functions/dist/package:/home/site/wwwroot:ro" \
  -e AzureWebJobsScriptRoot=/home/site/wwwroot \
  -e FUNCTIONS_WORKER_RUNTIME=custom \
  -e AzureWebJobsSecretStorageType=files \
  -e AzureFunctionsJobHost__Logging__Console__IsEnabled=true \
  mcr.microsoft.com/azure-functions/base:4
curl http://localhost:7071/.well-known/ssh-casign
```
