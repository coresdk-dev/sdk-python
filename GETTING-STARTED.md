# Getting Started with CoreSDK — Zero to Working in 15 Minutes

This guide takes you from nothing to a running sidecar with real JWT validation, a policy check, and a verified SDK call. Every step explains **what** you are doing and **why** it is needed.

---

## What CoreSDK is and why it is structured this way

CoreSDK separates security concerns from your application code. Instead of every service re-implementing JWT validation, rate limiting, and audit logging, a **sidecar process** handles all of that. Your application talks to the sidecar over local gRPC — a fast, loopback connection that never leaves the machine.

```
Your App  ──gRPC :50051──►  Sidecar  ──►  Auth / Policy / Audit / Flags
                                │
                         Control Plane :8080
                         (optional — syncs policy + flags every 30s)
```

**Why a sidecar?** Your app stays stateless and language-agnostic. The sidecar owns the secrets, caches the JWK set, evaluates Rego policies, and emits audit events. You get all of this without pulling a heavy library into every service.

**Why gRPC on loopback?** gRPC gives you strongly-typed calls, streaming, and built-in health checks. Loopback keeps traffic off the network — only mTLS is needed when you add it.

---

## Prerequisites

| Requirement | Why you need it |
|-------------|----------------|
| **Docker 20.10+** — OR — **Rust 1.75+** (via [rustup.rs](https://rustup.rs)) | To run the sidecar. Docker is the fastest path; Rust is needed only if you build from source. |
| Language runtime for your SDK (see table below) | To install and run the SDK in your application. |

| SDK | Minimum runtime |
|-----|----------------|
| Python | Python 3.9+ |
| Go | Go 1.21+ |
| TypeScript / Node.js | Node.js 18+ |
| Java (Spring Boot) | Java 17+ |

You do **not** need Rust installed to use the SDKs. Rust is only required to build the sidecar from source.

---

## Step 1 — Run the sidecar

**Why this step is first:** Nothing else works without the sidecar. The SDKs connect to it immediately on startup and will fail with a connection error if it is not running.

### Option A — Docker (recommended for getting started)

```bash
docker run --rm \
  -e CORESDK_SIDECAR_ADDR=[::]:50051 \
  -e CORESDK_ENV=development \
  -p 50051:50051 \
  -p 9091:9091 \
  ghcr.io/coresdk-dev/sidecar:latest
```

> **Why `CORESDK_SIDECAR_ADDR=[::]:50051`?** By default the sidecar binds to the loopback address `[::1]:50051` which is unreachable from outside the container. Setting it to `[::]` binds to all interfaces so Docker's port mapping (`-p 50051:50051`) can forward traffic in.

> **Why `CORESDK_ENV=development`?** In development mode JWT signatures are not verified and all decisions fail-open. This lets you get everything wired up before adding your identity provider.

### Option B — Pre-built binary (no Docker)

```bash
# macOS (Apple Silicon)
curl -LO https://github.com/coresdk-dev/core/releases/latest/download/coresdk-sidecar-aarch64-apple-darwin.tar.gz
tar xf coresdk-sidecar-aarch64-apple-darwin.tar.gz

# macOS (Intel)
curl -LO https://github.com/coresdk-dev/core/releases/latest/download/coresdk-sidecar-x86_64-apple-darwin.tar.gz
tar xf coresdk-sidecar-x86_64-apple-darwin.tar.gz

# Linux (amd64)
curl -LO https://github.com/coresdk-dev/core/releases/latest/download/coresdk-sidecar-x86_64-unknown-linux-gnu.tar.gz
tar xf coresdk-sidecar-x86_64-unknown-linux-gnu.tar.gz

# Linux (arm64)
curl -LO https://github.com/coresdk-dev/core/releases/latest/download/coresdk-sidecar-aarch64-unknown-linux-gnu.tar.gz
tar xf coresdk-sidecar-aarch64-unknown-linux-gnu.tar.gz

CORESDK_ENV=development ./coresdk-sidecar
```

### Option C — Build from source

```bash
git clone git@github.com:coresdk-dev/core-sdk.git && cd core-sdk
cargo build --release -p coresdk-sidecar
CORESDK_ENV=development ./target/release/coresdk-sidecar
```

### What you will see on startup

```
CoreSDK Sidecar v0.1.0
  gRPC               [::1]:50051
  Health             http://[::1]:9091/healthz
  Transport          plaintext
  Fail mode          open
  Env                development
  Tenant             default
  JWKS URI           not set          ← expected at this stage
  Control plane      not configured   ← expected at this stage
  Service name       unknown-service
WARN CORESDK_JWKS_URI not set — JWT validation DISABLED. All tokens accepted (fail-open).
CoreSDK Sidecar ready.
  Verify: curl http://localhost:9091/healthz
  Next:   export CORESDK_JWKS_URI=https://<your-idp>/.well-known/jwks.json
```

The `WARN` about `CORESDK_JWKS_URI` is expected right now — you will add it in Step 3. The sidecar is fully operational; it just accepts all tokens without signature verification.

### Verify the sidecar is up

```bash
curl http://localhost:9091/healthz
# Expected: {"status":"ok"}

curl http://localhost:9091/readyz
# Expected: {"status":"ready"}
```

> **Why two health endpoints?** `/healthz` answers as soon as the process is alive (liveness). `/readyz` answers only after gRPC is bound and all subsystems are initialized (readiness). Use `/readyz` as your Kubernetes `readinessProbe` so traffic is not sent before the sidecar is ready.

---

## Step 2 — Install your SDK and make a first call

**Why before JWT is configured:** You want to confirm the gRPC connection works before adding credential complexity. In development mode all tokens are accepted, so you can run a real authorize call with a dummy token.

### Python

```bash
pip install coresdk
```

```python
from coresdk import SDK

# from_env() reads CORESDK_SIDECAR_ADDR (default: localhost:50051),
# CORESDK_TENANT_ID, CORESDK_FAIL_MODE from environment variables.
# This is the only setup needed — no API keys, no config files.
sdk = SDK.from_env()

# In dev mode this will succeed even with a fake token because
# CORESDK_JWKS_URI is not set and fail_mode=open.
decision = sdk.authorize("Bearer test-token", action="read", resource="/api/orders")
print("allowed:", decision.allowed)
# Expected: allowed: True
```

> **Why `from_env()`?** Configuration through environment variables is the twelve-factor app standard. It works identically in development (`.env` files), CI (injected secrets), and Kubernetes (ConfigMaps + Secrets). You never hardcode addresses or credentials.

### Go

```bash
go get github.com/coresdk-dev/sdk-go
```

```go
package main

import (
    "context"
    "log"
    coresdk "github.com/coresdk-dev/sdk-go"
)

func main() {
    // FromEnv() reads CORESDK_SIDECAR_ADDR, CORESDK_TENANT_ID, CORESDK_FAIL_MODE.
    sdk, err := coresdk.FromEnv()
    if err != nil {
        log.Fatal(err)
    }
    defer sdk.Close()

    // In dev mode this succeeds with a dummy token.
    claims, err := sdk.Authorize(context.Background(), "Bearer test-token")
    if err != nil {
        log.Fatal("denied:", err)
    }
    log.Println("allowed, subject:", claims.Sub)
}
```

### TypeScript / Node.js

```bash
npm install @coresdk/sdk
```

```typescript
import { SDK } from '@coresdk/sdk'

// fromEnv() reads CORESDK_SIDECAR_ADDR (default: localhost:50051).
const sdk = SDK.fromEnv()

const decision = await sdk.authorize('Bearer test-token', '/api/orders', 'read')
console.log('allowed:', decision.allowed)
// Expected: allowed: true
```

### Java (Spring Boot)

`pom.xml`:

```xml
<dependency>
  <groupId>io.coresdk</groupId>
  <artifactId>coresdk-spring-boot-starter</artifactId>
  <version>0.1.0</version>
</dependency>
```

`application.yml`:

```yaml
coresdk:
  endpoint: localhost:50051   # which sidecar to connect to
  tenant-id: my-app
  fail-mode: open             # allow requests even if sidecar is unreachable
```

```java
@Autowired CoreSDK sdk;

AuthDecision decision = sdk.authorize("Bearer test-token", "/api/orders", "GET").join();
System.out.println("allowed: " + decision.isAllowed());
```

If you see `allowed: true` (or `allowed: True`) — the gRPC connection is working. Move to Step 3.

If you see a connection error — check that the sidecar is running (`curl http://localhost:9091/healthz`) and that `CORESDK_SIDECAR_ADDR` matches the address the sidecar is listening on.

---

## Step 3 — Wire in real JWT validation

**Why this step matters:** Without a JWKS URI the sidecar accepts every token, including forged ones. This is only safe for local development. Before you deploy anywhere, point the sidecar at your identity provider.

**Why JWKS and not a shared secret?** JWKS (JSON Web Key Set) lets the sidecar verify JWT signatures using the IdP's public keys. The private keys never leave the IdP. Key rotation is automatic — the sidecar fetches the updated key set and caches it.

```bash
# Auth0
export CORESDK_JWKS_URI=https://your-tenant.us.auth0.com/.well-known/jwks.json

# Okta
export CORESDK_JWKS_URI=https://your-org.okta.com/oauth2/default/v1/keys

# Keycloak
export CORESDK_JWKS_URI=https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs

# Google
export CORESDK_JWKS_URI=https://www.googleapis.com/oauth2/v3/certs
```

Restart the sidecar with this variable set. You will see in the startup banner:

```
  JWKS URI           https://your-idp.example.com/.well-known/jwks.json
```

And the WARN line disappears. The sidecar fetches and warms the JWK cache on startup (5 second timeout), then refreshes it in the background every hour.

**Require the audience claim (recommended for production):**

```bash
export CORESDK_JWT_REQUIRE_AUDIENCE=true
```

> **Why audience validation?** A JWT issued for your mobile app (`aud: mobile-app`) should not be accepted by your API (`aud: api`). Audience validation prevents tokens from being used across services they were not issued for.

Now try `authorize()` again with a real JWT from your IdP. A forged token should be rejected with status 401.

---

## Step 4 — Add a policy (optional but recommended)

**Why policies?** `authorize()` validates the token — it answers "is this token valid and who is this user?". Policies answer "is this user allowed to do this action?" These are separate concerns. A valid token does not automatically mean access is granted.

**Why Rego?** Rego (OPA policy language) is declarative — you describe what is allowed, not how to check it. Policies are hot-reloaded without restarting the sidecar.

### Start the control plane

The control plane stores and distributes policies to sidecars. Run it alongside the sidecar:

```bash
# Docker
docker run --rm -p 8080:8080 ghcr.io/coresdk-dev/control-plane:latest

# Or binary
./control-plane
```

Wire the sidecar to it:

```bash
export CORESDK_CONTROL_PLANE_URL=http://localhost:8080
export CORESDK_CONTROL_PLANE_TOKEN=dev-token
```

> **Why a token?** The control plane exposes an HTTP API that can push policy bundles to every connected sidecar. The token prevents unauthorized pushes. In development `dev-token` is fine; in production use a strong random secret.

### Write a policy

```rego
# policy/authz.rego
package authz

# Deny by default — explicit allow is safer than explicit deny.
# If no rule matches, allow = false and the request is rejected.
default allow = false

# Viewers can read anything.
allow if {
    input.action == "read"
    "viewer" in input.roles
}

# Admins can do anything.
allow if {
    "admin" in input.roles
}
```

> **Why `default allow = false`?** Fail-closed policy means a new resource is denied until someone explicitly adds a rule for it. Fail-open (`default allow = true`) means a new resource is accidentally public until someone adds a deny rule. Fail-closed is always the safer default.

### Upload the policy

```bash
BUNDLE_B64=$(base64 -i policy/authz.rego)

curl -s -X PUT http://localhost:8080/api/v1/policies \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d "{\"bundle_b64\": \"$BUNDLE_B64\"}"
```

The sidecar polls the control plane every 30 seconds and hot-reloads the policy when the content hash changes. No restart required.

### Evaluate the policy from your SDK

**Python:**
```python
allowed = sdk.evaluate_policy("authz.allow", {
    "action": "read",
    "roles": ["viewer"],
})
print("policy result:", allowed)
# Expected: True
```

**Go:**
```go
allowed, err := sdk.EvaluatePolicy(ctx, "authz.allow", map[string]any{
    "action": "read",
    "roles":  []string{"viewer"},
})
```

**TypeScript:**
```typescript
const allowed = await sdk.evaluatePolicy('authz.allow', {
  action: 'read',
  roles: ['viewer'],
})
```

---

## Step 5 — Run the pre-flight check

**Why this step?** Before shipping to staging or production, run the doctor command. It catches misconfiguration that is easy to miss — wrong var names, missing TLS files, open fail_mode — and tells you exactly how to fix each one.

```bash
# Pre-flight check (env vars + file existence — no running sidecar needed)
./coresdk-sidecar doctor

# Connectivity check (probes a running sidecar over TCP + TLS)
coresdk doctor

# Strict mode — exits non-zero if any warning is present
# Use this in CI before every deployment
coresdk doctor --strict
```

Example output with a clean configuration:

```
CoreSDK Doctor
──────────────────────────────────────────────────────
  ✓  Sidecar reachable         TCP localhost:50051    connected
  ✓  TLS handshake             https://localhost:9091
  ✓  mTLS client cert          CORESDK_TLS_CERT_FILE  loaded · expires in 287 day(s)
  ✓  Local cache (HMAC)        ~/.coresdk/cache/      present
  –  Control plane             CORESDK_CONTROL_PLANE_ADDR not set
──────────────────────────────────────────────────────
All checks passed.
  Your SDK can now connect — install one:
    pip install coresdk
    go get github.com/coresdk-dev/sdk-go
    npm install @coresdk/sdk
```

---

## Step 6 — Production checklist

Once the basics work, harden the deployment before going live.

### Required for production

| Setting | Why it is required |
|---------|-------------------|
| `CORESDK_JWKS_URI=<your-idp-url>` | Without this, all tokens are accepted including forged ones. |
| `CORESDK_FAIL_MODE=closed` | In `open` mode, a sidecar crash or network error silently allows all requests. `closed` rejects requests when the sidecar cannot be reached. |
| `CORESDK_SERVICE_TOKEN=<random-secret>` | Without a service token, any process that can reach port 50051 can make gRPC calls. The token is a shared secret that gates access to the sidecar. |
| `CORESDK_SERVICE_NAME=<your-service>` | Without a service name, all OTel traces are grouped under `unknown-service`, making them unsearchable in your tracing backend. |
| `CORESDK_AUTO_PKI=true` (or manual TLS certs) | Plaintext gRPC means tokens and policy decisions are sent unencrypted on the local socket. mTLS encrypts the channel and mutually authenticates the SDK and sidecar. |

### Recommended for production

```bash
export CORESDK_ENV=production
export CORESDK_TENANT_ID=acme-prod
export CORESDK_FAIL_MODE=closed
export CORESDK_SERVICE_NAME=orders-api
export CORESDK_JWKS_URI=https://your-idp.example.com/.well-known/jwks.json
export CORESDK_JWT_REQUIRE_AUDIENCE=true
export CORESDK_SERVICE_TOKEN=$(openssl rand -hex 32)
export CORESDK_AUTO_PKI=true
export CORESDK_DATA_DIR=/var/lib/coresdk
export CORESDK_CONTROL_PLANE_URL=http://control-plane.internal:8080
export CORESDK_CONTROL_PLANE_TOKEN=<cp-bearer-token>
export CORESDK_LOG_LEVEL=info
```

Run `coresdk doctor --strict` after setting these. It exits non-zero if anything is missing or misconfigured.

---

## Common first-run errors and fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `Connection refused` on `localhost:50051` | Sidecar not started or wrong port | Run `curl http://localhost:9091/healthz` to confirm it is up |
| `Connection refused` when using Docker | Sidecar binds to `[::1]` by default (loopback only) | Add `-e CORESDK_SIDECAR_ADDR=[::]:50051` to the `docker run` command |
| `WARN: JWT validation DISABLED` | `CORESDK_JWKS_URI` not set | Set `CORESDK_JWKS_URI` to your IdP's JWKS endpoint (Step 3) |
| Token rejected with 401 after adding JWKS | Token audience does not match | Check `CORESDK_JWT_REQUIRE_AUDIENCE` and the `aud` claim in your token |
| `allowed: False` for a valid user | Policy not loaded or rule does not match | Check control plane is running and policy was uploaded; test with `evaluate_policy` directly |
| `TLS cert not found` in doctor output | Wrong env var name | Sidecar uses `CORESDK_TLS_CERT_FILE`; Python/TS/Java SDKs use `CORESDK_TLS_CERT_FILE`; Go SDK uses `CORESDK_TLS_CERT` |
| `mTLS not configured` warning in strict mode | Auto-PKI not enabled and no certs supplied | Set `CORESDK_AUTO_PKI=true` or supply `CORESDK_TLS_CERT_FILE`, `CORESDK_TLS_KEY_FILE`, `CORESDK_TLS_CA_FILE` |

---

## Where to go next

| Goal | Guide |
|------|-------|
| Configure mTLS between SDK and sidecar | [mTLS Setup Guide](docs/guides/mtls-setup.md) |
| Store secrets in Vault / AWS / Azure | [Vault Adapter Selection](docs/guides/vault-adapter-selection.md) |
| Use a hardware security module for JWT signing | [HSM / PKCS#11 Setup](docs/guides/hsm-pkcs11.md) |
| Configure Redis for multi-replica cache sharing | [Cache Strategy Guide](docs/guides/cache-strategy.md) |
| Validate webhook deliveries | [Webhook Signature Validation](docs/guides/webhook-signature-validation.md) |
| Deploy to Kubernetes | [Kubernetes Operations Guide](docs/guides/kubernetes-operations.md) |
| Integrate OpenTelemetry tracing | [OTel Integration Guide](docs/guides/otel-integration.md) |
| Full environment variable reference | [Configuration Seeding Guide](docs/guides/configuration-seeding.md) |
