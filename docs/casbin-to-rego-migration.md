# Casbin to Rego Migration Guide

This guide helps teams migrate from Casbin (RBAC/ABAC) to CoreSDK's Rego-based policy engine
(`SDK.evaluate_policy()` / `PolicyService/Evaluate`).

---

## Why Migrate

| Capability | Casbin | CoreSDK Rego |
|---|---|---|
| Hot-reload without restart | No | Yes (SyncClient pushes every 30s) |
| Multi-tenant policy isolation | Manual | Native (`tenant_id` scoped) |
| Dry-run / audit-safe testing | No | Yes (`SDK.dry_run_policy()`) |
| Structured deny reasons | No | Yes (policy decision includes reason) |
| Sidecar-backed — no library in app | No | Yes |

---

## Mapping Casbin Concepts to Rego

### Model: RBAC

**Casbin `.conf`:**
```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

**Rego equivalent (`policies/rbac.rego`):**
```rego
package myapp.authz

import future.keywords.if
import future.keywords.in

# Role assignments (replaces Casbin g lines)
role_grants := {
    "alice": ["admin"],
    "bob":   ["viewer"],
}

# Role permissions (replaces Casbin p lines)
role_permissions := {
    "admin":  [["*",            "*"]],
    "viewer": [["/api/orders",  "GET"], ["/api/invoices", "GET"]],
}

default allow := false

allow if {
    some role in role_grants[input.sub]
    some [obj, act] in role_permissions[role]
    (obj == "*" or input.resource == obj)
    (act == "*" or input.action == act)
}
```

**SDK call:**
```python
# Casbin: enforcer.enforce(user, resource, action)
# CoreSDK:
decision = sdk.evaluate_policy("data.myapp.authz.allow", {
    "sub":      get_current_user(),
    "resource": "/api/orders",
    "action":   "GET",
})
```

---

### Model: ABAC

**Casbin `.conf` (attribute-based):**
```ini
[matchers]
m = r.sub.department == p.sub && r.obj == p.obj && r.act == p.act
```

**Rego equivalent:**
```rego
package myapp.authz_abac

default allow := false

allow if {
    input.user.department == "engineering"
    input.resource == "/api/deploy"
    input.action == "POST"
}

allow if {
    input.user.role == "admin"
}
```

**SDK call:**
```python
decision = sdk.evaluate_policy("data.myapp.authz_abac.allow", {
    "user":     {"department": "engineering", "role": "member"},
    "resource": "/api/deploy",
    "action":   "POST",
})
```

---

### Model: Deny-Override

**Casbin:** `e = !some(where (p.eft == deny))`

**Rego:**
```rego
package myapp.authz_deny

default allow := false

allow if {
    # explicit allow rules
    input.role == "admin"
}

# Deny overrides allow — check explicitly in application:
# allowed = evaluate_policy("data.myapp.authz_deny.allow", input)
#           and not evaluate_policy("data.myapp.authz_deny.deny", input)
deny if {
    input.resource == "/api/admin/nuke"
    input.role != "superadmin"
}
```

```python
# Application-side deny-override pattern:
allowed = sdk.evaluate_policy("data.myapp.authz_deny.allow", inp)
denied  = sdk.evaluate_policy("data.myapp.authz_deny.deny",  inp)
if allowed and not denied:
    # proceed
```

---

## Thin Adapter: Drop-in Casbin Replacement

If you cannot rewrite call sites immediately, use this adapter that translates
`enforce(sub, obj, act)` into a `SDK.evaluate_policy()` call:

```python
# coresdk_casbin_adapter.py
from coresdk import SDK

class CasbinPolicyAdapter:
    """Drop-in replacement for a Casbin Enforcer.

    Usage::

        # Before (Casbin):
        enforcer = casbin.Enforcer("model.conf", "policy.csv")
        allowed = enforcer.enforce(user, resource, action)

        # After (CoreSDK adapter):
        enforcer = CasbinPolicyAdapter(sdk, rule="data.myapp.authz.allow")
        allowed = enforcer.enforce(user, resource, action)
    """

    def __init__(self, sdk: SDK, *, rule: str = "data.myapp.authz.allow") -> None:
        self._sdk = sdk
        self._rule = rule

    def enforce(self, sub: str, obj: str, act: str) -> bool:
        """Translate enforce(sub, obj, act) to evaluate_policy()."""
        return self._sdk.evaluate_policy(self._rule, {
            "sub":      sub,
            "resource": obj,
            "action":   act,
        })

    def enforce_ex(self, sub: str, obj: str, act: str) -> tuple[bool, list]:
        """Extended enforce — returns (allowed, [reason])."""
        allowed = self.enforce(sub, obj, act)
        reason = [] if allowed else ["policy denied"]
        return allowed, reason

    # Casbin role-management stubs — resolve roles via Rego or remove if not needed
    def get_roles_for_user(self, user: str) -> list[str]:
        raise NotImplementedError("Role queries must be encoded in your Rego policy.")

    def add_role_for_user(self, user: str, role: str) -> bool:
        raise NotImplementedError("Role mutations must go through the control plane API.")
```

---

## Policy Bundle Upload

Rego policies are uploaded to the control plane and pushed to the sidecar automatically:

```bash
# Upload via CLI
coresdk policy upload --file policies/rbac.rego --tenant my-tenant

# Or via control plane REST API
curl -X PUT http://localhost:8080/api/v1/policies \
  -H "Content-Type: application/json" \
  -d "{\"bundle\": \"$(base64 -w0 policies/rbac.rego)\"}"
```

The sidecar syncs every 30 seconds. Use `SDK.dry_run_policy()` to validate before upload:

```python
# Test policy without side effects
result = sdk.dry_run_policy("data.myapp.authz.allow", {
    "sub": "alice", "resource": "/api/orders", "action": "GET"
})
print("Would allow:", result)
```

---

## Migration Checklist

- [ ] Map each Casbin `.conf` model to an equivalent Rego package
- [ ] Convert Casbin `p` (policy) lines to Rego `role_permissions` / `allow` rules
- [ ] Convert Casbin `g` (role) lines to Rego `role_grants` maps
- [ ] Upload Rego bundle to control plane and verify with `dry_run_policy()`
- [ ] Replace `enforcer.enforce(sub, obj, act)` call sites with `CasbinPolicyAdapter` (zero diff)
- [ ] Run parallel validation: log both Casbin and Rego decisions for 1 week, compare
- [ ] Remove Casbin dependency once parity is confirmed
- [ ] Remove `CasbinPolicyAdapter` and call `SDK.evaluate_policy()` directly

---

## Tenant-Scoped Policies

CoreSDK policies are tenant-aware. Pass `tenant_id` in the input to scope decisions:

```python
with sdk.tenant_scope("tenant-abc"):
    allowed = sdk.evaluate_policy("data.myapp.authz.allow", {
        "sub":       get_current_user(),
        "resource":  "/api/orders",
        "action":    "GET",
        "tenant_id": get_current_tenant(),  # explicit scoping
    })
```

The sidecar enforces tenant isolation — a Rego policy loaded for `tenant-abc` cannot
be evaluated in the context of `tenant-xyz`.
