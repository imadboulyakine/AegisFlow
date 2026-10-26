"""Read-only Azure discovery for AegisFlow (ADR-017).

Uses the service principal from the AZURE_CLIENT_ID / AZURE_TENANT_ID /
AZURE_SUBSCRIPTION_ID / AZURE_CLIENT_SECRET environment variables. Performs ONLY HTTP GETs
against Azure Resource Manager (plus the OAuth token request, built in-process so the secret
never appears in argv). Never prints the secret or the token; GUIDs are masked.

Usage: python3 -I scripts/azure/discover.py
Stdlib only; honours HTTPS_PROXY and the system CA store.
"""
import base64
import json
import os
import sys
import urllib.parse
import urllib.request
from collections import Counter

ARM = "https://management.azure.com"


def mask(guid: str) -> str:
    return guid[:4] + "…" + guid[-4:] if guid and len(guid) > 8 else "?"


def http(method, url, data=None, token=None):
    req = urllib.request.Request(url, data=data, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        body = e.read()
        try:
            err = json.loads(body).get("error", {})
            msg = err.get("code", "") if isinstance(err, dict) else str(err)
        except Exception:
            msg = ""
        return e.code, {"_error": msg}


def get(path, token):
    status, body = http("GET", ARM + path, token=token)
    return status, body


_SECRET_IDS = []


def scrub(text) -> str:
    text = str(text)
    for guid in _SECRET_IDS:
        text = text.replace(guid, mask(guid))
    return text


def main():
    tenant = os.environ["AZURE_TENANT_ID"]
    client = os.environ["AZURE_CLIENT_ID"]
    sub = os.environ["AZURE_SUBSCRIPTION_ID"]
    _SECRET_IDS.extend([sub, tenant, client])
    form = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client,
        "client_secret": os.environ["AZURE_CLIENT_SECRET"],
        "scope": ARM + "/.default",
    }).encode()
    status, tok = http("POST", f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token", data=form)
    if status != 200 or "access_token" not in tok:
        print(f"token: FAILED http={status} error={tok.get('_error') or tok.get('error')}")
        sys.exit(1)
    token = tok["access_token"]
    payload = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    oid = claims.get("oid", "")
    print(f"token: OK (tenant {mask(tenant)}, app {mask(client)}, sp object {mask(oid)}, expires_in {tok.get('expires_in')}s)")

    s, b = get(f"/subscriptions/{sub}?api-version=2022-12-01", token)
    if s == 200:
        pol = b.get("subscriptionPolicies", {})
        print(f"subscription: {mask(sub)} name={b.get('displayName')!r} state={b.get('state')} "
              f"quotaId={pol.get('quotaId')} spendingLimit={pol.get('spendingLimit')} "
              f"placement={pol.get('locationPlacementId')}")
    else:
        print(f"subscription: http={s} {b.get('_error')}")

    s, b = get(f"/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments"
               f"?api-version=2022-04-01&$filter=assignedTo('{oid}')", token)
    print(f"role assignments for SP (http={s} {b.get('_error', '')}):")
    for ra in b.get("value", []):
        p = ra["properties"]
        rs, rd = get(p["roleDefinitionId"] + "?api-version=2022-04-01", token)
        role = rd.get("properties", {}).get("roleName", "?") if rs == 200 else f"? (http {rs})"
        scope = p.get("scope", "")
        scope_disp = scope.replace(sub, mask(sub))
        print(f"  - {role} @ {scope_disp or '/'}")

    s, b = get(f"/subscriptions/{sub}/providers/Microsoft.Authorization/policyAssignments?api-version=2023-04-01", token)
    print(f"policy assignments (http={s} {b.get('_error', '')}): {len(b.get('value', []))}")
    for pa in b.get("value", []):
        p = pa.get("properties", {})
        params = p.get("parameters", {}) or {}
        locs = None
        for k, v in params.items():
            if "location" in k.lower():
                locs = v.get("value")
        print(f"  - {scrub(p.get('displayName') or pa.get('name'))!r} enforcement={p.get('enforcementMode')}"
              + (f" allowedLocations={locs}" if locs is not None else ""))

    s, b = get(f"/subscriptions/{sub}/resourcegroups?api-version=2021-04-01", token)
    rgs = b.get("value", [])
    print(f"resource groups (http={s} {b.get('_error', '')}): {len(rgs)}")
    for rg in rgs:
        print(f"  - {rg['name']} ({rg['location']}) tags={rg.get('tags') or {}}")

    s, b = get(f"/subscriptions/{sub}/resources?api-version=2021-04-01", token)
    res = b.get("value", [])
    print(f"resources (http={s} {b.get('_error', '')}): {len(res)}")
    for t, n in Counter(r["type"] for r in res).most_common():
        print(f"  - {t}: {n}")

    print("resource providers:")
    for ns in ["Microsoft.App", "Microsoft.ContainerRegistry", "Microsoft.KeyVault",
               "Microsoft.OperationalInsights", "Microsoft.Insights", "Microsoft.ManagedIdentity",
               "Microsoft.DBforPostgreSQL", "Microsoft.Consumption", "Microsoft.Security",
               "Microsoft.PolicyInsights", "Microsoft.CostManagement"]:
        s, b = get(f"/subscriptions/{sub}/providers/{ns}?api-version=2021-04-01", token)
        state = b.get("registrationState", b.get("_error", ""))
        extra = ""
        if ns == "Microsoft.App" and s == 200:
            for rt in b.get("resourceTypes", []):
                if rt.get("resourceType") == "managedEnvironments":
                    locs = rt.get("locations", [])
                    extra = " managedEnvironments in France Central: %s, West Europe: %s" % (
                        "France Central" in locs, "West Europe" in locs)
        print(f"  - {ns}: {state} (http={s}){extra}")

    s, b = get(f"/subscriptions/{sub}/providers/Microsoft.Consumption/budgets?api-version=2023-05-01", token)
    print(f"budgets (http={s} {b.get('_error', '')}): {[x.get('name') for x in b.get('value', [])]}")

    s, b = get(f"/subscriptions/{sub}/providers/Microsoft.Security/pricings?api-version=2024-01-01", token)
    if s == 200:
        std = [x["name"] for x in b.get("value", []) if x.get("properties", {}).get("pricingTier") == "Standard"]
        print(f"defender plans on Standard (paid) tier: {std or 'none'}")
    else:
        print(f"defender pricings: http={s} {b.get('_error', '')}")

    s, b = get(f"/subscriptions/{sub}/locations?api-version=2022-12-01", token)
    names = sorted(x["name"] for x in b.get("value", []))
    eu = [n for n in names if any(k in n for k in ("france", "europe", "spain", "italy", "germany", "sweden", "switzerland", "poland", "uk"))]
    print(f"locations (http={s}): {len(names)} total; EU-ish: {eu}")


if __name__ == "__main__":
    main()
