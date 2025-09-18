#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Stage 2: Per-subscription resource scan (read-only, fast & scalable)
Outputs (file names כוללים את ה-Subscription לקלות):
  1) azure_env_discovery_<SUB>_<ts>.csv
  2) non_transferable_reasons_<SUB>_<ts>.csv
  3) blockers_details_<SUB>_<ts>.csv          -> רק No + Not in table (ואופציונלי ARM)
  4) resources_support_matrix_<SUB>_<ts>.csv  -> כל הריסורסים עם Yes/No/Not in table
"""

import os, subprocess, json, csv, io, re, urllib.request, logging, time, argparse
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple, Optional

os.environ.setdefault("AZURE_CORE_NO_COLOR", "1")
os.environ.setdefault("AZURE_EXTENSION_USE_DYNAMIC_INSTALL", "yes_without_prompt")

MISSING = "Not available"

def az(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()

def az_json(cmd, default):
    try:
        _, out, _ = az(cmd)
        return json.loads(out) if out else default
    except Exception:
        return default

def ensure_login():
    az(["az","account","show","--only-show-errors"])

# ---------- normalize ----------
TYPE_ALIASES = {}
def normalize_type(s: str) -> str:
    if not s: return ""
    import re
    t = s.strip().lower()
    t = re.sub(r"\s+", "", t)
    t = re.sub(r"/+", "/", t)
    t = TYPE_ALIASES.get(t, t)
    return t

def _pick_col(row, *candidates):
    if not row: return None
    keys = {k.lower(): k for k in row.keys()}
    for c in candidates:
        k = keys.get(c.lower())
        if k: return k
    return None

# ---------- support table ----------
def load_move_support_map_from_url(url: str) -> Dict[str, Tuple[Optional[bool], str]]:
    with urllib.request.urlopen(url) as resp:
        raw = resp.read()
    text = raw.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
    rdr = csv.DictReader(io.StringIO(text))
    support: Dict[str, Tuple[Optional[bool], str]] = {}
    for row in rdr:
        if not row:
            continue
        col_ns   = _pick_col(row, "resourceProvider", "provider", "namespace", "rp")
        col_rt   = _pick_col(row, "resourceType", "type", "resourcetype")
        col_sub  = _pick_col(row, "subscription", "subscription_move", "subscription support")
        col_note = _pick_col(row, "note", "notes", "comment", "why")
        if not (col_ns and col_rt and col_sub):
            continue
        ns   = normalize_type(row.get(col_ns, ""))
        rt   = normalize_type(row.get(col_rt, ""))
        subs = (row.get(col_sub, "") or "").strip().lower()
        note = (row.get(col_note, "") or "").strip()
        if not ns or not rt:
            continue
        key = f"{ns}/{rt}"
        if subs.startswith("yes"):
            support[key] = (True, note)
        elif subs.startswith("no"):
            support[key] = (False, note)
        else:
            support[key] = (None, note)
    if not support:
        raise RuntimeError("Support map is empty after parsing CSV.")
    return support

# ---------- offers/owners ----------
def offer_from_quota(quota_id: str, authorization_source: str, has_mca_billing_link: bool) -> str:
    q = quota_id or ""
    if any(x in q for x in ("MSDN","MS-AZR-0029P","MS-AZR-0062P","MS-AZR-0063P","VisualStudio","VS")):
        return "MSDN"
    if q == "PayAsYouGo_2014-09-01" or any(x in q for x in ("MS-AZR-0003P","MS-AZR-0017P","MS-AZR-0023P")):
        return "Pay-As-You-Go"
    if any(x in q for x in ("MS-AZR-0145P","MS-AZR-0148P","MS-AZR-0033P","MS-AZR-0034P")):
        return "EA"
    if authorization_source == "ByPartner":
        return "CSP"
    if has_mca_billing_link:
        return "MCA-online"
    return MISSING

def get_classic_account_admin_via_rest(sub_id: str) -> str:
    url = f"https://management.azure.com/subscriptions/{sub_id}/providers/Microsoft.Authorization/classicAdministrators?api-version=2015-06-01"
    js = az_json(["az","rest","--only-show-errors","--method","get","--url",url,"-o","json"], {})
    try:
        for item in js.get("value", []):
            if (item.get("properties", {}) or {}).get("role") == "Account Administrator":
                em = (item.get("properties", {}) or {}).get("emailAddress","")
                if em: return em
    except Exception:
        pass
    return ""

def mca_billing_owner_for_sub(sub_id: str) -> str:
    bsub = az_json(["az","billing","subscription","show","--subscription-id",sub_id,"-o","json"], {})
    ba = bsub.get("billingAccountId"); bp = bsub.get("billingProfileId"); inv = bsub.get("invoiceSectionId")
    scope=None
    if ba and bp and inv: scope=f"/providers/Microsoft.Billing/billingAccounts/{ba}/billingProfiles/{bp}/invoiceSections/{inv}"
    elif ba and bp:       scope=f"/providers/Microsoft.Billing/billingAccounts/{ba}/billingProfiles/{bp}"
    elif ba:              scope=f"/providers/Microsoft.Billing/billingAccounts/{ba}"
    if not scope: return ""
    roles = az_json(["az","billing","role-assignment","list","--scope",scope,"-o","json"], [])
    for r in roles:
        if (r.get("roleDefinitionName") or "") == "Owner":
            return r.get("principalEmail") or r.get("principalName") or r.get("signInName") or ""
    return ""

def resolve_owner(sub_id: str, offer: str) -> str:
    if offer in ("MSDN","Pay-As-You-Go","EA"):
        owner = get_classic_account_admin_via_rest(sub_id)
        return owner if owner else ("Check in EA portal - Account Owner" if offer=="EA" else "Check in Portal - classic subscription")
    if offer in ("MCA-online","MCA-E"):
        owner = mca_billing_owner_for_sub(sub_id)
        return owner if owner else "Check in Billing (MCA)"
    if offer == "CSP":
        return "Managed by partner - CSP"
    return MISSING

def transferable_to_ea(offer: str) -> str:
    return "Yes" if offer in ("EA","Pay-As-You-Go") else "No"

# ---------- inventory ----------
def list_rgs(sub_id: str) -> List[str]:
    rgs = az_json(["az","group","list","--subscription",sub_id,"-o","json"], [])
    return [rg.get("name") for rg in rgs if rg.get("name")]

def list_resources_by_rg(subscription_id: str) -> Dict[str,List[str]]:
    resources = az_json(["az","resource","list","--subscription",subscription_id,
                         "--query","[].{id:id, type:type, rg:resourceGroup}","-o","json"], [])
    non_movable = {"Microsoft.Network/networkWatchers","Microsoft.OffAzure/VMwareSites",
                   "Microsoft.OffAzure/MasterSites","Microsoft.Migrate/migrateprojects",
                   "Microsoft.Migrate/assessmentProjects"}
    grouped={}
    for r in resources:
        if r.get("type") in non_movable: 
            continue
        rg=r.get("rg"); rid=r.get("id")
        if rg and rid: grouped.setdefault(rg, []).append(rid)
    return grouped

# ---------- ARM (optional) ----------
def validate_move_resources(source_sub: str, rg: str, resource_ids: List[str], target_rg_id: str) -> Dict[str,Any]:
    body = json.dumps({"resources": resource_ids, "targetResourceGroup": target_rg_id})
    code, out, err = az(["az","resource","invoke-action","--action","validateMoveResources",
                         "--ids", f"/subscriptions/{source_sub}/resourceGroups/{rg}",
                         "--request-body", body],)
    if code==0 and out:
        try: return json.loads(out)
        except Exception: return {}
    return {"error":{"code":"ValidationFailed","message": err or "Validation failed"}}

def _shorten(s: str, n: int = 240) -> str:
    s = (s or "").strip()
    return s if len(s) <= n else (s[:n-1] + "…")

def arm_error_to_tuple(err: Dict[str,Any]) -> Tuple[str,str,str]:
    blob = json.dumps(err, ensure_ascii=False).lower()
    if "requestdisallowedbypolicy" in blob or " policy" in blob:
        return ("PolicyBlocked","Blocked by Azure Policy on source/target.","Align policy & re-validate")
    if "lock" in blob or "readonly" in blob:
        return ("ResourceLockPresent","Read-only lock on source/destination RG/subscription.","Remove lock before move")
    if "not registered for a resource type" in blob or ("provider" in blob and "register" in blob):
        return ("ProviderRegistrationMissing","Missing provider registration in target subscription.","Register provider in target subscription")
    if "denyassignment" in blob or "insufficient" in blob or "not permitted" in blob or "authorization" in blob:
        return ("InsufficientPermissions","Caller lacks required permissions.","Ensure moveResources on source + write on target")
    if "cannot be moved" in blob or "not supported for move" in blob:
        return ("UnsupportedResourceType","Type/SKU not supported for move.","move-support")
    return ("ValidationFailed", _shorten(err.get("message") or err.get("code") or ""), "ARM validateMoveResources")

# ---------- parse/classify ----------
def parse_types(resource_id: str):
    m = re.search(r"/providers/([^/]+)/([^/]+)(/.*)?", resource_id, re.IGNORECASE)
    if not m:
        return False, None, None, None, None
    ns, t0, rest = m.group(1), m.group(2), (m.group(3) or "")
    top_type = normalize_type(f"{ns}/{t0}")
    segs = [s for s in rest.strip("/").split("/") if s]
    is_child = False
    full_type = top_type
    parent_id = None
    parent_type = top_type
    if len(segs) >= 3:
        is_child = True
        child_type = segs[1].lower()
        full_type  = f"{top_type}/{child_type}"
        parent_id = re.sub(r"(/providers/[^/]+/[^/]+/[^/]+).*", r"\1", resource_id, flags=re.IGNORECASE)
    return is_child, top_type, full_type, parent_id, parent_type

def table_status_for_type(full_type: Optional[str], top_type: Optional[str], support: Dict[str, Tuple[Optional[bool], str]]):
    if full_type and full_type in support:
        return support[full_type][0], support[full_type][1], full_type
    if top_type and top_type in support:
        return support[top_type][0], support[top_type][1], top_type
    return None, "", (full_type or top_type or "")

# ---------- main ----------
def main():
    t0 = time.perf_counter()

    parser = argparse.ArgumentParser(description="Per-subscription Azure resource assessor (read-only)")
    parser.add_argument("--subscription", required=True, help="Subscription ID to scan")
    parser.add_argument("--move-support-url", default="https://raw.githubusercontent.com/GuyAshkenazi-TS/azure-env-assessment/refs/heads/main/move-support-resources-local.csv")
    parser.add_argument("--include-arm-blockers", default="0", choices=["0","1"])
    parser.add_argument("--run-arm-validate", default="0", choices=["0","1"])
    args = parser.parse_args()

    sub_id = args.subscription
    MOVE_SUPPORT_URL = args.move_support_url
    INCLUDE_ARM_BLOCKERS = (args.include_arm_blockers == "1")
    RUN_ARM_VALIDATE = (args.run_arm_validate == "1")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    logging.info(f"Stage-2 starting for subscription: {sub_id}")
    logging.info(f"Support table: {MOVE_SUPPORT_URL}")
    logging.info(f"ARM validate: {'ON' if RUN_ARM_VALIDATE else 'OFF'} | Include ARM blockers in CSV: {'ON' if INCLUDE_ARM_BLOCKERS else 'OFF'}")

    ensure_login()

    # load table
    support_map = load_move_support_map_from_url(MOVE_SUPPORT_URL)
    logging.info(f"Loaded {len(support_map)} type rows from support table.")

    # filenames (לכל קובץ מצרפים את הסאבסקריפשן)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_discovery = f"azure_env_discovery_{sub_id}_{ts}.csv"
    out_reasons   = f"non_transferable_reasons_{sub_id}_{ts}.csv"
    out_blockers  = f"blockers_details_{sub_id}_{ts}.csv"
    out_allres    = f"resources_support_matrix_{sub_id}_{ts}.csv"

    # headers
    headers_discovery = ["Subscription ID","Sub. Type","Sub. Owner","Transferable (Internal)"]
    headers_reasons   = ["Subscription ID","Sub. Type","ReasonCode","Why","DocRef"]
    headers_blockers  = ["SubscriptionId","ResourceGroup","ResourceId","ResourceType","IsChild","ParentId","ParentType","BlockerCategory","Why","DocRef","TableNote","ArmMessage"]
    headers_allres    = ["SubscriptionId","ResourceGroup","ResourceId","ResourceType","IsChild","ParentId","ParentType","TableSupport","TableNote","ArmMessage"]

    # discovery (למנוי בודד)
    arm = az_json(["az","rest","--method","get","--url", f"https://management.azure.com/subscriptions/{sub_id}?api-version=2020-01-01","-o","json"], {})
    has_err=("error" in arm)
    quota_id = arm.get("subscriptionPolicies",{}).get("quotaId","") if not has_err else ""
    auth_src = arm.get("authorizationSource","") if not has_err else ""
    bsub = az_json(["az","billing","subscription","show","--subscription-id",sub_id,"-o","json"], {})
    offer = offer_from_quota(quota_id, auth_src, bool(bsub.get("billingAccountId")))
    owner = resolve_owner(sub_id, offer)
    transferable = "Yes" if offer in ("EA","Pay-As-You-Go") else "No"

    with open(out_discovery,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(headers_discovery); w.writerow([sub_id, offer, owner, transferable])
    reasons=[]
    if transferable=="No":
        if auth_src=="ByPartner":
            reasons.append([sub_id, offer, "PartnerManagedNotDirectToEA","CSP → EA requires manual resource move.","Move resources guidance"])
        elif offer in ("MCA-online","MCA-E"):
            reasons.append([sub_id, offer, "ManualResourceMoveRequired","MCA → EA billing transfer unsupported; move resources.","Move resources guidance"])
        elif offer in ("MSDN", MISSING):
            reasons.append([sub_id, offer, "NotSupportedOffer","Dev/Test or classic/unknown offer not supported for direct EA transfer.","Transfer matrix"])
        else:
            reasons.append([sub_id, offer, "Unknown","Insufficient data.","Check tenant/offer/permissions"])
    with open(out_reasons,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(headers_reasons); w.writerows(reasons)

    print(f"✅ Discovery CSV: {out_discovery}")
    print(f"✅ Reasons   CSV: {out_reasons}")

    # Pre-scan inventory
    rgs = list_rgs(sub_id)
    grouped = list_resources_by_rg(sub_id)
    rg_count = len(grouped)
    res_count = sum(len(v) for v in grouped.values())
    logging.info(f"[Pre-scan] {sub_id}: {rg_count} RGs, {res_count} resources.")
    if res_count == 0:
        with open(out_blockers,"w",newline="",encoding="utf-8") as f:
            csv.writer(f).writerow(headers_blockers)
        with open(out_allres,"w",newline="",encoding="utf-8") as f:
            csv.writer(f).writerow(headers_allres)
        print("No resources found.")
        return

    # Optional ARM validate (RG-level)
    arm_rg_errors = {}
    arm_rg_msg = {}
    if RUN_ARM_VALIDATE:
        logging.info("ARM validateMoveResources: running
