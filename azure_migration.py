#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Azure Migration Assessor – single-file, read-only (final polish + progress logging)
- Loads move-support table ONLY from your repo CSV (or env MOVE_SUPPORT_URL)
- Emits three CSVs: discovery / non-transferable reasons / blockers
- Verbose logging for progress, counts, and timing

Table rules (Subscription column = source of truth):
- Child must move with parent; supported children אינם חסם.
- Child supported + parent NOT → ParentNotSupported
- Child NOT + parent supported → UnsupportedChildTypeCannotMove
- Neither supported → UnsupportedResourceType
- Any validateMoveResources policy/permission/lock/provider errors = blockers
"""

import os, subprocess, json, csv, io, re, urllib.request, logging, time
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

# ---------------- Config ----------------
os.environ.setdefault("AZURE_CORE_NO_COLOR", "1")
os.environ.setdefault("AZURE_EXTENSION_USE_DYNAMIC_INSTALL", "yes_without_prompt")

MOVE_SUPPORT_URL = os.getenv(
    "MOVE_SUPPORT_URL",
    "https://raw.githubusercontent.com/GuyAshkenazi-TS/Test/refs/heads/main/move-support-resources-local.csv"
)
MISSING = "Not available"

# Known aliases / normalizations (rare typos / cosmetic variants that appear in some exports)
TYPE_ALIASES = {
    # example: "microsoft.network/networkmanager" : "microsoft.network/networkmanagers",
}

# Progress printing granularity for large batches
PROGRESS_EVERY_N_RESOURCES = 100

# ---------------- Shell helpers ----------------
def az(cmd: List[str], check: bool = True) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise subprocess.CalledProcessError(p.returncode, cmd, p.stdout, p.stderr)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()

def az_json(cmd: List[str], default: Any):
    try:
        _, out, _ = az(cmd, check=False)
        return json.loads(out) if out else default
    except Exception:
        return default

def ensure_login():
    az(["az", "account", "show", "--only-show-errors"], check=False)

# ---------------- String / type helpers ----------------
def normalize_type(s: str) -> str:
    if not s: return ""
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

# ---------------- Move-support (CSV from repo) ----------------
def load_move_support_map_from_url(url: str) -> Dict[str, bool]:
    with urllib.request.urlopen(url) as resp:
        raw = resp.read()
    text = raw.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
    rdr = csv.DictReader(io.StringIO(text))

    support: Dict[str, bool] = {}
    for row in rdr:
        if not row:
            continue
        col_ns  = _pick_col(row, "resourceProvider", "provider", "namespace", "rp")
        col_rt  = _pick_col(row, "resourceType", "type", "resourcetype")
        col_sub = _pick_col(row, "subscription", "subscription_move", "subscription support")

        if not (col_ns and col_rt and col_sub):
            continue

        ns  = normalize_type(row.get(col_ns, ""))
        rt  = normalize_type(row.get(col_rt, ""))
        sub = (row.get(col_sub, "") or "").strip().lower()

        if not ns or not rt:
            continue

        key = f"{ns}/{rt}"
        support[key] = sub.startswith("yes")  # "Yes..." variants supported

    if not support:
        raise RuntimeError("Support map is empty after parsing CSV.")
    return support

def load_move_support_map() -> Dict[str, bool]:
    logging.info(f"Downloading move-support CSV from: {MOVE_SUPPORT_URL}")
    return load_move_support_map_from_url(MOVE_SUPPORT_URL)

# ---------------- Offer / Owner / Transferability ----------------
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

def transferable_to_ea(offer: str) -> str:
    return "Yes" if offer in ("EA","Pay-As-You-Go") else "No"

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

def reason_for_non_transferable(offer: str, state: str, auth_src: str) -> Tuple[str,str,str]:
    if state and state.lower()!="enabled":
        return ("DisabledSubscription","Subscription must be Active/Enabled before transfer.","Move prerequisites")
    if offer == "CSP":
        return ("PartnerManagedNotDirectToEA","CSP → EA isn’t an automatic billing transfer; requires manual resource move.","Move resources guidance")
    if offer in ("MCA-online","MCA-E"):
        return ("ManualResourceMoveRequired","MCA → EA direct billing transfer isn’t supported; move resources into EA subscription.","Move resources guidance")
    if offer in ("MSDN", MISSING):
        return ("NotSupportedOffer","Dev/Test or classic/unknown offer isn’t supported for a direct EA transfer.","Transfer matrix")
    return ("Unknown","Insufficient data to determine blocking reason.","Check tenant/offer/permissions")

# ---------------- Inventory & validation ----------------
def list_rgs(sub_id: str) -> List[str]:
    rgs = az_json(["az","group","list","--subscription",sub_id,"-o","json"], [])
    return [rg.get("name") for rg in rgs if rg.get("name")]

def list_resources_by_rg(subscription_id: str) -> Dict[str,List[str]]:
    resources = az_json(["az","resource","list","--subscription",subscription_id,
                         "--query","[].{id:id, type:type, rg:resourceGroup}","-o","json"], [])
    non_movable = {
        "Microsoft.Network/networkWatchers",
        "Microsoft.OffAzure/VMwareSites",
        "Microsoft.OffAzure/MasterSites",
        "Microsoft.Migrate/migrateprojects",
        "Microsoft.Migrate/assessmentProjects",
    }
    grouped={}
    for r in resources:
        if r.get("type") in non_movable: 
            continue
        rg=r.get("rg"); rid=r.get("id")
        if rg and rid: grouped.setdefault(rg, []).append(rid)
    return grouped

def pick_intrasub_target_rg(sub_id: str, src_rg: str, all_rgs: List[str]) -> str:
    candidates = [r for r in all_rgs if r and r.lower()!=src_rg.lower()]
    if not candidates: return ""
    for pref in ("migr","target","transit","move"):
        for r in candidates:
            if pref in r.lower(): return r
    return candidates[0]

def validate_move_resources(source_sub: str, rg: str, resource_ids: List[str], target_rg_id: str) -> Dict[str,Any]:
    body = json.dumps({"resources": resource_ids, "targetResourceGroup": target_rg_id})
    code, out, err = az(["az","resource","invoke-action","--action","validateMoveResources",
                         "--ids", f"/subscriptions/{source_sub}/resourceGroups/{rg}",
                         "--request-body", body], check=False)
    if code==0 and out:
        try: return json.loads(out)
        except Exception: return {}
    return {"error":{"code":"ValidationFailed","message": err or "Validation failed"}}

# ---------------- Parse types & classification ----------------
def parse_types(resource_id: str):
    """
    Returns: is_child, top_level_type, full_type, parent_id, parent_type
    ex: .../providers/Microsoft.Web/sites/myapp/slots/stage
        top = microsoft.web/sites, full = microsoft.web/sites/slots
    """
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

def classify_support(resource_id: str, support: Dict[str,bool]) -> Dict[str,Any]:
    is_child, top_type, full_type, parent_id, parent_type = parse_types(resource_id)
    top_ok  = support.get(top_type or "", None)
    full_ok = support.get(full_type or "", None)
    this_ok = full_ok if full_ok is not None else top_ok

    if this_ok is None:
        return {
            "BlockerCategory": "Unknown",
            "Why": "Resource type not found in official move-support table (subscription column). Review manually.",
            "DocRef": "move-support",
            "ResourceType": (full_type or top_type or ""),
            "IsChild": "Yes" if is_child else "No",
            "ParentId": parent_id or "",
            "ParentType": parent_type or "",
        }

    if this_ok is True:
        if is_child and top_ok is False:
            return {
                "BlockerCategory": "ParentNotSupported",
                "Why": "Parent resource type doesn’t support subscription move.",
                "DocRef": "move-support",
                "ResourceType": full_type or top_type or "",
                "IsChild": "Yes",
                "ParentId": parent_id or "",
                "ParentType": parent_type or "",
            }
        return {}  # OK

    # Not supported
    if is_child:
        if top_ok is True:
            return {
                "BlockerCategory":"UnsupportedChildTypeCannotMove",
                "Why":"Child resource type doesn’t support subscription move although parent does.",
                "DocRef":"move-support",
                "ResourceType": full_type or top_type or "",
                "IsChild":"Yes",
                "ParentId": parent_id or "",
                "ParentType": parent_type or "",
            }
        else:
            return {
                "BlockerCategory":"UnsupportedResourceType",
                "Why":"Neither child nor parent supports subscription move.",
                "DocRef":"move-support",
                "ResourceType": full_type or top_type or "",
                "IsChild":"Yes",
                "ParentId": parent_id or "",
                "ParentType": parent_type or "",
            }
    else:
        return {
            "BlockerCategory":"UnsupportedResourceType",
            "Why":"Resource type doesn’t support subscription move.",
            "DocRef":"move-support",
            "ResourceType": top_type or "",
            "IsChild":"No",
            "ParentId":"",
            "ParentType":"",
        }

# ---------------- ARM error mapping (enhanced) ----------------
def _shorten(s: str, n: int = 280) -> str:
    s = (s or "").strip()
    return s if len(s) <= n else (s[:n-1] + "…")

def blocker_from_arm_error(err: Dict[str,Any]) -> Tuple[str,str,str]:
    details = []
    try:
        details = err.get("details") or []
    except Exception:
        details = []
    detail_text = " | ".join([json.dumps(d, ensure_ascii=False) for d in details])

    blob = (json.dumps(err, ensure_ascii=False) + " " + detail_text).lower()

    if "requestdisallowedbypolicy" in blob or " policy" in blob:
        if "tag" in blob and "owner" in blob and "email" in blob:
            return ("PolicyBlocked","Required 'owner' tag with valid email (may require specific domain).","Align tags/policy and re-validate")
        return ("PolicyBlocked","Blocked by Azure Policy on source/target RG or subscription.","Align policy and re-validate")
    if "lock" in blob or "readonly" in blob or "cannot modify because it is locked" in blob:
        return ("ResourceLockPresent","Read-only lock on source or destination RG/subscription.","Remove lock before move")
    if "not registered for a resource type" in blob or ("provider" in blob and "register" in blob):
        return ("ProviderRegistrationMissing","Destination subscription missing required Resource Provider registration.","Register provider in target subscription")
    if "linkedauthorizationfailed" in blob:
        return ("InsufficientPermissions","Linked scope authorization failed on source/target.","Grant required roles at linked scope")
    if "authorization" in blob or "not permitted" in blob or "insufficient privileges" in blob or "denyassignment" in blob:
        return ("InsufficientPermissions","Caller lacks required permissions on source/destination.","Ensure moveResources on source RG + write on target RG")
    if "child" in blob and "parent" in blob and ("must be moved together" in blob or "dependen" in blob):
        return ("CrossRGParentChildDependency","Child must move with its parent (or vice versa).","Move together / unify RG first")
    if "cannot be moved" in blob or "not supported for move" in blob or "resource type is not supported for move" in blob:
        return ("UnsupportedResourceType","Resource type/SKU isn’t supported for move.","See move-support table")

    why = _shorten(err.get("message") or err.get("code") or "Azure returned a validation failure.")
    return ("ValidationFailed", why, "See ARM move guidance")

# ---------------- Main ----------------
def main():
    start_t = time.time()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    ensure_login()

    # Load support table (CSV from your repo)
    support_map = load_move_support_map()
    logging.info(f"Loaded {len(support_map)} resource-type rows into support map.")

    headers_discovery = ["Subscription ID","Sub. Type","Sub. Owner","Transferable (Internal)"]
    headers_reasons   = ["Subscription ID","Sub. Type","ReasonCode","Why","DocRef"]
    headers_blockers  = ["SubscriptionId","ResourceGroup","ResourceId","ResourceType","IsChild","ParentId","ParentType","BlockerCategory","Why","DocRef"]

    subs = az_json(["az","account","list","--all","-o","json"], [])
    total_subs = len(subs or [])
    logging.info(f"Discovered {total_subs} subscriptions.")

    billing_accounts = az_json(["az","billing","account","list","-o","json"], [])
    overall_agreement = ""
    try: overall_agreement = (billing_accounts[0].get("agreementType") or "")
    except Exception: pass

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_discovery = f"azure_env_discovery_{ts}.csv"
    out_reasons   = f"non_transferable_reasons_{ts}.csv"
    out_blockers  = f"blockers_details_{ts}.csv"

    rows_discovery=[]; rows_reasons=[]
    non_transferable_subs: List[str] = []

    # ---- Stage 1: discovery ----
    for idx, s in enumerate(subs, start=1):
        sub_id = s.get("id",""); state = s.get("state","")
        logging.info(f"[{idx}/{total_subs}] Inspecting subscription {sub_id} (state={state})")
        if not sub_id: 
            logging.warning(f"Subscription at index {idx} has no ID; skipping.")
            continue

        arm = az_json(["az","rest","--method","get","--url", f"https://management.azure.com/subscriptions/{sub_id}?api-version=2020-01-01","-o","json"], {})
        has_err=("error" in arm)
        quota_id = arm.get("subscriptionPolicies",{}).get("quotaId","") if not has_err else ""
        auth_src = arm.get("authorizationSource","") if not has_err else ""
        bsub = az_json(["az","billing","subscription","show","--subscription-id",sub_id,"-o","json"], {})
        has_mca = bool(bsub.get("billingAccountId")) if bsub else ("MicrosoftCustomerAgreement" in overall_agreement)

        offer = offer_from_quota(quota_id, auth_src, has_mca)
        owner = resolve_owner(sub_id, offer)
        transferable = transferable_to_ea(offer)

        rows_discovery.append([sub_id, offer, owner, transferable])

        if transferable == "No":
            code, why, doc = reason_for_non_transferable(offer, state, auth_src)
            rows_reasons.append([sub_id, offer, code, why, doc])
            non_transferable_subs.append(sub_id)

    with open(out_discovery,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(headers_discovery); w.writerows(rows_discovery)
    with open(out_reasons,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(headers_reasons); w.writerows(rows_reasons)
    logging.info(f"✅ Discovery CSV: {out_discovery}  |  Reasons CSV: {out_reasons}")
    logging.info(f"Marked {len(non_transferable_subs)} non-transferable subscriptions for blockers scan.")

    # ---- Stage 2: blockers ----
    blockers_rows: List[List[str]] = []
    total_resources_examined = 0
    total_blockers_found = 0
    total_rgs_examined = 0

    for sidx, sub_id in enumerate(non_transferable_subs, start=1):
        sub_t0 = time.time()
        all_rgs = list_rgs(sub_id)
        if not all_rgs or len(all_rgs)==0:
            logging.info(f"[{sidx}/{len(non_transferable_subs)}] {sub_id}: no resource groups → skipping blockers.")
            continue

        grouped = list_resources_by_rg(sub_id)
        if not grouped:
            logging.info(f"[{sidx}/{len(non_transferable_subs)}] {sub_id}: no resources → skipping blockers.")
            continue

        rg_names = list(grouped.keys())
        logging.info(f"[{sidx}/{len(non_transferable_subs)}] {sub_id}: {len(rg_names)} RGs with resources to check.")
        for ridx, src_rg in enumerate(rg_names, start=1):
            ids = grouped.get(src_rg, []) or []
            total_rgs_examined += 1
            if not ids:
                logging.info(f"  RG {ridx}/{len(rg_names)} '{src_rg}': 0 resources → skip.")
                continue

            tgt_rg = pick_intrasub_target_rg(sub_id, src_rg, all_rgs)
            if not tgt_rg:
                logging.info(f"  RG {ridx}/{len(rg_names)} '{src_rg}': no alternate target RG → skip validation.")
                continue
            target_rg_id = f"/subscriptions/{sub_id}/resourceGroups/{tgt_rg}"

            logging.info(f"  RG {ridx}/{len(rg_names)} '{src_rg}': validating {len(ids)} resources → target '{tgt_rg}'")
            batch_t0 = time.time()
            result = validate_move_resources(sub_id, src_rg, ids, target_rg_id)

            # Global ARM error
            if isinstance(result, dict) and "error" in result:
                cat, why, doc = blocker_from_arm_error(result["error"])
                for rid in ids:
                    is_child, top_t, full_t, parent_id, parent_t = parse_types(rid)
                    blockers_rows.append([
                        sub_id, src_rg, rid,
                        (full_t or top_t or ""),
                        "Yes" if is_child else "No",
                        parent_id or "",
                        parent_t or "",
                        cat, why, doc
                    ])
                total_resources_examined += len(ids)
                total_blockers_found += len(ids)
                logging.info(f"    ⛔ Global ARM error → marked {len(ids)} blockers (cat={cat}). Took {time.time()-batch_t0:.1f}s.")
                continue

            # Table-driven per-resource
            batch_blockers = 0
            for i, rid in enumerate(ids, start=1):
                cls = classify_support(rid, support_map)
                if cls:
                    blockers_rows.append([
                        sub_id,
                        src_rg,
                        rid,
                        cls.get("ResourceType",""),
                        cls.get("IsChild","No"),
                        cls.get("ParentId",""),
                        cls.get("ParentType",""),
                        cls.get("BlockerCategory","Unknown"),
                        cls.get("Why",""),
                        cls.get("DocRef","move-support"),
                    ])
                    batch_blockers += 1
                total_resources_examined += 1
                # Progress pulse for very large RGs
                if i % PROGRESS_EVERY_N_RESOURCES == 0:
                    logging.info(f"    Progress: {i}/{len(ids)} resources classified in RG '{src_rg}'...")

            total_blockers_found += batch_blockers
            logging.info(f"    ✅ RG '{src_rg}': {len(ids)} resources classified, blockers found: {batch_blockers}. Took {time.time()-batch_t0:.1f}s.")

        logging.info(f"Finished subscription {sub_id} in {time.time()-sub_t0:.1f}s.")

    # Write blockers CSV
    if blockers_rows:
        with open(out_blockers,"w",newline="",encoding="utf-8") as f:
            w=csv.writer(f); w.writerow(headers_blockers); w.writerows(blockers_rows)
        logging.info(f"🔎 Blockers CSV: {out_blockers}")
    else:
        logging.info("🔎 Blockers scan: none detected (validateMoveResources + official move-support table).")

    # ---- Summary ----
    elapsed = time.time() - start_t
    logging.info("====================================================")
    logging.info(f"SUMMARY: subs={total_subs}, non-transferable scanned={len(non_transferable_subs)}, "
                 f"RGs scanned={total_rgs_examined}, resources examined={total_resources_examined}, "
                 f"blockers found={total_blockers_found}, elapsed={elapsed:.1f}s")
    logging.info("Outputs: %s | %s | %s", out_discovery, out_reasons, out_blockers if blockers_rows else "(no blockers csv)")

if __name__ == "__main__":
    main()
