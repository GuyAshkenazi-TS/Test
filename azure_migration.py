#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Azure Migration Assessor – table-first, read-only (ALL resources coverage)

Outputs:
1) azure_env_discovery_<ts>.csv
2) non_transferable_reasons_<ts>.csv
3) resources_move_support_<ts>.csv  ← כל הריסורסים בכל הסאבים: Yes / No / Not in table
4) blockers_details_<ts>.csv        ← רק No מהטבלה (Not Movable)

Notes:
- מקורות האמת ל-Yes/No הם עמודת Subscription בטבלת ה-CSV שלך (MOVE_SUPPORT_URL).
- Unknown הוחלף ל-"Not in table".
- לוגינג מציג ספירה כוללת של ריסורסים + התקדמות.
- אפשרות ARM validate לצרכי אינדיקציה (לא חובה): VALIDATE_ARM=1
- שליטה בתדירות פרוגרס: PROGRESS_EVERY (ברירת מחדל 50)
"""

import os, subprocess, json, csv, io, re, urllib.request, logging
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

# ---------- Config ----------
os.environ.setdefault("AZURE_CORE_NO_COLOR", "1")
os.environ.setdefault("AZURE_EXTENSION_USE_DYNAMIC_INSTALL", "yes_without_prompt")

MOVE_SUPPORT_URL = os.getenv(
    "MOVE_SUPPORT_URL",
    "https://raw.githubusercontent.com/GuyAshkenazi-TS/Test/refs/heads/main/move-support-resources-local.csv"
)
VALIDATE_ARM   = os.getenv("VALIDATE_ARM", "0") == "1"
PROGRESS_EVERY = max(1, int(os.getenv("PROGRESS_EVERY", "50")))

MISSING = "Not available"

TYPE_ALIASES = {
    # דוגמאות אם צריך לנרמל שמות טיפוסים חריגים:
    # "microsoft.network/networkmanager": "microsoft.network/networkmanagers",
}

# ---------- Shell helpers ----------
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

# ---------- String / type ----------
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

# ---------- Move-support map ----------
def load_move_support_map_from_url(url: str) -> Dict[str, Dict[str, Any]]:
    with urllib.request.urlopen(url) as resp:
        raw = resp.read()
    text = raw.decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
    rdr = csv.DictReader(io.StringIO(text))

    support: Dict[str, Dict[str, Any]] = {}
    for row in rdr:
        if not row:
            continue
        col_ns   = _pick_col(row, "resourceProvider", "provider", "namespace", "rp")
        col_rt   = _pick_col(row, "resourceType", "type", "resourcetype")
        col_sub  = _pick_col(row, "subscription", "subscription_move", "subscription support")
        col_note = _pick_col(row, "subscription_note", "note", "subscriptionreason", "reason")

        if not (col_ns and col_rt and col_sub):
            continue

        ns  = normalize_type(row.get(col_ns, ""))
        rt  = normalize_type(row.get(col_rt, ""))
        sub = (row.get(col_sub, "") or "").strip().lower()
        note = (row.get(col_note, "") or "").strip() if col_note else ""

        if not ns or not rt:
            continue

        key = f"{ns}/{rt}"
        if sub.startswith("yes"):
            ok: Optional[bool] = True
        elif sub.startswith("no"):
            ok = False
        else:
            ok = None  # Not in table

        support[key] = {"ok": ok, "note": note}

    if not support:
        raise RuntimeError("Support map is empty after parsing CSV.")
    return support

def load_move_support_map() -> Dict[str, Dict[str, Any]]:
    logging.info(f"Downloading move-support CSV: {MOVE_SUPPORT_URL}")
    return load_move_support_map_from_url(MOVE_SUPPORT_URL)

# ---------- Offer / Owner / Transferability ----------
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

# ---------- Inventory ----------
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

# ---------- Parse types ----------
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

# ---------- Table lookup ----------
def table_status_for_type(full_type: str, top_type: str, support: Dict[str,Dict[str,Any]]) -> Tuple[Optional[bool], str, str]:
    full = support.get(full_type or "", None)
    top  = support.get(top_type or "", None)
    if full is not None and isinstance(full, dict) and "ok" in full:
        return full["ok"], full.get("note",""), full_type
    if top  is not None and isinstance(top, dict) and "ok" in top:
        return top["ok"], top.get("note",""), top_type
    return None, "", (full_type or top_type or "")

# ---------- Optional ARM validation (info only) ----------
def validate_move_resources(source_sub: str, rg: str, resource_ids: List[str], target_rg_id: str) -> Dict[str,Any]:
    body = json.dumps({"resources": resource_ids, "targetResourceGroup": target_rg_id})
    code, out, err = az(["az","resource","invoke-action","--action","validateMoveResources",
                         "--ids", f"/subscriptions/{source_sub}/resourceGroups/{rg}",
                         "--request-body", body], check=False)
    if code==0 and out:
        try: return json.loads(out)
        except Exception: return {"error":{"code":"ParseError","message":"Failed to parse ARM response"}}
    return {"error":{"code":"ValidationFailed","message": err or "Validation failed"}}

# ---------- Main ----------
def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    ensure_login()

    support_map = load_move_support_map()
    logging.info(f"Loaded {len(support_map)} resource-type rows into support map.")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_discovery   = f"azure_env_discovery_{ts}.csv"
    out_reasons     = f"non_transferable_reasons_{ts}.csv"
    out_resources   = f"resources_move_support_{ts}.csv"
    out_blockers    = f"blockers_details_{ts}.csv"

    headers_discovery = ["Subscription ID","Sub. Type","Sub. Owner","Transferable (Internal)"]
    headers_reasons   = ["Subscription ID","Sub. Type","ReasonCode","Why","DocRef"]
    headers_resources = ["SubscriptionId","ResourceGroup","ResourceId","ResourceType","IsChild","ParentId","ParentType","TableSupport","TableNote","ArmError"]
    headers_blockers  = ["SubscriptionId","ResourceGroup","ResourceId","ResourceType","IsChild","ParentId","ParentType","BlockerCategory","Why","DocRef","TableNote","ArmError"]

    # Stage 1: subscriptions discovery
    subs = az_json(["az","account","list","--all","-o","json"], [])
    billing_accounts = az_json(["az","billing","account","list","-o","json"], [])
    overall_agreement = ""
    try: overall_agreement = (billing_accounts[0].get("agreementType") or "")
    except Exception: pass

    rows_discovery=[]; rows_reasons=[]
    for s in subs:
        sub_id = s.get("id",""); state = s.get("state","")
        if not sub_id: continue

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

    with open(out_discovery,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(headers_discovery); w.writerows(rows_discovery)
    with open(out_reasons,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(headers_reasons); w.writerows(rows_reasons)
    print(f"✅ Discovery CSV: {out_discovery}")
    print(f"✅ Reasons   CSV: {out_reasons}")

    # Stage 2: ALL subscriptions → ALL resources (for resources_move_support),
    #          blockers_details יוציא רק No לפי הטבלה
    # Pre-count for progress
    total_to_scan = 0
    pre_grouped: Dict[str, Dict[str, List[str]]] = {}
    for s in subs:
        sub_id = s.get("id","")
        if not sub_id: continue
        grouped = list_resources_by_rg(sub_id)
        pre_grouped[sub_id] = grouped
        subtotal = sum(len(v) for v in grouped.values())
        total_to_scan += subtotal
        logging.info(f"Pre-scan: subscription {sub_id} has {subtotal} resources across {len(grouped)} RGs.")

    if total_to_scan == 0:
        logging.info("No resources found in any subscription.")
    else:
        logging.info(f"Total resources to scan: {total_to_scan}")

    rows_resources=[]; rows_blockers=[]
    scanned = 0
    total_blockers=0

    for sub_id, grouped in pre_grouped.items():
        if not grouped:
            continue

        # Optional ARM hint per-RG (purely informational)
        rg_arm_err: Dict[str, str] = {}
        if VALIDATE_ARM:
            rgs = list(grouped.keys())
            for src_rg, ids in grouped.items():
                tgt = next((r for r in rgs if r.lower()!=src_rg.lower()), "")
                if tgt:
                    target_rg_id = f"/subscriptions/{sub_id}/resourceGroups/{tgt}"
                    res = validate_move_resources(sub_id, src_rg, ids, target_rg_id)
                    if "error" in (res or {}):
                        arm_blob = (res.get("error", {}).get("message") or json.dumps(res.get("error", {}), ensure_ascii=False))
                        rg_arm_err[src_rg] = arm_blob
                        logging.info(f"[ARM hint] {sub_id}/{src_rg}: {arm_blob[:120]}")

        for src_rg, ids in grouped.items():
            arm_blob = rg_arm_err.get(src_rg, "") if VALIDATE_ARM else ""
            for rid in ids:
                is_child, top_t, full_t, parent_id, parent_t = parse_types(rid)
                t_ok, t_note, _tkey = table_status_for_type(full_t, top_t, support_map)
                table_support = ("Yes" if t_ok else ("No" if t_ok is False else "Not in table"))

                rows_resources.append([
                    sub_id, src_rg, rid,
                    (full_t or top_t or ""),
                    "Yes" if is_child else "No",
                    parent_id or "",
                    parent_t or "",
                    table_support,
                    t_note,
                    arm_blob
                ])

                if t_ok is False:
                    rows_blockers.append([
                        sub_id, src_rg, rid,
                        (full_t or top_t or ""),
                        "Yes" if is_child else "No",
                        parent_id or "",
                        parent_t or "",
                        "UnsupportedResourceType",
                        ("Not movable (table)" + (f": {t_note}" if t_note else "")),
                        "move-support",
                        t_note,
                        arm_blob
                    ])
                    total_blockers += 1

                scanned += 1
                if scanned % PROGRESS_EVERY == 0 or scanned == total_to_scan:
                    pct = (scanned / total_to_scan * 100.0) if total_to_scan else 100.0
                    logging.info(f"Progress: {scanned}/{total_to_scan} resources processed ({pct:.1f}%).")

    with open(out_resources,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(headers_resources); w.writerows(rows_resources)
    if rows_blockers:
        with open(out_blockers,"w",newline="",encoding="utf-8") as f:
            w=csv.writer(f); w.writerow(headers_blockers); w.writerows(rows_blockers)
        print(f"🔎 Blockers CSV (table-only): {out_blockers}")
    else:
        print("🔎 Blockers: none by table (no 'No' rows).")

    logging.info(f"Resources scanned: {scanned}, blockers (No): {total_blockers}")

    print("\n===== OUTPUT FILES =====")
    print(out_discovery)
    print(out_reasons)
    print(out_resources)
    if rows_blockers:
        print(out_blockers)
    print("========================\n")

if __name__ == "__main__":
    main()
