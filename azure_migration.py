#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Azure Migration Assessor – single-file, read-only (final with pre-scan + blockers includes 'Not in table')
- Loads move-support table ONLY from your repo CSV (or env MOVE_SUPPORT_URL)
- No mutations – uses only GET/list operations (read-only)
- Emits four CSVs:
   1) azure_env_discovery_<ts>.csv
   2) non_transferable_reasons_<ts>.csv
   3) blockers_details_<ts>.csv            -> כל הריסורסים שהטבלה מסמנת No + כל מה ש'Not in table'
   4) resources_support_matrix_<ts>.csv    -> כל הריסורסים עם Yes/No/Not in table

דגלים אופציונליים:
- MOVE_SUPPORT_URL         (ברירת מחדל: ה-CSV מה-Repo שלך)
- RUN_ARM_VALIDATE=1       (רק לצירוף הודעת ARM לעמודת עזר; לא חוסם)
- INCLUDE_ARM_BLOCKERS=1   (אם באמת תרצה שגם ARM ייחשבו כחוסמים; ברירת מחדל כבוי)
"""

import os, subprocess, json, csv, io, re, urllib.request, logging
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

# ---------------- Config ----------------
os.environ.setdefault("AZURE_CORE_NO_COLOR", "1")
os.environ.setdefault("AZURE_EXTENSION_USE_DYNAMIC_INSTALL", "yes_without_prompt")

MOVE_SUPPORT_URL = os.getenv(
    "MOVE_SUPPORT_URL",
    "https://raw.githubusercontent.com/GuyAshkenazi-TS/Test/refs/heads/main/move-support-resources-local.csv"
)
INCLUDE_ARM_BLOCKERS = os.getenv("INCLUDE_ARM_BLOCKERS", "0") == "1"   # ברירת מחדל: לא
RUN_ARM_VALIDATE     = os.getenv("RUN_ARM_VALIDATE", "0") == "1"       # ברירת מחדל: לא
MISSING = "Not available"

# אופציונלי: אליאסים לסוגי ריסורסים
TYPE_ALIASES = {
    # "microsoft.network/networkmanager": "microsoft.network/networkmanagers",
}

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
def load_move_support_map_from_url(url: str) -> Dict[str, Tuple[Optional[bool], str]]:
    """
    מחזיר map:
      key = 'microsoft.xxx/type[/child]'
      val = (is_supported: True/False/None, note: str)
    """
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
            support[key] = (None, note)  # רשומה קיימת אך ללא Yes/No ברור

    if not support:
        raise RuntimeError("Support map is empty after parsing CSV.")
    return support

def load_move_support_map() -> Dict[str, Tuple[Optional[bool], str]]:
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

# ---------------- Inventory ----------------
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

# ---------------- ARM (optional, read-only) ----------------
def validate_move_resources(source_sub: str, rg: str, resource_ids: List[str], target_rg_id: str) -> Dict[str,Any]:
    body = json.dumps({"resources": resource_ids, "targetResourceGroup": target_rg_id})
    code, out, err = az(["az","resource","invoke-action","--action","validateMoveResources",
                         "--ids", f"/subscriptions/{source_sub}/resourceGroups/{rg}",
                         "--request-body", body], check=False)
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

def table_status_for_type(full_type: Optional[str], top_type: Optional[str], support: Dict[str, Tuple[Optional[bool], str]]):
    """
    מחזיר: (is_supported: True/False/None, note, key_hit)
    """
    if full_type and full_type in support:
        return support[full_type][0], support[full_type][1], full_type
    if top_type and top_type in support:
        return support[top_type][0], support[top_type][1], top_type
    return None, "", (full_type or top_type or "")

# ---------------- Main ----------------
def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    ensure_login()

    # Load support table (CSV from your repo)
    support_map = load_move_support_map()
    logging.info(f"Loaded {len(support_map)} resource-type rows into support map.")

    # Output filenames
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_discovery = f"azure_env_discovery_{ts}.csv"
    out_reasons   = f"non_transferable_reasons_{ts}.csv"
    out_blockers  = f"blockers_details_{ts}.csv"
    out_allres    = f"resources_support_matrix_{ts}.csv"

    # CSV headers
    headers_discovery = ["Subscription ID","Sub. Type","Sub. Owner","Transferable (Internal)"]
    headers_reasons   = ["Subscription ID","Sub. Type","ReasonCode","Why","DocRef"]
    headers_blockers  = ["SubscriptionId","ResourceGroup","ResourceId","ResourceType","IsChild","ParentId","ParentType","BlockerCategory","Why","DocRef","TableNote","ArmMessage"]
    headers_allres    = ["SubscriptionId","ResourceGroup","ResourceId","ResourceType","IsChild","ParentId","ParentType","TableSupport","TableNote","ArmMessage"]

    # Stage 0: discovery of subscriptions
    subs = az_json(["az","account","list","--all","-o","json"], [])
    billing_accounts = az_json(["az","billing","account","list","-o","json"], [])
    overall_agreement = ""
    try: overall_agreement = (billing_accounts[0].get("agreementType") or "")
    except Exception: pass

    rows_discovery=[]; rows_reasons=[]
    target_subs: List[str] = []

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
        target_subs.append(sub_id)

        if transferable == "No":
            code, why, doc = reason_for_non_transferable(offer, state, auth_src)
            rows_reasons.append([sub_id, offer, code, why, doc])

    # write discovery/reasons
    with open(out_discovery,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(headers_discovery); w.writerows(rows_discovery)
    with open(out_reasons,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(headers_reasons); w.writerows(rows_reasons)
    print(f"✅ Discovery CSV: {out_discovery}")
    print(f"✅ Reasons   CSV: {out_reasons}")

    # Stage 1: enumerate ALL resources (Pre-scan per subscription)
    work: List[Tuple[str,str,List[str]]] = []  # (sub, rg, [ids])
    total_to_scan = 0
    total_rgs = 0

    logging.info("──── Pre-scan: counting resource groups and resources per subscription ────")
    for sub_id in target_subs:
        rgs = list_rgs(sub_id)
        grouped = list_resources_by_rg(sub_id)
        rg_count = len(grouped)
        res_count = sum(len(v) for v in grouped.values())
        total_rgs += rg_count
        total_to_scan += res_count
        if rg_count == 0:
            logging.info(f"[Pre-scan] {sub_id}: 0 RGs, 0 resources (skipping).")
            continue
        logging.info(f"[Pre-scan] {sub_id}: {rg_count} RGs, {res_count} resources.")
        for rg, ids in grouped.items():
            if not ids: 
                continue
            work.append((sub_id, rg, ids))

    logging.info(f"Pre-scan TOTAL: {total_rgs} RGs, {total_to_scan} resources across {len(target_subs)} subscriptions.")

    # Stage 2: optional ARM validate per RG (read-only notes)
    arm_rg_errors: Dict[Tuple[str,str], Tuple[str,str,str]] = {}  # (sub,rg) -> (Cat,Why,DocRef)
    arm_rg_msg:    Dict[Tuple[str,str], str] = {}

    if RUN_ARM_VALIDATE and work:
        logging.info("ARM validateMoveResources is ENABLED (RUN_ARM_VALIDATE=1). Collecting RG-level errors…")
        for (sub_id, rg, ids) in work:
            target_rg_id = f"/subscriptions/{sub_id}/resourceGroups/{rg}"  # self-target; המטרה לקבל הודעה כללית אם קיימת
            result = validate_move_resources(sub_id, rg, ids, target_rg_id)
            if isinstance(result, dict) and "error" in result:
                cat, why, doc = arm_error_to_tuple(result["error"])
                arm_rg_errors[(sub_id,rg)] = (cat, why, doc)
                arm_rg_msg[(sub_id,rg)] = _shorten(json.dumps(result["error"], ensure_ascii=False))
            else:
                arm_rg_msg[(sub_id,rg)] = ""
        logging.info("Finished ARM validation pre-pass.")

    # Stage 3: process resources (per resource logging)
    rows_blockers: List[List[str]] = []
    rows_all: List[List[str]] = []

    scanned = 0
    total_blockers = 0

    for (sub_id, src_rg, ids) in work:
        arm_cat, arm_why, arm_doc = arm_rg_errors.get((sub_id,src_rg), ("","",""))
        arm_blob = arm_rg_msg.get((sub_id,src_rg), "")
        for rid in ids:
            is_child, top_t, full_t, parent_id, parent_t = parse_types(rid)
            t_ok, t_note, _tkey = table_status_for_type(full_t, top_t, support_map)

            # Map to printable support
            if t_ok is True:
                table_support = "Yes"
            elif t_ok is False:
                table_support = "No"
            else:
                table_support = "Not in table"

            # ----- לוגינג פר ריסורס -----
            scanned += 1
            pct = (scanned / total_to_scan * 100.0) if total_to_scan else 100.0
            logging.info(f"Resource {scanned}/{total_to_scan} ({pct:.1f}%): {rid}")

            # All resources row (תמיד)
            rows_all.append([
                sub_id, src_rg, rid,
                (full_t or top_t or ""),
                "Yes" if is_child else "No",
                parent_id or "",
                parent_t or "",
                table_support,
                t_note,
                arm_blob
            ])

            # Blockers: No + Not in table
            if table_support == "No":
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
            elif table_support == "Not in table":
                rows_blockers.append([
                    sub_id, src_rg, rid,
                    (full_t or top_t or ""),
                    "Yes" if is_child else "No",
                    parent_id or "",
                    parent_t or "",
                    "NotInTable",
                    "Not in table (subscription column) – review manually.",
                    "move-support",
                    t_note,
                    arm_blob
                ])
                total_blockers += 1
            elif INCLUDE_ARM_BLOCKERS and arm_cat:
                rows_blockers.append([
                    sub_id, src_rg, rid,
                    (full_t or top_t or ""),
                    "Yes" if is_child else "No",
                    parent_id or "",
                    parent_t or "",
                    arm_cat,
                    arm_why,
                    arm_doc or "ARM",
                    t_note,
                    arm_blob
                ])
                total_blockers += 1

    # כתיבת הקבצים
    with open(out_allres,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(headers_allres); w.writerows(rows_all)

    if rows_blockers:
        with open(out_blockers,"w",newline="",encoding="utf-8") as f:
            w=csv.writer(f); w.writerow(headers_blockers); w.writerows(rows_blockers)
    else:
        with open(out_blockers,"w",newline="",encoding="utf-8") as f:
            w=csv.writer(f); w.writerow(headers_blockers)

    # סיכום למסך
    print("")
    print("──────── Summary ────────")
    print(f"Total subscriptions     : {len(target_subs)}")
    print(f"Total resource groups   : {total_rgs}")
    print(f"Total resources scanned : {total_to_scan}")
    print(f"Total blockers (table)  : {total_blockers}"
          f"{'  (+ ARM included)' if INCLUDE_ARM_BLOCKERS else ''}")
    print("")
    print(f"📄 Discovery CSV        : {out_discovery}")
    print(f"📄 Reasons CSV          : {out_reasons}")
    print(f"📄 Blockers CSV         : {out_blockers}")
    print(f"📄 All-resources CSV    : {out_allres}")
    print("─────────────────────────")

if __name__ == "__main__":
    main()
