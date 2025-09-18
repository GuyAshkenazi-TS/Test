#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Stage 2 (table-only): Per-subscription resource scan (read-only)
Outputs (file names כוללים את ה-Subscription לנוחות):
  1) blockers_details_<SUB>_<ts>.csv           -> רק No + Not in table (לפי הטבלה)
  2) resources_support_matrix_<SUB>_<ts>.csv   -> כל הריסורסים עם Yes / No / Not in table

מאפיינים:
- שימוש ב-CSV מהגיטהאב שלך כטבלת תמיכה (עמודת Subscription = מקור האמת).
- "Not in table" במקום "Unknown".
- לוגינג: Pre-scan (כמה RG/Resources), Progress ריסורס-ריסורס, Summary עם זמן ריצה ושמות הקבצים.
"""

import os, subprocess, json, csv, io, re, urllib.request, logging, time, argparse
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

# ---------- env ----------
os.environ.setdefault("AZURE_CORE_NO_COLOR", "1")
os.environ.setdefault("AZURE_EXTENSION_USE_DYNAMIC_INSTALL", "yes_without_prompt")

# ---------- shell helpers ----------
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
TYPE_ALIASES: Dict[str,str] = {}
def normalize_type(s: str) -> str:
    if not s: return ""
    t = s.strip().lower()
    t = re.sub(r"\s+", "", t)
    t = re.sub(r"/+", "/", t)
    return TYPE_ALIASES.get(t, t)

def _pick_col(row, *candidates):
    if not row: return None
    keys = {k.lower(): k for k in row.keys()}
    for c in candidates:
        k = keys.get(c.lower())
        if k: return k
    return None

# ---------- support table ----------
# מחזיר: { 'microsoft.x/type[/child]' : (True/False/None, note) }
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

# ---------- inventory ----------
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
    grouped: Dict[str, List[str]] = {}
    for r in resources:
        if r.get("type") in non_movable:
            continue
        rg=r.get("rg"); rid=r.get("id")
        if rg and rid: grouped.setdefault(rg, []).append(rid)
    return grouped

# ---------- parse/classify ----------
def parse_types(resource_id: str):
    """
    Returns: is_child, top_type, full_type, parent_id, parent_type
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
    if full_type and full_type in support:
        return support[full_type][0], support[full_type][1], full_type
    if top_type and top_type in support:
        return support[top_type][0], support[top_type][1], top_type
    return None, "", (full_type or top_type or "")

# ---------- main ----------
def main():
    t0 = time.perf_counter()

    parser = argparse.ArgumentParser(description="Per-subscription resource assessor (table-only, read-only)")
    parser.add_argument("--subscription", required=True, help="Subscription ID to scan")
    parser.add_argument("--move-support-url", default="https://raw.githubusercontent.com/GuyAshkenazi-TS/azure-env-assessment/refs/heads/main/move-support-resources-local.csv")
    args = parser.parse_args()

    sub_id = args.subscription
    MOVE_SUPPORT_URL = args.move_support_url

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    logging.info(f"Stage-2 (table-only) starting for subscription: {sub_id}")
    logging.info(f"Support table: {MOVE_SUPPORT_URL}")

    ensure_login()

    # load table
    support_map = load_move_support_map_from_url(MOVE_SUPPORT_URL)
    logging.info(f"Loaded {len(support_map)} type rows from support table.")

    # filenames (לכל קובץ מצרפים את ה-Subscription)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_blockers  = f"blockers_details_{sub_id}_{ts}.csv"
    out_allres    = f"resources_support_matrix_{sub_id}_{ts}.csv"

    # headers
    headers_blockers  = ["SubscriptionId","ResourceGroup","ResourceId","ResourceType","IsChild","ParentId","ParentType","BlockerCategory","Why","DocRef","TableNote"]
    headers_allres    = ["SubscriptionId","ResourceGroup","ResourceId","ResourceType","IsChild","ParentId","ParentType","TableSupport","TableNote"]

    # Pre-scan inventory
    grouped = list_resources_by_rg(sub_id)
    rg_count = len(grouped)
    res_count = sum(len(v) for v in grouped.values())
    logging.info("")
    logging.info("========== PRE-SCAN ==========")
    logging.info(f"Subscription: {sub_id}")
    logging.info(f"Resource Groups: {rg_count}")
    logging.info(f"Resources total: {res_count}")
    logging.info("==============================")
    logging.info("")

    if res_count == 0:
        # create empty outputs with headers
        with open(out_blockers,"w",newline="",encoding="utf-8") as f:
            csv.writer(f).writerow(headers_blockers)
        with open(out_allres,"w",newline="",encoding="utf-8") as f:
            csv.writer(f).writerow(headers_allres)
        logging.info("No resources found. Exiting.")
        # Summary
        elapsed = time.perf_counter() - t0
        logging.info("")
        logging.info("========== SUMMARY ==========")
        logging.info(f"Processed: 0 resources across {rg_count} RGs")
        logging.info(f"Duration : {elapsed:.1f}s")
        logging.info("Outputs  :")
        logging.info(f"  - {out_blockers}")
        logging.info(f"  - {out_allres}")
        logging.info("=============================")
        print("📄 Files created:")
        print(f" - {out_blockers}")
        print(f" - {out_allres}")
        print(f"⏱️ Total duration: {elapsed:.1f}s")
        return

    # רשימה שטוחה לצורך לוג התקדמות
    flat: List[Tuple[str,str]] = []
    for rg, ids in grouped.items():
        for rid in ids:
            flat.append((rg, rid))

    # פותחים את הקבצים
    f_blockers = open(out_blockers,"w",newline="",encoding="utf-8")
    w_blockers = csv.writer(f_blockers); w_blockers.writerow(headers_blockers)
    f_allres = open(out_allres,"w",newline="",encoding="utf-8")
    w_allres = csv.writer(f_allres); w_allres.writerow(headers_allres)

    # ריצה ריסורס-ריסורס עם לוג התקדמות
    total = len(flat)
    start_loop = time.perf_counter()
    for i, (rg, rid) in enumerate(flat, start=1):
        pct = (i/total)*100.0
        logging.info(f"Progress: {i}/{total} resources processed ({pct:.1f}%) | RG: {rg}")

        is_child, top_type, full_type, parent_id, parent_type = parse_types(rid)
        table_bool, table_note, matched_type = table_status_for_type(full_type, top_type, support_map)

        # מיפוי Yes/No/Not in table
        if table_bool is True:
            table_support = "Yes"
        elif table_bool is False:
            table_support = "No"
        else:
            table_support = "Not in table"

        # All resources
        w_allres.writerow([
            sub_id, rg, rid,
            matched_type,
            "Yes" if is_child else "No",
            parent_id or "",
            parent_type or "",
            table_support,
            table_note
        ])

        # Blockers: רק No או Not in table
        if table_support in ("No","Not in table"):
            w_blockers.writerow([
                sub_id, rg, rid,
                matched_type,
                "Yes" if is_child else "No",
                parent_id or "",
                parent_type or "",
                ("UnsupportedResourceType" if table_support=="No" else "NotInSupportTable"),
                ("Resource type doesn’t support subscription move." if table_support=="No" else "Resource type not listed in move-support table."),
                "move-support",
                table_note
            ])

    f_blockers.close()
    f_allres.close()

    # Summary
    elapsed = time.perf_counter() - t0
    loop_elapsed = time.perf_counter() - start_loop
    logging.info("")
    logging.info("========== SUMMARY ==========")
    logging.info(f"Processed: {total} resources across {rg_count} RGs")
    logging.info(f"Duration : {elapsed:.1f}s (scan loop: {loop_elapsed:.1f}s)")
    logging.info("Outputs  :")
    logging.info(f"  - {out_blockers}")
    logging.info(f"  - {out_allres}")
    logging.info("=============================")

    print("📄 Files created:")
    print(f" - {out_blockers}")
    print(f" - {out_allres}")
    print(f"⏱️ Total duration: {elapsed:.1f}s")

if __name__ == "__main__":
    main()
