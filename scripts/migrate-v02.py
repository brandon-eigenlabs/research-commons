#!/usr/bin/env python3
"""migrate-v02 — one-shot: stamp v0.1 manifests with schema + verification tier.

Idempotent. Adds to every manifest lacking them:
  "schema": "rc.v1"
  "verification": {"tier": …, "criteria"?: …}

Tier assignment rules:
  * has provenance.workflow            → T0  (it was literally re-derived)
  * type dataset, no workflow          → T3  (acquired from the world, attested)
  * type workflow/skill                → untiered (methods are pinned by content
                                         hash, not evidence — tiering them would
                                         poison the chain grade of their consumers)
  * everything else (report, wiki,
    bibliography)                      → unverified
Existing `verification` blocks are never overwritten (pass --force to redo).

Usage: scripts/migrate-v02.py [--dry-run] [--force] [--root DIR]
"""
import argparse, json, os, sys

DEFAULT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = "rc.v1"

METHOD_TYPES = {"workflow", "skill"}

CRITERIA = {
    "T3": "self-attested one-time capture; raw extract published as acquired",
}


def classify(m):
    prov = m.get("provenance") or {}
    if prov.get("workflow"):
        return "T0", None
    if m.get("type") in METHOD_TYPES:
        return None, None
    if m.get("type") == "dataset":
        return "T3", CRITERIA["T3"]
    return "unverified", None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.environ.get("COMMONS_ROOT", DEFAULT_ROOT))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--force", action="store_true", help="re-stamp manifests that already have verification")
    a = ap.parse_args()

    art = os.path.join(a.root, "registry", "artifacts")
    if not os.path.isdir(art): sys.exit("error: no registry at %s" % a.root)

    changed = skipped = 0
    for fn in sorted(os.listdir(art)):
        if not fn.endswith(".json"): continue
        p = os.path.join(art, fn)
        with open(p) as f: m = json.load(f)
        tier, criteria = classify(m)
        need_schema = m.get("schema") != SCHEMA
        need_tier = (a.force or not (m.get("verification") or {}).get("tier")) and tier is not None
        if not (need_schema or need_tier):
            skipped += 1
            continue
        if need_schema: m["schema"] = SCHEMA
        if need_tier:
            v = {"tier": tier}
            if criteria: v["criteria"] = criteria
            m["verification"] = v
        print("%s %-14s → schema=%s tier=%s%s"
              % ("[dry-run]" if a.dry_run else "stamped ", m["id"], SCHEMA,
                 (m.get("verification") or {}).get("tier", "— (method, untiered)"),
                 "  (%s)" % criteria if criteria else ""))
        if not a.dry_run:
            tmp = p + ".tmp"
            with open(tmp, "w") as f: json.dump(m, f, indent=2, sort_keys=True)
            os.replace(tmp, p)
        changed += 1

    print("migrate-v02: %d stamped, %d already current%s"
          % (changed, skipped, " (dry run — nothing written)" if a.dry_run else ""))
    if changed and not a.dry_run:
        print("next: bin/commons reindex")


if __name__ == "__main__":
    main()
