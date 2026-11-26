"""Before/after comparison of all scanner outputs -> scans/comparison.json + printed summary.

Usage: py -I tools/compare_scans.py   (run from repo root)
"""

import collections
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
S = ROOT / "scans"
SCOPE = ("authbypass", "hijacksession", "spoofcookie", "jwt", "passwordreset", "insecurelogin",
         "securepasswords")


def norm(p):
    return p.replace("\\", "/")


def in_scope(path):
    p = norm(path)
    return any(f"/lessons/{s}/" in p or f"lessons.{s}." in p for s in SCOPE)


def semgrep(name):
    d = json.load(open(S / name, encoding="utf-8"))
    return [(r["check_id"].split(".")[-1], norm(r["path"]).split("/lessons/")[-1], r["start"]["line"])
            for r in d["results"]]


def spotbugs(phase):
    xml = (S / phase / "spotbugs" / "spotbugsXml.xml").read_text(encoding="utf-8")
    out = []
    for m in re.finditer(r"<BugInstance ([^>]*)>(.*?)</BugInstance>", xml, re.S):
        attrs = dict(re.findall(r"(\w+)='([^']*)'", m.group(1)))
        cls = re.search(r"<Class classname='([^']+)'", m.group(2))
        out.append((attrs.get("type"), attrs.get("category"), cls.group(1) if cls else ""))
    return out


def secrets(phase):
    d = json.load(open(S / phase / "detect-secrets.json", encoding="utf-8"))["results"]
    return [(s["type"], norm(f), s["line_number"]) for f, v in d.items() for s in v]


def sca(phase):
    return json.load(open(S / phase / "sca-osv.json", encoding="utf-8"))["findings"]


res = {}
# Semgrep (registry rules) and custom rules
for name in ("semgrep.json", "semgrep-rgr.json"):
    b, a = semgrep("before/" + name), semgrep("after/" + name)
    res[name] = {"before": len(b), "after": len(a),
                 "before_by_rule": collections.Counter(r[0] for r in b),
                 "after_by_rule": collections.Counter(r[0] for r in a),
                 "after_items": a}

# SpotBugs: security category, in-scope classes
for phase in ("before", "after"):
    items = spotbugs(phase)
    sec = [i for i in items if i[1] == "SECURITY"]
    scoped = [i for i in sec if in_scope(i[2])]
    res[f"spotbugs_{phase}"] = {
        "total": len(items), "security": len(sec), "security_in_scope": len(scoped),
        "in_scope_by_type": collections.Counter(i[0] for i in scoped),
        "in_scope_items": sorted(set((i[0], i[2].split("lessons.")[-1]) for i in scoped)),
    }

# Secrets
for phase in ("before", "after"):
    items = secrets(phase)
    main = [i for i in items if "/src/main/" in i[1]]
    scoped = [i for i in main if in_scope(i[1])]
    res[f"secrets_{phase}"] = {"total": len(items), "main": len(main), "in_scope": scoped}

# SCA
for phase in ("before", "after"):
    f = sca(phase)
    res[f"sca_{phase}"] = {
        "total": len(f),
        "by_sev": collections.Counter(r["severity"] for r in f),
        "by_comp": collections.Counter(r["component"] for r in f),
    }

json.dump(res, open(S / "comparison.json", "w", encoding="utf-8"), indent=2, default=list,
          ensure_ascii=False)

print("SEMGREP registry:", res["semgrep.json"]["before"], "->", res["semgrep.json"]["after"])
print("SEMGREP custom:", res["semgrep-rgr.json"]["before"], "->", res["semgrep-rgr.json"]["after"])
for k in sorted(set(res["semgrep-rgr.json"]["before_by_rule"]) | set(res["semgrep-rgr.json"]["after_by_rule"])):
    print("   ", k, res["semgrep-rgr.json"]["before_by_rule"].get(k, 0), "->",
          res["semgrep-rgr.json"]["after_by_rule"].get(k, 0))
print("    remaining:", res["semgrep-rgr.json"]["after_items"])
for p in ("before", "after"):
    r = res[f"spotbugs_{p}"]
    print(f"SPOTBUGS {p}: total={r['total']} security={r['security']} in_scope={r['security_in_scope']}",
          dict(r["in_scope_by_type"]))
print("SPOTBUGS in-scope after:", res["spotbugs_after"]["in_scope_items"])
for p in ("before", "after"):
    r = res[f"secrets_{p}"]
    print(f"SECRETS {p}: total={r['total']} main={r['main']} in_scope={r['in_scope']}")
for p in ("before", "after"):
    r = res[f"sca_{p}"]
    print(f"SCA {p}: total={r['total']} {dict(r['by_sev'])}")
bc, ac = res["sca_before"]["by_comp"], res["sca_after"]["by_comp"]
for c in sorted(set(bc) | set(ac)):
    if bc.get(c, 0) != ac.get(c, 0):
        print("   SCA delta", c, bc.get(c, 0), "->", ac.get(c, 0))
