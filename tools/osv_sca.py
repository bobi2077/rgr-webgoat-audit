"""SCA: match CycloneDX SBOM components (Maven purls) against OSV.dev.

Usage: py -I tools/osv_sca.py <sbom.json> <out-prefix>
Writes <out-prefix>.json (raw matches) and <out-prefix>.md (summary table).
Only public package coordinates (purl) are sent to api.osv.dev.
"""

import json
import sys
import urllib.request

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"


def post(url, payload):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "sca-script"},
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "sca-script"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def severity_of(v):
    sev = (v.get("database_specific") or {}).get("severity")
    cvss = next((s["score"] for s in v.get("severity", []) if s["type"].startswith("CVSS")), "")
    return sev or "UNKNOWN", cvss


def main(sbom_path, out_prefix):
    sbom = json.load(open(sbom_path, encoding="utf-8"))
    comps = [c for c in sbom.get("components", []) if c.get("purl", "").startswith("pkg:maven/")]
    purls = [c["purl"].split("?")[0] for c in comps]
    results = []
    for i in range(0, len(purls), 500):
        chunk = purls[i : i + 500]
        resp = post(OSV_BATCH, {"queries": [{"package": {"purl": p}} for p in chunk]})
        for p, r in zip(chunk, resp["results"]):
            for v in r.get("vulns", []):
                results.append((p, v["id"]))
    rows, cache = [], {}
    for purl, vid in results:
        v = cache.get(vid) or get(OSV_VULN + vid)
        cache[vid] = v
        sev, cvss = severity_of(v)
        aliases = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
        cwes = (v.get("database_specific") or {}).get("cwe_ids", [])
        fixed = sorted(
            {
                e["fixed"]
                for a in v.get("affected", [])
                for rg in a.get("ranges", [])
                for e in rg.get("events", [])
                if "fixed" in e
            }
        )
        rows.append(
            {
                "component": purl.replace("pkg:maven/", ""),
                "id": vid,
                "cve": ", ".join(aliases),
                "cwe": ", ".join(cwes),
                "severity": sev,
                "cvss_vector": cvss,
                "fixed_in": ", ".join(fixed),
                "summary": (v.get("summary") or "")[:140],
            }
        )
    order = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    rows.sort(key=lambda r: (order.get(r["severity"], 5), r["component"]))
    json.dump(
        {"components_scanned": len(purls), "findings": rows},
        open(out_prefix + ".json", "w", encoding="utf-8"),
        indent=2,
    )
    with open(out_prefix + ".md", "w", encoding="utf-8") as f:
        f.write(f"Components scanned: {len(purls)}; vulnerable matches: {len(rows)}\n\n")
        f.write("| Component | ID | CVE | Severity | Fixed in | Summary |\n|---|---|---|---|---|---|\n")
        for r in rows:
            f.write(
                f"| {r['component']} | {r['id']} | {r['cve']} | {r['severity']} | "
                f"{r['fixed_in']} | {r['summary'].replace('|', '/')} |\n"
            )
    print(f"components={len(purls)} findings={len(rows)}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
