#!/usr/bin/env python3
"""
Mine CPEs from the tiiuae/cpedict CSV and match them to fingerprints.
Also validates PURLs and suggests corrections.

Usage:
    python3 mine_cpes.py [--update-enrichment]
"""

import csv
import json
import re
import sys
import urllib.request
from collections import defaultdict

CPE_CSV_URL = "https://raw.githubusercontent.com/tiiuae/cpedict/main/data/cpes.csv"
CPE_CSV_LOCAL = "/tmp/cpes.csv"
FINGERPRINTS_FILE = "../../fingerprints_data.json"
ENRICHMENT_FILE = "enrichment.json"

# ── Packages that are genuinely distributed via the stated registry
# (libraries / frameworks / CMS / tools you install with a package manager).
# Server applications (GitLab, Grafana, Jenkins-server, …) should NOT get
# pkg:npm / pkg:gem / pkg:pypi PURLs – those resolve to unrelated client libs.
#
# Key = tech name in fingerprints_data.json
# Value = correct PURL (or None to explicitly remove a wrong PURL)
PURL_CORRECTIONS = {
    # ── Wrong: pkg:gem/gitlab is the Ruby REST *client*, not GitLab itself
    "GitLab":                  "pkg:docker/gitlab/gitlab-ce",
    # ── Wrong: pkg:npm/@grafana/data is the frontend component lib
    "Grafana":                 "pkg:docker/grafana/grafana",
    # ── Wrong: pkg:npm/kibana doesn't exist as a stand-alone installable pkg
    "Kibana":                  "pkg:docker/elastic/kibana",
    # ── Wrong: pkg:npm/elasticsearch is a JS client, not the server
    "Elasticsearch":           "pkg:docker/elasticsearch/elasticsearch",
    # ── Wrong: pkg:generic/redis – there IS a pkg:pypi/redis (client) but not the server
    "Redis":                   "pkg:docker/redis/redis",
    # ── Wrong: pkg:generic/nginx
    "Nginx":                   "pkg:docker/nginx/nginx",
    # ── Wrong: pkg:generic/apache-httpd
    "Apache HTTP Server":      "pkg:docker/httpd/httpd",
    # ── Wrong: pkg:generic/postgresql
    "PostgreSQL":              "pkg:docker/postgres/postgres",
    # ── Wrong: pkg:generic/node
    "Node.js":                 "pkg:docker/node/node",
    # ── Wrong: pkg:generic/php
    "PHP":                     "pkg:docker/php/php",
    # ── Wrong: pkg:generic/bun  (bun is an npm-compatible package manager itself)
    "Bun":                     None,
    # ── Wrong: pkg:generic/deno
    "Deno":                    None,
    # ── Wrong: pkg:npm/ghost – there is no installable npm pkg called 'ghost'
    # The correct one would be pkg:npm/@ghost/ghost or pkg:docker/ghost/ghost
    "Ghost":                   "pkg:docker/ghost/ghost",
    # ── Wrong: pkg:golang/github.com/kubernetes/dashboard (that's the Go module, fine to keep)
    # ── Wrong: pkg:npm/cloudflare – that's an API client
    "Cloudflare":              None,
    # ── pkg:npm/react is correct ✓
    # ── pkg:npm/vue is correct ✓
    # ── pkg:npm/next is correct ✓
    # ── pkg:pypi/django is correct ✓
}

# ── Technologies that are server software and should NOT get a PURL unless
# they have a genuine official package (Docker image counts).
SERVER_SOFTWARE_NO_PURL = {
    "Varnish", "HAProxy", "Traefik", "Caddy", "OpenResty", "Envoy",
    "Apache Kafka", "RabbitMQ", "ZooKeeper", "Cassandra", "CouchDB",
    "Neo4j", "MariaDB", "MySQL", "MongoDB",
    "Jenkins", "SonarQube", "Metabase", "Redash",
    "Prometheus", "InfluxDB", "Grafana",
    "Apache Solr", "Apache Tomcat", "Apache Traffic Server",
    "Keycloak", "Okta",
}


def normalize(s: str) -> str:
    """Lowercase, remove punctuation/spaces for fuzzy matching."""
    return re.sub(r"[^a-z0-9]", "", s.lower())


def download_cpe_csv():
    print(f"Downloading CPE dictionary from {CPE_CSV_URL}…", file=sys.stderr)
    urllib.request.urlretrieve(CPE_CSV_URL, CPE_CSV_LOCAL)
    print(f"Saved to {CPE_CSV_LOCAL}", file=sys.stderr)


def load_cpe_dict() -> tuple[dict, dict]:
    """
    Returns:
        by_product  – {norm_product: [(vendor, product), …]}
        by_vendor   – {norm_vendor: [(vendor, product), …]}
    """
    by_product: dict[str, list] = defaultdict(list)
    by_vendor:  dict[str, list] = defaultdict(list)
    try:
        f = open(CPE_CSV_LOCAL, newline="", encoding="utf-8")
    except FileNotFoundError:
        download_cpe_csv()
        f = open(CPE_CSV_LOCAL, newline="", encoding="utf-8")

    with f:
        reader = csv.DictReader(f)
        for row in reader:
            vendor  = row["vendor"].strip()
            product = row["product"].strip()
            key_v = normalize(vendor)
            key_p = normalize(product)
            pair = (vendor, product)
            if pair not in by_product[key_p]:
                by_product[key_p].append(pair)
            if pair not in by_vendor[key_v]:
                by_vendor[key_v].append(pair)

    print(
        f"Loaded {sum(len(v) for v in by_product.values())} CPE pairs "
        f"({len(by_product)} unique products)",
        file=sys.stderr,
    )
    return dict(by_product), dict(by_vendor)


def find_cpe_candidates(
    tech_name: str,
    website: str,
    by_product: dict,
    by_vendor: dict,
    max_results: int = 5,
) -> list[tuple[str, str, str]]:
    """
    Returns list of (vendor, product, reason) tuples, best matches first.
    """
    results = {}

    def add(vendor, product, reason, score):
        key = (vendor, product)
        if key not in results or results[key][1] < score:
            results[key] = (reason, score)

    norm_name = normalize(tech_name)

    # ── 1. Exact product match
    if norm_name in by_product:
        for v, p in by_product[norm_name]:
            add(v, p, "exact_product", 100)

    # ── 2. Exact vendor match (if tech name looks like a company)
    if norm_name in by_vendor:
        for v, p in by_vendor[norm_name]:
            add(v, p, "exact_vendor", 90)

    # ── 3. Strip common suffixes and try again
    stripped = re.sub(
        r"(cms|blog|wiki|server|framework|engine|platform|"
        r"suite|system|library|sdk|api|client|open.?source|"
        r"community|enterprise|pro|plus|lite|free|core)$",
        "",
        norm_name,
    ).strip()
    if stripped and stripped != norm_name:
        if stripped in by_product:
            for v, p in by_product[stripped]:
                add(v, p, "stripped_suffix", 80)
        if stripped in by_vendor:
            for v, p in by_vendor[stripped]:
                add(v, p, "stripped_vendor", 75)

    # ── 4. Product contains the tech name as a substring
    for key, pairs in by_product.items():
        if len(norm_name) >= 4 and norm_name in key and key != norm_name:
            for v, p in pairs:
                add(v, p, "product_contains", 60)
        if len(norm_name) >= 4 and key in norm_name and key != norm_name:
            for v, p in pairs:
                add(v, p, "name_contains_product", 55)

    # ── 5. Vendor domain heuristic from website
    if website:
        domain = re.sub(r"https?://(?:www\.)?([^/]+).*", r"\1", website)
        domain_norm = normalize(domain.split(".")[0])  # first label
        if len(domain_norm) >= 3 and domain_norm in by_vendor:
            for v, p in by_vendor[domain_norm]:
                add(v, p, "website_vendor", 70)
        if len(domain_norm) >= 3 and domain_norm in by_product:
            for v, p in by_product[domain_norm]:
                add(v, p, "website_product", 65)

    # Sort by score desc, then alphabetically
    sorted_results = sorted(
        [(v, p, reason, score) for (v, p), (reason, score) in results.items()],
        key=lambda x: (-x[3], x[0], x[1]),
    )
    return [(v, p, reason) for v, p, reason, _ in sorted_results[:max_results]]


def build_cpe_string(vendor: str, product: str) -> str:
    return f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"


def main():
    update_enrichment = "--update-enrichment" in sys.argv

    # Load fingerprints
    with open(FINGERPRINTS_FILE) as f:
        data = json.load(f)
    apps = data["apps"]

    # Load current enrichment
    with open(ENRICHMENT_FILE) as f:
        enrichment: dict = json.load(f)

    # Load CPE dict
    by_product, by_vendor = load_cpe_dict()

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 1 – Find missing CPEs
    # ─────────────────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("PHASE 1 – CPE candidates for technologies WITHOUT a CPE")
    print("=" * 70)

    new_cpes: dict[str, str] = {}      # tech_name → confirmed CPE string
    suggestions: list[tuple] = []       # (tech_name, candidates)

    no_cpe_techs = [
        (name, app)
        for name, app in sorted(apps.items())
        if not app.get("cpe") and not enrichment.get(name, {}).get("cpe")
    ]
    print(f"{len(no_cpe_techs)} technologies without a CPE\n")

    for tech_name, app in no_cpe_techs:
        website = app.get("website", "")
        candidates = find_cpe_candidates(
            tech_name, website, by_product, by_vendor, max_results=3
        )
        if candidates:
            suggestions.append((tech_name, candidates))

    print(f"Found CPE candidates for {len(suggestions)} technologies:\n")
    for tech_name, cands in suggestions[:200]:   # print first 200
        print(f"  {tech_name!r:40s}  {app.get('website','')}")
        for v, p, reason in cands:
            cpe = build_cpe_string(v, p)
            print(f"    [{reason:28s}]  {cpe}")
        print()

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 2 – Validate existing CPEs against the dictionary
    # ─────────────────────────────────────────────────────────────────────────
    print("=" * 70)
    print("PHASE 2 – Validate existing CPEs in fingerprints + enrichment")
    print("=" * 70)

    all_cpe_pairs = {
        (vendor, product)
        for vendor, products in by_product.items()
        for vendor, product in products
    }
    # rebuild as a flat set of "vendor:product" strings for fast lookup
    cpe_flat = {f"{v}:{p}" for v, p in all_cpe_pairs}

    def cpe_in_dict(cpe_str: str) -> bool:
        m = re.match(r"cpe:2\.3:[aoh]:([^:]+):([^:]+):", cpe_str)
        if not m:
            return False
        return f"{m.group(1)}:{m.group(2)}" in cpe_flat

    invalid = []
    for tech_name, app in sorted(apps.items()):
        cpe = app.get("cpe") or enrichment.get(tech_name, {}).get("cpe", "")
        if cpe and not cpe_in_dict(cpe):
            invalid.append((tech_name, cpe))

    if invalid:
        print(f"\n{len(invalid)} CPEs NOT found in cpedict (may need correction):\n")
        for name, cpe in invalid[:100]:
            print(f"  {name!r:40s}  {cpe}")
    else:
        print("\nAll existing CPEs found in cpedict ✓")

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 3 – PURL audit
    # ─────────────────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("PHASE 3 – PURL audit")
    print("=" * 70)

    print("\nCorrections to apply (from PURL_CORRECTIONS dict):")
    for name, new_purl in PURL_CORRECTIONS.items():
        old_purl = apps.get(name, {}).get("purl") or enrichment.get(name, {}).get("purl", "")
        if old_purl:
            if new_purl is None:
                print(f"  REMOVE  {name!r:40s}  {old_purl!r}")
            elif old_purl != new_purl:
                print(f"  CHANGE  {name!r:40s}  {old_purl!r}")
                print(f"          {'':40s}→ {new_purl!r}")
        elif new_purl:
            print(f"  ADD     {name!r:40s}  → {new_purl!r}")

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 4 – Optionally build auto-confirmed new_cpes dict
    # Strategy: only auto-confirm if there is EXACTLY ONE candidate from
    # 'exact_product' or 'exact_vendor' reason – avoids false positives.
    # ─────────────────────────────────────────────────────────────────────────
    auto_confirmed: dict[str, str] = {}
    for tech_name, cands in suggestions:
        exact = [(v, p) for v, p, r in cands if r in ("exact_product", "exact_vendor")]
        if len(exact) == 1:
            v, p = exact[0]
            auto_confirmed[tech_name] = build_cpe_string(v, p)

    print(f"\n{len(auto_confirmed)} CPEs auto-confirmed (single exact match):")
    for name, cpe in sorted(auto_confirmed.items()):
        print(f"  {name!r:40s}  {cpe}")

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 5 – Write updated enrichment.json
    # ─────────────────────────────────────────────────────────────────────────
    if update_enrichment:
        print("\n" + "=" * 70)
        print("PHASE 5 – Writing updated enrichment.json")
        print("=" * 70)

        changed = 0

        # Apply auto-confirmed CPEs
        for name, cpe in auto_confirmed.items():
            if name not in enrichment:
                enrichment[name] = {}
            if not enrichment[name].get("cpe"):
                enrichment[name]["cpe"] = cpe
                changed += 1
                print(f"  CPE added  {name!r}  {cpe}")

        # Apply PURL corrections
        for name, new_purl in PURL_CORRECTIONS.items():
            if name not in enrichment:
                enrichment[name] = {}
            if new_purl is None:
                if enrichment[name].get("purl"):
                    del enrichment[name]["purl"]
                    changed += 1
                    print(f"  PURL removed  {name!r}")
            else:
                if enrichment[name].get("purl") != new_purl:
                    enrichment[name]["purl"] = new_purl
                    changed += 1
                    print(f"  PURL updated  {name!r}  {new_purl!r}")

        # Clean up empty entries
        enrichment = {k: v for k, v in enrichment.items() if v}

        # Sort keys
        enrichment = dict(sorted(enrichment.items()))

        with open(ENRICHMENT_FILE, "w") as f:
            json.dump(enrichment, f, indent=4)

        print(f"\nDone – {changed} changes written to {ENRICHMENT_FILE}")
    else:
        print(
            "\nRun with --update-enrichment to apply auto-confirmed CPEs "
            "and PURL corrections to enrichment.json"
        )


if __name__ == "__main__":
    main()
