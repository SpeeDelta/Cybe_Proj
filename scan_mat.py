import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import requests

# =========================
# CONFIG
# =========================
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NVD_API_KEY = None  # <- optionnel (recommandé si tu fais beaucoup de requêtes)
HTTP_TIMEOUT = 25
RETRY_429_SLEEP = 8
MAX_429_RETRIES = 3

REPORTS_DIR = "reports"

# Limites pour garder un rapport lisible
CPE_RESULTS_PER_COMPONENT = 10     # combien de CPE on récupère depuis /cpes
TOP_CPE_TO_QUERY = 3              # combien de CPE on garde pour aller chercher des CVE
TOP_CVE_TO_SHOW_PER_CPE = 12      # combien de CVE on affiche par CPE
DESC_MAX_LEN = 220


# =========================
# UTILS
# =========================
def slugify(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^\w\-]+", "_", s, flags=re.UNICODE)
    s = re.sub(r"_+", "_", s)
    return s.strip("_") or "unknown"


def build_versioned_report_path(reports_dir: str, source_name: str, kind: str = "hardware") -> Path:
    Path(reports_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = f"{kind}_{slugify(source_name)}_{ts}"
    v = 1
    while True:
        p = Path(reports_dir) / f"{base}_v{v}.txt"
        if not p.exists():
            return p
        v += 1


def clean_description(text: str, max_len: int = DESC_MAX_LEN) -> str:
    if not text:
        return ""
    one_line = " ".join(text.split())
    return one_line[:max_len].rstrip() + ("..." if len(one_line) > max_len else "")


def severity_bucket(cvss_score, cvss_sev: str | None) -> str:
    if cvss_sev:
        s = cvss_sev.upper()
        if s in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            return s
    if cvss_score is None:
        return "UNKNOWN"
    try:
        x = float(cvss_score)
    except Exception:
        return "UNKNOWN"
    if x >= 9.0:
        return "CRITICAL"
    if x >= 7.0:
        return "HIGH"
    if x >= 4.0:
        return "MEDIUM"
    return "LOW"


def safe_float(x):
    try:
        return float(x)
    except Exception:
        return None


# =========================
# INVENTORY
# =========================
def read_inventory_txt(path: str) -> dict:
    inv = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                inv[k.strip().lower()] = v.strip()
            else:
                inv.setdefault("raw_lines", [])
                inv["raw_lines"].append(line)
    return inv


def detect_cpu_vendor(inv: dict) -> str | None:
    cpu = (inv.get("cpu") or "").lower()
    if "intel" in cpu:
        return "intel"
    if "amd" in cpu or "ryzen" in cpu:
        return "amd"
    return None


def arch_cpu_cpe(cpu_vendor: str | None) -> str | None:
    # CPE générique “architecture/famille” (CPU)
    if cpu_vendor == "intel":
        return "cpe:2.3:h:intel:processor:*:*:*:*:*:*:*:*"
    if cpu_vendor == "amd":
        return "cpe:2.3:h:amd:processor:*:*:*:*:*:*:*:*"
    return None


def build_components(inv: dict) -> list[dict]:
    """
    Construit une liste de "composants" à matcher via l'API CPE.
    Chaque composant a:
      - label (BIOS/CPU/NIC/GPU/OS/…)
      - query (texte) pour keywordSearch
    """
    manufacturer = inv.get("manufacturer") or inv.get("vendor") or ""
    model = inv.get("model") or inv.get("product") or ""
    bios_vendor = inv.get("bios vendor") or ""
    bios_version = inv.get("bios version") or inv.get("bios") or ""
    cpu = inv.get("cpu") or ""
    gpu = inv.get("gpu") or inv.get("graphics") or ""
    nic = inv.get("nic") or ""
    os_name = inv.get("os") or inv.get("operating system") or ""

    comps = []

    # BIOS / Machine : souvent difficile sur laptop grand public, mais on tente.
    if manufacturer and model and bios_version:
        comps.append({"label": "BIOS", "query": f"{manufacturer} {model} BIOS {bios_version}"})
    if bios_vendor and bios_version:
        comps.append({"label": "BIOS_VENDOR", "query": f"{bios_vendor} BIOS {bios_version}"})
    if manufacturer and model:
        comps.append({"label": "MACHINE", "query": f"{manufacturer} {model}"})

    # CPU/GPU/NIC/OS
    if cpu:
        comps.append({"label": "CPU", "query": cpu})
    if gpu:
        comps.append({"label": "GPU", "query": gpu})
    if nic:
        comps.append({"label": "NIC", "query": nic})
    if os_name:
        comps.append({"label": "OS", "query": os_name})

    # fallback : premières lignes brutes
    for raw in inv.get("raw_lines", [])[:3]:
        comps.append({"label": "RAW", "query": raw})

    # dédup
    seen = set()
    out = []
    for c in comps:
        key = (c["label"], c["query"].strip().lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


# =========================
# NVD HTTP
# =========================
def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "TP-HW-CPE-NVD/1.0"})
    if NVD_API_KEY:
        s.headers.update({"apiKey": NVD_API_KEY})
    return s


def nvd_get_json(session: requests.Session, url: str) -> dict:
    for _ in range(MAX_429_RETRIES + 1):
        r = session.get(url, timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            return r.json()
        if r.status_code == 429:
            time.sleep(RETRY_429_SLEEP)
            continue
        raise RuntimeError(f"HTTP {r.status_code} for URL: {url}")
    return {}


# =========================
# CPE LOOKUP (Products API)
# =========================
def cpe_search_keyword(session: requests.Session, query: str, results_per_page: int = CPE_RESULTS_PER_COMPONENT) -> list[dict]:
    url = f"{NVD_CPE_API}?keywordSearch={quote(query)}&resultsPerPage={int(results_per_page)}"
    data = nvd_get_json(session, url)

    # NVD renvoie typiquement un tableau "products"
    products = data.get("products") or data.get("result", {}).get("products") or []
    out = []

    for p in products:
        # formats possibles selon la sérialisation: p["cpe"] ou p directement
        cpe_obj = p.get("cpe") if isinstance(p, dict) else None
        if isinstance(cpe_obj, dict):
            cpe_name = cpe_obj.get("cpeName")
            titles = cpe_obj.get("titles") or []
        else:
            cpe_name = p.get("cpeName") if isinstance(p, dict) else None
            titles = p.get("titles") if isinstance(p, dict) else []

        title = ""
        if isinstance(titles, list) and titles:
            # souvent [{lang, title}]
            for t in titles:
                if isinstance(t, dict) and t.get("lang") in ("en", "fr"):
                    title = t.get("title") or ""
                    break
            if not title and isinstance(titles[0], dict):
                title = titles[0].get("title") or ""

        if cpe_name:
            out.append({"cpeName": cpe_name, "title": title})

    # dédup par cpeName
    seen = set()
    uniq = []
    for item in out:
        if item["cpeName"] in seen:
            continue
        seen.add(item["cpeName"])
        uniq.append(item)
    return uniq


# =========================
# CVE LOOKUP (Vulnerability API)
# =========================
def cve_search_by_cpe(session: requests.Session, cpe_name: str, results_per_page: int = 50) -> list[dict]:
    url = f"{NVD_CVE_API}?cpeName={quote(cpe_name, safe=':/')}&resultsPerPage={int(results_per_page)}"
    data = nvd_get_json(session, url)
    return data.get("vulnerabilities", [])


def extract_cve_summary(vuln: dict) -> dict:
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "CVE-????-????")

    desc_en = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc_en = d.get("value", "")
            break

    published = cve.get("published") or ""

    metrics = cve.get("metrics", {})
    score = None
    sev = None

    if metrics.get("cvssMetricV31"):
        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        sev = cvss_data.get("baseSeverity")
    elif metrics.get("cvssMetricV3"):
        cvss_data = metrics["cvssMetricV3"][0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        sev = cvss_data.get("baseSeverity")
    elif metrics.get("cvssMetricV2"):
        cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
        score = cvss_data.get("baseScore")
        sev = cvss_data.get("baseSeverity") or ""

    bucket = severity_bucket(score, sev)
    return {
        "id": cve_id,
        "bucket": bucket,
        "score": score,
        "published": published,
        "desc": clean_description(desc_en),
    }


def sort_cves(summaries: list[dict]) -> list[dict]:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

    def key(x):
        sc = safe_float(x.get("score"))
        return (order.get(x["bucket"], 9), -(sc if sc is not None else -1.0), x["id"])

    return sorted(summaries, key=key)


# =========================
# REPORT
# =========================
def format_report(inventory_path: str, inv: dict, arch_block: dict | None, blocks: list[dict]) -> str:
    lines = []
    lines.append("=== Hardware → CPE (NVD Products API) → CVE (NVD Vulnerability API) Report ===")
    lines.append(f"Source inventory file : {inventory_path}")
    lines.append(f"Generated at          : {datetime.now().isoformat(timespec='seconds')}")
    lines.append("")

    lines.append("=== Inventory ===")
    for k in sorted(inv.keys()):
        if k == "raw_lines":
            continue
        lines.append(f"- {k}: {inv[k]}")
    lines.append("")

    # Architecture CPU CPE (vendor/family)
    lines.append("=== Architecture CPU (generic CPE) ===")
    if not arch_block:
        lines.append("No CPU vendor detected -> no architecture CPE query performed.")
    else:
        lines.append(f"CPU vendor detected: {arch_block['cpu_vendor']}")
        lines.append(f"Architecture CPE    : {arch_block['cpe']}")
        lines.append(f"CVE found           : {arch_block['cve_count']} (showing top {TOP_CVE_TO_SHOW_PER_CPE})")
        for i, s in enumerate(arch_block["top_cves"][:TOP_CVE_TO_SHOW_PER_CPE], start=1):
            sc = s["score"]
            head = f"{i:02d}. {s['id']} | {s['bucket']}"
            if sc is not None:
                head += f" (CVSS {sc})"
            if s.get("published"):
                head += f" | {s['published'][:10]}"
            lines.append(head)
            lines.append(f"    Summary: {s['desc']}")
    lines.append("")

    # Component blocks
    lines.append("=== Component CPE matching (Products API keywordSearch) ===")
    for b in blocks:
        lines.append("")
        lines.append(f"--- [{b['label']}] query: {b['query']}")
        if b.get("error"):
            lines.append(f"ERROR: {b['error']}")
            continue

        cpes = b.get("cpes", [])
        lines.append(f"CPE candidates found: {len(cpes)} (showing up to {TOP_CPE_TO_QUERY})")
        for idx, c in enumerate(cpes[:TOP_CPE_TO_QUERY], start=1):
            title = f" - {c.get('title')}" if c.get("title") else ""
            lines.append(f"  {idx}. {c['cpeName']}{title}")

            cve_summaries = c.get("cves", [])
            lines.append(f"     CVE found: {len(cve_summaries)} (showing top {TOP_CVE_TO_SHOW_PER_CPE})")
            for j, s in enumerate(cve_summaries[:TOP_CVE_TO_SHOW_PER_CPE], start=1):
                sc = s["score"]
                head = f"     {j:02d}) {s['id']} | {s['bucket']}"
                if sc is not None:
                    head += f" (CVSS {sc})"
                if s.get("published"):
                    head += f" | {s['published'][:10]}"
                lines.append(head)
                lines.append(f"         Summary: {s['desc']}")

    lines.append("")
    lines.append("=== Notes ===")
    lines.append("- Products API (/cpes/2.0) is used to map a human-readable component string to official CPE names.")
    lines.append("- Vulnerability API (/cves/2.0?cpeName=...) returns CVEs whose applicability includes that CPE.")
    lines.append("- For consumer laptops, model-specific CPE/CVE coverage can be limited; generic architecture CPE is used to cover CPU-family issues.")
    lines.append("")
    return "\n".join(lines)


# =========================
# MAIN PIPELINE
# =========================
def run(inventory_path: str, reports_dir: str = REPORTS_DIR) -> Path:
    inv = read_inventory_txt(inventory_path)
    session = make_session()

    # 1) Architecture CPU block (generic CPE)
    cpu_vendor = detect_cpu_vendor(inv)
    arch_cpe = arch_cpu_cpe(cpu_vendor)

    arch_block = None
    if arch_cpe:
        try:
            vulns = cve_search_by_cpe(session, arch_cpe, results_per_page=50)
            summaries = [extract_cve_summary(v) for v in vulns]
            summaries = sort_cves(summaries)
            arch_block = {
                "cpu_vendor": cpu_vendor,
                "cpe": arch_cpe,
                "cve_count": len(summaries),
                "top_cves": summaries,
            }
        except Exception as e:
            arch_block = {"cpu_vendor": cpu_vendor, "cpe": arch_cpe, "cve_count": 0, "top_cves": [], "error": str(e)}

    # 2) Component mapping via CPE API then CVEs
    components = build_components(inv)
    blocks = []

    for comp in components:
        label = comp["label"]
        query = comp["query"]

        try:
            cpes = cpe_search_keyword(session, query, results_per_page=CPE_RESULTS_PER_COMPONENT)
            # Pour chaque CPE retenu, on récupère les CVE
            for c in cpes[:TOP_CPE_TO_QUERY]:
                vulns = cve_search_by_cpe(session, c["cpeName"], results_per_page=50)
                summaries = [extract_cve_summary(v) for v in vulns]
                c["cves"] = sort_cves(summaries)
            blocks.append({"label": label, "query": query, "cpes": cpes, "error": None})
        except Exception as e:
            blocks.append({"label": label, "query": query, "cpes": [], "error": str(e)})

    report_text = format_report(inventory_path, inv, arch_block, blocks)
    out = build_versioned_report_path(reports_dir, Path(inventory_path).stem, kind="hardware_cpe")
    out.write_text(report_text, encoding="utf-8")
    return out


if __name__ == "__main__":
    inv_path = sys.argv[1] if len(sys.argv) > 1 else "machine.txt"
    out = run(inv_path, REPORTS_DIR)
    print(f"Report written to: {out.resolve()}")
