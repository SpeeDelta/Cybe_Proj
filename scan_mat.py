import re
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import requests


# =========================
# CONFIG
# =========================
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HTTP_TIMEOUT = 25
RETRY_429_SLEEP = 8
MAX_429_RETRIES = 3

# Si ton prof te donne une API key NVD, mets-la ici (sinon None)
NVD_API_KEY = None

REPORTS_DIR = "reports"

# Limites pour que le rapport reste lisible
MAX_CVES_PER_QUERY = 15        # affiche max N CVE par requête
DESC_MAX_LEN = 220             # longueur max des descriptions
INCLUDE_PUBLISHED_DATE = True  # affiche la date de publication si dispo


# =========================
# OUTILS NOMMAGE / FICHIERS
# =========================
def slugify(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^\w\-]+", "_", s, flags=re.UNICODE)
    s = re.sub(r"_+", "_", s)
    return s.strip("_") or "unknown"


def build_versioned_report_path(reports_dir: str, source_name: str, kind: str = "hardware") -> Path:
    """
    Convention de nommage :
    reports/<kind>_<source>_<YYYYMMDD-HHMMSS>_vN.txt
    """
    Path(reports_dir).mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = f"{kind}_{slugify(source_name)}_{ts}"

    v = 1
    while True:
        p = Path(reports_dir) / f"{base}_v{v}.txt"
        if not p.exists():
            return p
        v += 1


def write_report(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


# =========================
# NETTOYAGE / FORMAT
# =========================
def clean_description(text: str, max_len: int = 220) -> str:
    """
    Rend la description lisible :
    - supprime retours à la ligne / espaces multiples
    - tronque
    """
    if not text:
        return ""
    one_line = " ".join(text.split())
    if len(one_line) > max_len:
        return one_line[:max_len].rstrip() + "..."
    return one_line


def severity_bucket(cvss_score, cvss_sev: str | None) -> str:
    """
    Retourne un bucket de sévérité. Priorité à baseSeverity si dispo,
    sinon dérive du score.
    """
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


# =========================
# LECTURE INVENTAIRE TXT
# =========================
def read_inventory_txt(path: str) -> dict:
    """
    Lit un fichier "clé: valeur". Garde aussi les lignes brutes si besoin.
    """
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


def build_hw_queries(inv: dict) -> list[tuple[str, str]]:
    """
    Construit des requêtes NVD (keywordSearch) basées sur l'inventaire.
    """
    manufacturer = inv.get("manufacturer") or inv.get("vendor") or ""
    model = inv.get("model") or inv.get("product") or ""
    bios = inv.get("bios version") or inv.get("bios") or ""
    cpu = inv.get("cpu") or ""
    nic = inv.get("nic") or inv.get("network") or inv.get("ethernet") or ""
    gpu = inv.get("gpu") or inv.get("graphics") or ""
    os_name = inv.get("os") or inv.get("operating system") or ""

    queries = []

    if manufacturer and model and bios:
        queries.append(("BIOS", f"{manufacturer} {model} BIOS {bios}"))
    if manufacturer and model:
        queries.append(("Machine", f"{manufacturer} {model} BIOS"))

    if cpu:
        # Plus efficace qu'un modèle exact parfois
        queries.append(("CPU", f"{cpu} vulnerability"))
        queries.append(("CPU", f"{cpu} microcode vulnerability"))

    if nic:
        queries.append(("NIC", f"{nic} driver vulnerability"))
        queries.append(("NIC", f"{nic} firmware vulnerability"))

    if gpu:
        queries.append(("GPU", f"{gpu} driver vulnerability"))

    if os_name:
        queries.append(("OS", f"{os_name} vulnerability"))

    for raw in inv.get("raw_lines", [])[:5]:
        queries.append(("RAW", raw))

    # Dedup
    seen = set()
    out = []
    for label, q in queries:
        qq = q.strip()
        if not qq:
            continue
        key = (label, qq.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append((label, qq))
    return out


# =========================
# NVD
# =========================
def nvd_keyword_search(session: requests.Session, query: str) -> list[dict]:
    url = f"{NVD_BASE_URL}?keywordSearch={quote(query)}"

    for _ in range(MAX_429_RETRIES + 1):
        r = session.get(url, timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            return r.json().get("vulnerabilities", [])
        if r.status_code == 429:
            time.sleep(RETRY_429_SLEEP)
            continue
        raise RuntimeError(f"HTTP {r.status_code} sur keywordSearch={query!r}")

    return []


def extract_cve_summary(vuln: dict) -> dict:
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "CVE-????-????")

    # Description EN
    desc_en = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc_en = d.get("value", "")
            break

    # Dates (optionnel)
    published = cve.get("published") or ""
    last_modified = cve.get("lastModified") or ""

    # CVSS (v3.1 -> v3 -> v2)
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

    return {
        "id": cve_id,
        "cvss_score": score,
        "cvss_severity": sev,
        "severity_bucket": severity_bucket(score, sev),
        "published": published,
        "last_modified": last_modified,
        "description": clean_description(desc_en, DESC_MAX_LEN),
    }


# =========================
# FORMAT RAPPORT (LISIBLE)
# =========================
def format_report(source_txt: str, inv: dict, blocks: list[dict]) -> str:
    lines = []
    lines.append("=== Hardware Inventory → NVD CVE Report (Readable) ===")
    lines.append(f"Source inventory file : {source_txt}")
    lines.append(f"Generated at          : {datetime.now().isoformat(timespec='seconds')}")
    lines.append("")

    # Inventaire
    lines.append("=== Parsed inventory ===")
    for k in sorted(inv.keys()):
        if k == "raw_lines":
            continue
        lines.append(f"- {k}: {inv[k]}")
    if inv.get("raw_lines"):
        lines.append("- raw_lines:")
        for rl in inv["raw_lines"]:
            lines.append(f"  - {rl}")
    lines.append("")

    # Résumé global
    global_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for b in blocks:
        for s in b.get("cves", []):
            global_counts[s["severity_bucket"]] += 1

    lines.append("=== Global summary (all queries combined) ===")
    lines.append(
        f"CRITICAL: {global_counts['CRITICAL']} | "
        f"HIGH: {global_counts['HIGH']} | "
        f"MEDIUM: {global_counts['MEDIUM']} | "
        f"LOW: {global_counts['LOW']} | "
        f"UNKNOWN: {global_counts['UNKNOWN']}"
    )
    lines.append("")

    # Détails par requête
    lines.append("=== NVD results (keywordSearch) ===")
    for b in blocks:
        label = b["label"]
        query = b["query"]
        err = b.get("error")
        cves = b.get("cves", [])

        lines.append("")
        lines.append(f"--- [{label}] query: {query}")
        if err:
            lines.append(f"ERROR: {err}")
            continue

        lines.append(f"Found: {len(cves)} CVE entries (showing up to {MAX_CVES_PER_QUERY})")

        # mini résumé par sévérité pour cette requête
        local_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for s in cves:
            local_counts[s["severity_bucket"]] += 1
        lines.append(
            f"Breakdown: CRIT {local_counts['CRITICAL']} | HIGH {local_counts['HIGH']} | "
            f"MED {local_counts['MEDIUM']} | LOW {local_counts['LOW']} | UNK {local_counts['UNKNOWN']}"
        )

        # On affiche une liste courte, triée par gravité puis score
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        def sort_key(x):
            # score peut être None
            sc = x["cvss_score"]
            try:
                scf = float(sc) if sc is not None else -1.0
            except Exception:
                scf = -1.0
            return (severity_order.get(x["severity_bucket"], 9), -scf, x["id"])

        shown = sorted(cves, key=sort_key)[:MAX_CVES_PER_QUERY]

        for i, s in enumerate(shown, start=1):
            score = s["cvss_score"]
            sev = s["severity_bucket"]
            header = f"{i:02d}. {s['id']}"

            if score is not None:
                header += f" | {sev} (CVSS {score})"
            else:
                header += f" | {sev}"

            if INCLUDE_PUBLISHED_DATE and s.get("published"):
                # souvent format ISO, on affiche juste YYYY-MM-DD
                header += f" | Published {s['published'][:10]}"

            lines.append(header)
            lines.append(f"    Summary: {s['description']}")

        if len(cves) > MAX_CVES_PER_QUERY:
            lines.append(f"    ... {len(cves) - MAX_CVES_PER_QUERY} more CVEs not displayed")

    lines.append("")
    lines.append("=== Notes ===")
    lines.append("- This report is based on keyword searches, so results are potentially related, not guaranteed to match your exact firmware/driver versions.")
    lines.append("- For confirmation, cross-check vendor advisories (Dell/Intel) and exact installed versions.")
    lines.append("")
    return "\n".join(lines)


# =========================
# MAIN
# =========================
def run_from_txt(inventory_path: str, reports_dir: str = REPORTS_DIR) -> Path:
    inv = read_inventory_txt(inventory_path)
    queries = build_hw_queries(inv)

    session = requests.Session()
    session.headers.update({"User-Agent": "TP-HW-CVE-Scanner/1.1"})
    if NVD_API_KEY:
        session.headers.update({"apiKey": NVD_API_KEY})

    blocks = []
    for label, q in queries:
        try:
            vulns_raw = nvd_keyword_search(session, q)
        except Exception as e:
            blocks.append({"label": label, "query": q, "cves": [], "error": str(e)})
            continue

        cves = [extract_cve_summary(v) for v in vulns_raw]
        blocks.append({"label": label, "query": q, "cves": cves, "error": None})

    report_text = format_report(inventory_path, inv, blocks)

    source_name = Path(inventory_path).stem
    out_path = build_versioned_report_path(reports_dir, source_name, kind="hardware")
    write_report(out_path, report_text)
    return out_path


if __name__ == "__main__":
    INVENTORY_TXT = "machine.txt"  # <-- change si besoin
    out = run_from_txt(INVENTORY_TXT, REPORTS_DIR)
    print(f"Report written to: {out}")
