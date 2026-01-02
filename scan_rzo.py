import nmap
import requests
import json
from datetime import datetime
from pathlib import Path
import subprocess
import platform

nm = nmap.PortScanner()

def super_scan_de_la_mort_sur(ip_to_scan: str, REPORTS_DIR: str) -> None :

    # Initialisation
    output_lines = []

    def log(msg: str):
        """
        Ajoute le message au buffer du rapport UNIQUEMENT.
        Aucun affichage console (print) ici.
        """
        output_lines.append(msg)

    # Petit message console pour dire que ça démarre (ne va pas dans le rapport)
    print(f"[*] Scan en cours sur {ip_to_scan}, veuillez patienter...")

    # Ajout d'en-tête dans le fichier rapport
    log(f"Rapport de scan pour : {ip_to_scan}")
    log(f"Date : {datetime.now()}")
    log("-" * 40)

    # Lancement du scan Nmap
    nm.scan(hosts=ip_to_scan, arguments="-sV")

    # Parcours des hôtes
    host = nm.all_hosts()[0]
    hostname = nm[host].hostname() or ""
    host_line = f"Hôte : {host}"
    if hostname:
        host_line += f" ({hostname})"
    log(host_line)

    if nm[host].state() != "up":
        return 1

    for proto in nm[host].all_protocols():
        ports = nm[host][proto].keys()
        for port in sorted(ports):
            port_info = nm[host][proto][port]
            
            if port_info.get('state') != 'open':
                continue

            service_name = port_info.get('name') or "unknown"
            product = port_info.get('product') or ""
            version = port_info.get('version') or ""
            
            service_desc = f"{service_name}"
            if product:
                service_desc += f" ({product} {version})" if version else f" ({product})"
            
            cpe = port_info.get('cpe')
            cpe_str = cpe if cpe else ""
            
            if cpe_str:
                if cpe_str.startswith("cpe:/"):
                    cpe_query = "cpe:2.3:" + cpe_str[len("cpe:/"):]
                else:
                    cpe_query = cpe_str
            else:
                cpe_query = None

            if cpe_query:
                log(f"    Port {port}/{proto} – Service : {service_desc} – CPE : {cpe_query}")
            else:
                log(f"    Port {port}/{proto} – Service : {service_desc} – CPE non disponible")
            
            if not cpe_query:
                continue

            # Requête NVD
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_query}"
            try:
                response = requests.get(url)
            except Exception as e:
                log(f"        Erreur requête NVD : {e}")
                continue

            if response.status_code != 200:
                log(f"        Erreur HTTP {response.status_code}")
                continue

            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                log("        Aucune vulnérabilité trouvée.")
                continue

            for vuln in vulns:
                cve_info = vuln.get("cve", {})
                cve_id = cve_info.get("id", "CVE-????-????")
                description = ""
                for desc in cve_info.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                
                metrics = cve_info.get("metrics", {})
                cvss_score = None
                cvss_severity = None

                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get("baseSeverity")
                elif "cvssMetricV3" in metrics:
                    cvss_data = metrics["cvssMetricV3"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get("baseSeverity")
                elif "cvssMetricV2" in metrics:
                    cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get("baseSeverity") or ""

                if cvss_score is not None:
                    log(f"        {cve_id} (CVSS {cvss_score} - {cvss_severity}) : {description}")
                else:
                    log(f"        {cve_id} : {description}")

    # --- Sauvegarde ---
    try:
        Path(REPORTS_DIR).mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        report_file = Path(REPORTS_DIR) / f"scan_network_{ts}_{host.replace('.', '-')}_{hostname}.txt"
        report_file.write_text("\n".join(output_lines), encoding="utf-8")
        
        # Seul message de fin visible
        print(f"[OK] Rapport généré : {report_file.resolve()}")

    except Exception as e:
        print(f"[ERREUR] Écriture fichier : {e}")


# --- Configuration / Paramètres ---

def scan_ips(addresses: list, report_dir: str) -> None:
    for ip in addresses:
        super_scan_de_la_mort_sur(format(ip), report_dir)

def discover_reachable_ips(network):
    # Create a new Nmap PortScanner object
    nm = nmap.PortScanner()
    
    # Scan the network for live hosts
    nm.scan(hosts=network, arguments='-sn')  # -sn for Ping Scan
    
    reachable_ips = []
    
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            reachable_ips.append(host)
    
    return reachable_ips

if __name__ == "__main__":
    # Replace '192.168.1.0/24' with the desired network address and mask
    network = '192.168.1.0/24'
    reachable_ips = discover_reachable_ips(network)
    scan_ips(reachable_ips, "reports")