import nmap
import requests
import json
from datetime import datetime
from pathlib import Path
import subprocess
import platform
from sys import argv, exit
import ipaddress

# Initialisation
nm = nmap.PortScanner()
output_lines = []
network = argv[1] if len(argv) > 1 else '192.168.1.0/24'
report_dir = argv[2] if len(argv) > 2 else 'reports'


def log(msg: str):
    """
    Ajoute le message au buffer du rapport UNIQUEMENT.
    Aucun affichage console (print) ici.
    """
    output_lines.append(msg)

def super_scan_de_la_mort_sur(ip_to_scan: str, REPORTS_DIR: str) -> None :

    # Ajout d'en-tête dans le fichier rapport
    log(f"Rapport de scan pour : {ip_to_scan}")
    log(f"Date : {datetime.now()}")
    log("-" * 40)

    # Petit message console pour dire que ça démarre (ne va pas dans le rapport)
    print(f"[*] Scan en cours sur {ip_to_scan}, veuillez patienter...")

    # Lancement du scan Nmap
    nm.scan(hosts=ip_to_scan, arguments="-sV")

    # Parcours des hôtes
    hostname = nm[ip_to_scan].hostname() or ""
    host_line = f"Hôte : {ip_to_scan}"
    if hostname:
        host_line += f" ({hostname})"
    log(host_line)

    if nm[ip_to_scan].state() != "up":
        return 1

    for proto in nm[ip_to_scan].all_protocols():
        ports = nm[ip_to_scan][proto].keys()
        for port in sorted(ports):
            port_info = nm[ip_to_scan][proto][port]
            
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

    # Sauvegarde
    try:
        Path(REPORTS_DIR).mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        report_file = Path(REPORTS_DIR) / f"scan_network_{ts}_{host.replace('.', '-')}_{hostname}.txt"
        report_file.write_text("\n".join(output_lines), encoding="utf-8")
        
        # Seul message de fin visible
        print(f"[OK] Rapport généré : {report_file.resolve()}")

    except Exception as e:
        print(f"[ERREUR] Écriture fichier : {e}")


# Programme principal

if __name__ == "__main__":
    if len(argv) > 1:
        if argv[1] == 'help':
            print("Utilisation : scan_rzo [network/mask] [report_direcotry]")
            print("Exemple : scan_rzo 172.19.30.0/25 /home/user/Documents/reports")
            print("Par défaut - network=192.168.1.0/24 - report_directory=reports/")
            exit()

    print(f"Découverte du réseau {network}...")

    reachable_ips = []
    
    # Scan avec nmap
    nm.scan(hosts=network, arguments='-sn')
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            reachable_ips.append(host)

    # scan classique
    network_to_ping = ipaddress.IPv4Network(network)
    for ip in network_to_ping.hosts():
        if format(ip) not in reachable_ips:
            try:
                output = subprocess.check_output(["ping", "-c", "1", format(ip)])
                reachable_ips.append(ip)
            except subprocess.CalledProcessError:
                pass

    if len(reachable_ips) > 0:
        print("Découverte du réseau terminée, démarrage de l'analyse.")
        for ip in reachable_ips:
            super_scan_de_la_mort_sur(format(ip), report_dir)
    else:
        print("Découverte du réseau terminée, aucune machine trouvée.")