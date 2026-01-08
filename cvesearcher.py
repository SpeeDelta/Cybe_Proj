import nmap
import requests
from datetime import datetime
from pathlib import Path
import subprocess
import ipaddress
import typer
from typing import Annotated

# Initialisation
nm = nmap.PortScanner()
output_lines = []
app = typer.Typer()


def log(msg: str):
    """
    add message to buffer
    """
    output_lines.append(msg)


@app.command()
def scanip(
    ip_to_scan: str,
    report_dir: Annotated[str, typer.Option("--report-dir", "-d", help="specify directory where the report is created")] = "reports"
):
    """
    Performs a complete scan of a specific IP address and calls a CVE API to create a CVE report.
    """

    # Ajout d'en-tête dans le fichier rapport
    log(f"IP : {ip_to_scan}")
    log(f"Date : {datetime.now()}")
    log("")
    log("-" * 40)

    # Petit message console pour dire que ça démarre (ne va pas dans le rapport)
    print(f"[*] Scan en cours sur {ip_to_scan}, veuillez patienter...")


    try:
        # Lancement du scan Nmap
        nm.scan(hosts=ip_to_scan, arguments="-sV")
        hostname = nm[ip_to_scan].hostname() or ""
    except KeyError:
        # en cas de problème de scan
        nm.scan(hosts=ip_to_scan, arguments="-Pn")
        hostname = nm[ip_to_scan].hostname() or ""

    if hostname:
        log(f"Hôte : {hostname}")

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
                log(f"Port {port}/{proto} – Service : {service_desc} – CPE : {cpe_query}")
            else:
                log(f"Port {port}/{proto} – Service : {service_desc} – CPE non disponible")
            
            if not cpe_query:
                continue

            # Requête NVD
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_query}"
            try:
                response = requests.get(url)
            except Exception as e:
                log(f"Erreur requête NVD : {e}")
                continue

            if response.status_code != 200:
                log(f"Erreur HTTP {response.status_code}")
                continue

            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                log("Aucune vulnérabilité trouvée.")
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
                    log(f"{cve_id} (CVSS {cvss_score} - {cvss_severity}) : {description}")
                else:
                    log(f"{cve_id} : {description}")

    # Sauvegarde
    log("")
    try:
        Path(report_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        report_file = Path(report_dir) / f"scan_network_{ts}_{ip_to_scan.replace('.', '-')}_{hostname}.txt"
        report_file.write_text("\n".join(output_lines), encoding="utf-8")
        
        # Seul message de fin visible
        print(f"[OK] Rapport généré : {report_file.resolve()}")

    except Exception as e:
        print(f"[ERREUR] Écriture fichier : {e}")

    # reinitialisation du buffer
    output_lines = []


# Programme principal
@app.command()
def scanet(
    network: Annotated[str, typer.Option("--network", "-n", help="specify network to scan")] = "192.168.1.0/24",
    report_dir: Annotated[str, typer.Option("--report-dir", "-d", help="specify directory where reports are created")] = "reports"
):
    """
    Performs a scan of a specific network and calls the 'scanip' command for each IP address found.
    """
    
    print(f"Découverte du réseau {network}...")

    reachable_ips = []

    # scan classique
    network_to_ping = ipaddress.IPv4Network(network)
    for ip in network_to_ping.hosts():
        try:
            output = subprocess.check_output(["ping", "-c", "1", format(ip)])
            reachable_ips.append(format(ip))
        except subprocess.CalledProcessError:
            pass
    if len(reachable_ips) > 0:
        print("Découverte du réseau terminée, démarrage de l'analyse.")
        for ip in reachable_ips:
            scanip(ip, report_dir)
    else:
        print("Découverte du réseau terminée, aucune machine trouvée.")


if __name__ == "__main__":
    app()