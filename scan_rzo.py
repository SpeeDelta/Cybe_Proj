import nmap
import requests
import json

# --- Configuration / Paramètres ---
network_range = "45.33.32.156"  # Plage d'IP à scanner (peut être modifiée selon le réseau cible)
nm = nmap.PortScanner()          # Initialisation du scanner Nmap

print(f"Scanning network {network_range} ...")
# Lancement du scan Nmap en mode -sV (détection de version des services)
nm.scan(hosts=network_range, arguments="-sV")

# Parcours des hôtes scannés
for host in nm.all_hosts():
    hostname = nm[host].hostname() or ""  # nom DNS si disponible
    host_line = f"Hôte : {host}"
    if hostname:
        host_line += f" ({hostname})"
    print(host_line)
    # Vérifier que l'hôte est up
    if nm[host].state() != "up":
        continue  # ignorer les hôtes hors-ligne

    # Parcours des protocoles (tcp/udp) - Nmap -sV port scan couvre généralement TCP
    for proto in nm[host].all_protocols():
        ports = nm[host][proto].keys()
        for port in sorted(ports):
            port_info = nm[host][proto][port]
            state = port_info.get('state')
            if state != 'open':
                continue  # ne traiter que les ports ouverts
            service_name = port_info.get('name') or "unknown"
            product = port_info.get('product') or ""
            version = port_info.get('version') or ""
            service_desc = f"{service_name}"
            if product:
                service_desc += f" ({product} {version})" if version else f" ({product})"
            cpe = port_info.get('cpe')  # CPE fourni par Nmap (si disponible)
            cpe_str = cpe if cpe else ""
            if cpe_str:
                # Conversion éventuelle du format CPE 2.2 vers 2.3 pour l’API NVD
                if cpe_str.startswith("cpe:/"):
                    cpe_query = "cpe:2.3:" + cpe_str[len("cpe:/"):]
                else:
                    cpe_query = cpe_str
            else:
                cpe_query = None

            # Affichage du service avec CPE (ou mention "No CPE")
            if cpe_query:
                print(f"    Port {port}/{proto} – Service : {service_desc} – CPE : {cpe_query}")
            else:
                print(f"    Port {port}/{proto} – Service : {service_desc} – CPE non disponible")
            
            # Si pas de CPE, passer au service suivant (pas de recherche de vulnérabilités)
            if not cpe_query:
                continue

            # Requête à l'API NVD pour récupérer les CVE du CPE
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_query}"
            try:
                response = requests.get(url)
            except Exception as e:
                print(f"        Erreur lors de la requête NVD pour {cpe_query} : {e}")
                continue

            if response.status_code != 200:
                print(f"        Erreur HTTP {response.status_code} en interrogeant le NVD pour {cpe_query}")
                continue

            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                print("        Aucune vulnérabilité connue n’a été trouvée pour ce CPE.")
                continue

            # Parcours des vulnérabilités retournées
            for vuln in vulns:
                cve_info = vuln.get("cve", {})
                cve_id = cve_info.get("id", "CVE-????-????")
                # Récupérer la description en anglais
                description = ""
                for desc in cve_info.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                # Récupérer le score CVSS (v3.1 de préférence, sinon v3, sinon v2)
                cvss_score = None
                cvss_severity = None
                metrics = cve_info.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get("baseSeverity")
                elif "cvssMetricV3" in metrics:  # pour d'anciens CVE en v3.0
                    cvss_data = metrics["cvssMetricV3"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get("baseSeverity")
                elif "cvssMetricV2" in metrics:
                    cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore")
                    # CVSS v2 n’a pas de libellé de sévérité standardisé dans la même clé, on pourrait le dériver du score
                    cvss_severity = cvss_data.get("baseSeverity") or ""

                # Formater l’affichage du CVE
                if cvss_score is not None:
                    print(f"        {cve_id} (CVSS {cvss_score} - {cvss_severity}) : {description}")
                else:
                    # Pas de score disponible
                    print(f"        {cve_id} : {description}")
