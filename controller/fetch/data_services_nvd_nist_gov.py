# exemple fonctionnel de tache cron pour miner https:/nvd.nist.gov pour récupérer des CVE
# le système gère les doublons dans le datalake, pas besoin de le gérer ici (!important si il y a plusieurs source qui peuvent output les même CVE!)

# doit contenir la fonction "fetch" et "save"

# 🔁 CVE Data Normalization
# All CVE sources (e.g., NVD, Shodan, Nessus) must produce a DataFrame
# with the following exact columns, in this order:
#
# - cve_id       : unique identifier (e.g., CVE-2023-12345)
# - vendor       : name of the vendor or author of the technology
# - product      : name of the technology/library affected
# - version      : affected version ("" if unknown)
# - description  : short vulnerability summary
# - severity     : severity level (LOW, MEDIUM, HIGH, CRITICAL or empty string)
#
# ⚠️ These column names are mandatory for correct merging and storage

import requests
import datetime
import pandas as pd

class Data_services_nvd_nist_gov:
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch(self, sinceDay):
        # fetch
        today = datetime.date.today()
        yesterday = today - datetime.timedelta(days=sinceDay)
        url = f"{self.base_url}?pubStartDate={yesterday}T00:00:00.000Z&pubEndDate={today}T00:00:00.000Z"
        resp = requests.get(url)
        raw_cves = resp.json().get("vulnerabilities", [])

        rows = []
        for item in raw_cves:
            cve = item.get("cve", {})
            cve_id = cve.get("id")

            # Extraire la description (prendre la première en anglais si possible)
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            # Extraire la date de publication
            published_date = cve.get("published", "")
            # Convertir au format date si nécessaire (optionnel)
            if published_date:
                try:
                    # Format: "2025-04-03T01:03:51.193"
                    published_date = published_date.split("T")[0]  # Garder seulement YYYY-MM-DD
                except:
                    pass  # Garder le format original si problème

            # Extraire le severity et le score - gérer différentes versions CVSS
            severity = ""
            cvss_score = 0.0
            cvss_version = ""
            metrics = cve.get("metrics", {})

            # Essayer CVSS v4.0 d'abord
            if "cvssMetricV40" in metrics and metrics["cvssMetricV40"]:
                cvss_data = metrics["cvssMetricV40"][0].get("cvssData", {})
                severity = cvss_data.get("baseSeverity", "")
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_version = "4.0"
            # Puis CVSS v3.1
            elif "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                severity = cvss_data.get("baseSeverity", "")
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_version = "3.1"
            # Puis CVSS v3.0
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                severity = cvss_data.get("baseSeverity", "")
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_version = "3.0"
            # Enfin CVSS v2.0
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                severity = cvss_data.get("baseSeverity", "")
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_version = "2.0"

            # Extraire technologies/librairies/versions depuis configurations
            techs = []
            configurations = cve.get("configurations", [])
            for config in configurations:
                nodes = config.get("nodes", [])
                for node in nodes:
                    cpe_matches = node.get("cpeMatch", [])
                    for match in cpe_matches:
                        cpe = match.get("criteria", "")
                        if cpe.startswith("cpe:"):
                            parts = cpe.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3] if len(parts) > 3 else ""
                                product = parts[4] if len(parts) > 4 else ""
                                version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""

                                # Nettoyer les valeurs
                                vendor = vendor.replace("\\", "") if vendor else ""
                                product = product.replace("\\", "") if product else ""
                                version = version.replace("\\", "") if version else ""

                                if vendor or product:  # Au moins un des deux doit être présent
                                    techs.append((vendor, product, version))

            # Si aucune technologie trouvée dans configurations, créer une ligne avec des valeurs vides
            if techs:
                # Pour chaque technologie trouvée, créer une ligne
                for vendor, product, version in techs:
                    rows.append({
                        "cve_id": cve_id,
                        "vendor": vendor,
                        "product": product,
                        "version": version,
                        "description": description,
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "cvss_version": cvss_version,
                        "published_date": published_date
                    })
            else:
                # Si pas de technologies, créer quand même une ligne pour ne pas perdre le CVE
                rows.append({
                    "cve_id": cve_id,
                    "vendor": "",
                    "product": "",
                    "version": "",
                    "description": description,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "cvss_version": cvss_version,
                    "published_date": published_date
                })

        return pd.DataFrame(rows)


