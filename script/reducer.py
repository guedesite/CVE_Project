import json
import re

def mapreduce_cves():
    with open('/opt/airflow/script/cve_raw.json', 'r') as f:
        scraped_docs = json.load(f)

    print(f"📦 Nombre de CVE brutes à traiter : {len(scraped_docs)}")
    result = []
    id_counter = 1

    for doc in scraped_docs:
        try:
            cve_id = (
                doc.get("cveMetadata", {}).get("cveId") or
                doc.get("ID_CVE") or
                extract_cve_id(str(doc))
            )

            container = doc.get("containers", {}).get("cna", {})
            adp = doc.get("containers", {}).get("adp", [])
            description = next((d["value"] for d in container.get("descriptions", []) if d.get("lang") == "en"), "")

            produit = "Non défini"
            versions = ["Non précisée"]
            if "affected" in container and len(container["affected"]) > 0:
                produit = container["affected"][0].get("product", "Non défini")
                versions = [v.get("version", "") for v in container["affected"][0].get("versions", [])]

            # CVSS score et niveau de risque
            score = 0
            niveau_risque = "Inconnu"
            for bloc in adp:
                metrics = bloc.get("metrics", [])
                for metric in metrics:
                    if "cvssV3_1" in metric:
                        score = metric["cvssV3_1"].get("baseScore", 0)
                        if score >= 9:
                            niveau_risque = "Critique"
                        elif score >= 7:
                            niveau_risque = "Élevé"
                        elif score >= 4:
                            niveau_risque = "Modéré"
                        else:
                            niveau_risque = "Faible"

            # URL de référence
            url = ""
            refs = container.get("references", [])
            if refs:
                url = refs[0].get("url", "")

            # Type de faille (via CWE)
            cwe = "Non défini"
            if "problemTypes" in container:
                for pt in container["problemTypes"]:
                    for desc in pt.get("descriptions", []):
                        if "CWE" in desc.get("type", "") or "CWE" in desc.get("description", ""):
                            cwe = desc.get("description", "Non défini")

            # Date de publication
            date_pub = doc.get("cveMetadata", {}).get("datePublished", "").split("T")[0]

            result.append({
                "ID_CVE": cve_id,
                "Produit": produit,
                "Version": versions,
                "Description": description,
                "Score_CVSS": score,
                "Niveau_Risque": niveau_risque,
                "Date_Publication": date_pub,
                "Patch_Disponible": "Non",  # à enrichir plus tard si besoin
                "URL_Reference": url,
                "Type_Faille": cwe,
                "Statut_Analyse": "Non analysé"
            })

        except Exception as e:
            print(f"⚠️ Erreur lors du traitement d’un élément : {e}")
            continue

    with open('/opt/airflow/script/cve_cleaned.json', 'w') as f:
        json.dump(result, f, indent=2)

    print(f"✅ {len(result)} CVE nettoyées et sauvegardées.")
    return result


def extract_cve_id(text):
    found = re.findall(r"CVE-\d{4}-\d{4,7}", text)
    return found[0] if found else None
