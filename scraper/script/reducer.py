import json
import re


def mapreduce_cves():
    with open('/opt/airflow/script/cve_raw.json', 'r', encoding='utf-8') as f:
        scraped_docs = json.load(f)

    print(f"📦 Nombre de CVE récupérées pour réduction : {len(scraped_docs)}")

    result = []
    id_counter = 1

    for doc in scraped_docs:
        try:
            id_cve = doc.get("ID_CVE") or extract_cve_id(str(doc))
            if not id_cve:
                id_cve = f"AUTO-CVE-{id_counter:05d}"
                id_counter += 1

            description = doc.get("Description", "").strip()
            produit = doc.get("Produit", "Non défini")
            version = ["Non précisée"]  # Par défaut, à ajuster si plus d'infos
            score = 0  # Pas de score CVSS dans l’API mitre.org publique
            niveau_risque = "Inconnu"
            date_pub = doc.get("Date_Publication", "").split("T")[0] if "T" in doc.get("Date_Publication", "") else doc.get("Date_Publication", "")
            url = doc.get("Références", [""])[0] if doc.get("Références") else ""
            type_faille = doc.get("Type_Faille", "Non défini")

            result.append({
                "ID_CVE": id_cve,
                "Produit": produit,
                "Version": version,
                "Description": description,
                "Score_CVSS": score,
                "Niveau_Risque": niveau_risque,
                "Date_Publication": date_pub,
                "Patch_Disponible": "Non",
                "URL_Reference": url,
                "Type_Faille": type_faille,
                "Statut_Analyse": "Non analysé"
            })

        except Exception as e:
            print(f"⚠️ Erreur sur {doc.get('ID_CVE', 'Inconnu')} : {e}")

    with open('/opt/airflow/script/cve_cleaned.json', 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"✅ {len(result)} CVE nettoyées et sauvegardées.")
    return result


def extract_cve_id(text):
    found = re.findall(r"CVE-\d{4}-\d{4,7}", text)
    return found[0] if found else None
