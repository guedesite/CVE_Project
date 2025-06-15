import json
import requests
from time import sleep

# Liste de CVE à récupérer (tu peux l'automatiser plus tard)
CVE_IDS = [
    "CVE-2024-24576",
    "CVE-2025-5419",
    "CVE-2023-12345",
    "CVE-2022-40982",
    "CVE-2024-31497",
]

def fetch_cve_data(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        print(f"🔍 Fetching {cve_id}...")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"❌ Erreur pour {cve_id} : {e}")
        return None

def fetch_all():
    results = []

    for cve_id in CVE_IDS:
        data = fetch_cve_data(cve_id)
        if data:
            results.append(data)
        sleep(1)  # Évite d’abuser de l’API

    print(f"✅ Total CVE récupérés : {len(results)}")
    with open("/opt/airflow/script/cve_raw.json", "w") as f:
        json.dump(results, f, indent=2)

    return results
