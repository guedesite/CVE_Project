# data/get_data_opencve_api_json.py

import requests
import json
import os

def fetch_cve_data(cve_id="CVE-2021-44228"):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {
        "apiKey": "10745830-a4d3-4532-b9cd-eb8cf2cebd09"
    }

    try:
        r = requests.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.Timeout:
        print("❌ Timeout")
    except requests.exceptions.HTTPError as err:
        print(f"❌ HTTP Error: {err}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Request Error: {e}")
    

    
   

def save_to_local(json_data, file_path):
    with open(file_path, 'w') as f:
        json.dump(json_data, f, indent=2)
    print(f"✅ Fichier JSON sauvegardé localement : {file_path}")

if __name__ == "__main__":
    cve_id = "CVE-2021-44228"
    json_data = fetch_cve_data(cve_id)

    if json_data:
        local_dir = os.path.join(os.path.dirname(__file__), './data')
        os.makedirs(local_dir, exist_ok=True)
        
        local_file = os.path.join(local_dir, f"{cve_id}.json")
        save_to_local(json_data, local_file)
