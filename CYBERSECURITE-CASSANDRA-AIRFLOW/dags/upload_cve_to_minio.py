# import os
# import json
# import tempfile
# import requests
# from minio import Minio
# from minio.error import S3Error

# # ----------------------------
# # 🔐 Configuration MinIO & API
# # ----------------------------

# MINIO_ENDPOINT = "minio:9000"
# MINIO_ACCESS_KEY = "minioadmin"
# MINIO_SECRET_KEY = "minioadmin"
# MINIO_BUCKET_NAME = "raw"

# NVD_API_KEY = "10745830-a4d3-4532-b9cd-eb8cf2cebd09"
# NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# # ----------------------------
# # 📥 Récupérer les données CVE
# # ----------------------------
# def fetch_cve_json(cve_id="CVE-2021-44228"):
#     url = f"{NVD_API_BASE}?cveId={cve_id}"
#     headers = {"apiKey": NVD_API_KEY}

#     try:
#         response = requests.get(url, headers=headers, timeout=10)
#         response.raise_for_status()
#         print(f"✅ Données récupérées pour {cve_id}")
#         return response.json()
#     except requests.exceptions.Timeout:
#         print("❌ Timeout lors de la requête API")
#     except requests.exceptions.HTTPError as err:
#         print(f"❌ HTTP Error: {err}")
#     except requests.exceptions.RequestException as e:
#         print(f"❌ Erreur requête API: {e}")
#     return None

# # ----------------------------
# # 💾 Sauvegarder localement
# # ----------------------------
# def save_temp_file(json_data, cve_id):
#     try:
#         temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
#         with open(temp_file.name, 'w') as f:
#             json.dump(json_data, f, indent=2)
#         print(f"✅ Fichier temporaire créé : {temp_file.name}")
#         return temp_file.name
#     except Exception as e:
#         print(f"❌ Erreur lors de la sauvegarde du fichier temporaire: {e}")
#         return None

# # ----------------------------
# # ☁️ Envoyer dans MinIO
# # ----------------------------
# def upload_to_minio(file_path, object_name):
#     try:
#         client = Minio(
#             MINIO_ENDPOINT,
#             access_key=MINIO_ACCESS_KEY,
#             secret_key=MINIO_SECRET_KEY,
#             secure=False
#         )
#     except Exception as e:
#         print(f"❌ Erreur lors de la connexion à MinIO : {e}")
#         return False

#     try:
#         # Créer le bucket s'il n'existe pas
#         if not client.bucket_exists(MINIO_BUCKET_NAME):
#             client.make_bucket(MINIO_BUCKET_NAME)
#             print(f"📦 Bucket créé : {MINIO_BUCKET_NAME}")
#     except S3Error as e:
#         print(f"❌ Erreur lors de la création / vérification du bucket MinIO : {e}")
#         return False

#     try:
#         client.fput_object(
#             MINIO_BUCKET_NAME,
#             object_name,
#             file_path,
#             content_type="application/json"
#         )
#         print(f"✅ Fichier {object_name} envoyé dans MinIO bucket '{MINIO_BUCKET_NAME}'")
#         return True
#     except S3Error as err:
#         print(f"❌ Erreur MinIO lors de l'envoi du fichier : {err}")
#         return False

# # ----------------------------
# # 🚀 Script principal
# # ----------------------------
# if __name__ == "__main__":
#     cve_id = "CVE-2021-44228"
#     json_data = fetch_cve_json(cve_id)

#     if not json_data:
#         print("❌ Échec récupération des données CVE, arrêt du script.")
#         exit(1)

#     file_path = save_temp_file(json_data, cve_id)
#     if not file_path:
#         print("❌ Échec de la sauvegarde locale, arrêt du script.")
#         exit(1)

#     success = upload_to_minio(file_path, f"{cve_id}.json")
#     if not success:
#         print("❌ Échec de l'upload vers MinIO.")
#         # selon besoin, on peut décider d’arrêter ou de continuer

#     # Nettoyage du fichier temporaire
#     try:
#         os.remove(file_path)
#         print(f"🧹 Fichier temporaire supprimé : {file_path}")
#     except Exception as e:
#         print(f"❌ Erreur lors de la suppression du fichier temporaire : {e}")






import os
import json
import tempfile
import requests
from minio import Minio
from minio.error import S3Error

# ----------------------------
# 🔐 Configuration MinIO & API
# ----------------------------
MINIO_ENDPOINT = "minio:9000"
MINIO_ACCESS_KEY = "minioadmin"
MINIO_SECRET_KEY = "minioadmin"
MINIO_BUCKET_NAME = "raw"

NVD_API_KEY = "10745830-a4d3-4532-b9cd-eb8cf2cebd09"
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ----------------------------
# 📥 Récupérer les données CVE
# ----------------------------
def fetch_cve_json(cve_id):
    url = f"{NVD_API_BASE}?cveId={cve_id}"
    headers = {"apiKey": NVD_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        print(f"✅ Données récupérées pour {cve_id}")
        return response.json()
    except requests.exceptions.Timeout:
        print(f"❌ Timeout lors de la requête pour {cve_id}")
    except requests.exceptions.HTTPError as err:
        print(f"❌ HTTP Error pour {cve_id}: {err}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Erreur requête API pour {cve_id}: {e}")
    return None

# ----------------------------
# 💾 Sauvegarder localement
# ----------------------------
def save_temp_file(json_data, cve_id):
    try:
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        with open(temp_file.name, 'w') as f:
            json.dump(json_data, f, indent=2)
        print(f"✅ Fichier temporaire créé pour {cve_id} : {temp_file.name}")
        return temp_file.name
    except Exception as e:
        print(f"❌ Erreur lors de la sauvegarde de {cve_id} : {e}")
        return None

# ----------------------------
# ☁️ Envoyer dans MinIO
# ----------------------------
def upload_to_minio(file_path, object_name):
    try:
        client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=False
        )

        if not client.bucket_exists(MINIO_BUCKET_NAME):
            client.make_bucket(MINIO_BUCKET_NAME)
            print(f"📦 Bucket créé : {MINIO_BUCKET_NAME}")
    except S3Error as e:
        print(f"❌ Erreur MinIO : {e}")
        return False

    try:
        client.fput_object(
            MINIO_BUCKET_NAME,
            object_name,
            file_path,
            content_type="application/json"
        )
        print(f"✅ {object_name} envoyé dans MinIO")
        return True
    except S3Error as err:
        print(f"❌ Erreur upload MinIO : {err}")
        return False

# ----------------------------
# 🚀 Script principal
# ----------------------------
if __name__ == "__main__":
    # Fichier contenant les CVE (un par ligne)
    cve_file = "cves.txt"

    if not os.path.exists(cve_file):
        print(f"❌ Le fichier {cve_file} est introuvable.")
        exit(1)

    with open(cve_file, "r") as f:
        cve_list = [line.strip() for line in f if line.strip()]

    for cve_id in cve_list:
        print(f"\n🔍 Traitement de {cve_id}")
        json_data = fetch_cve_json(cve_id)

        if not json_data:
            print(f"⚠️ Skipping {cve_id}")
            continue

        file_path = save_temp_file(json_data, cve_id)
        if not file_path:
            continue

        success = upload_to_minio(file_path, f"{cve_id}.json")

        try:
            os.remove(file_path)
            print(f"🧹 Fichier temporaire supprimé : {file_path}")
        except Exception as e:
            print(f"❌ Erreur suppression fichier : {e}")
