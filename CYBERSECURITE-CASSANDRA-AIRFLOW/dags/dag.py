from airflow import DAG
from airflow.operators.python import PythonOperator
from datetime import datetime, timedelta
import sys
import os

# Ajouter le chemin vers le dossier contenant upload_cve_to_minio.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from upload_cve_to_minio import fetch_cve_json, upload_to_minio, save_temp_file

from store import parse_cve_fields, download_from_minio, insert_into_cassandra

OBJECT_NAMES = ["CVE-2021-44228.json", "CVE-2021-45046.json", "CVE-2021-45105.json", "CVE-2021-44832.json"]

def run_cve_upload(**context):
    cve_file = "/opt/airflow/dags/cves.txt"
    if not os.path.exists(cve_file):
        raise Exception(f"Fichier {cve_file} introuvable")

    with open(cve_file, "r") as f:
        cve_list = [line.strip() for line in f if line.strip()]

    for cve_id in cve_list:
        json_data = fetch_cve_json(cve_id)
        if not json_data:
            print(f"⚠️ Skipping {cve_id}")
            continue

        file_path = save_temp_file(json_data, cve_id)
        if not file_path:
            continue

        upload_to_minio(file_path, f"{cve_id}.json")

        try:
            os.remove(file_path)
        except Exception as e:
            print(f"❌ Erreur suppression fichier : {e}")

    return f"Upload des CVE terminé"


def run_cve_process(**context):
    results = []
    for obj_name in OBJECT_NAMES:
        file_path = download_from_minio(obj_name)
        if not file_path:
            raise Exception(f"Erreur téléchargement {obj_name}")

        cve_data = parse_cve_fields(file_path)
        if not cve_data:
            os.remove(file_path)
            raise Exception(f"Erreur parsing {obj_name}")

        insert_into_cassandra(cve_data)
        os.remove(file_path)
        results.append(f"Insertion de {cve_data['cve_id']} réussie")

    return results

default_args = {
    'owner': 'airflow',
    'depends_on_past': False,
    'retries': 1,
    'retry_delay': timedelta(minutes=1)
}


with DAG(
    'upload_cve_to_minio',
    default_args=default_args,
    description='DAG pour récupérer et uploader CVE dans MinIO',
    schedule_interval='0 8 * * *',  # Tous les jours à 08:00
    start_date=datetime(2025, 6, 15),
    catchup=False,
    tags=['cve', 'minio'],
) as dag:

    task_upload = PythonOperator(
        task_id='fetch_and_upload_cve',
        python_callable=run_cve_upload
    )

    task_process = PythonOperator(
        task_id='process_cve_from_minio_to_cassandra',
        python_callable=run_cve_process
    )

    task_upload >> task_process