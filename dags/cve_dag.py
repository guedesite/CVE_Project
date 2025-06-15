from airflow import DAG # type: ignore
from airflow.operators.python import PythonOperator # type: ignore
from datetime import datetime, timedelta

# Import des tâches depuis main.py
from main import scrape_task, reduce_task, insert_mongo_task, insert_neo4j_task, notify

# Arguments par défaut pour le DAG
default_args = {
    'owner': 'airflow',
    'depends_on_past': False,
    'email_on_failure': False,
    'email_on_retry': False,
    'retries': 1,
    'retry_delay': timedelta(minutes=1),
    'on_failure_callback': notify,
}

# Définition du DAG principal
with DAG(
    dag_id='cve_pipeline_dag',
    default_args=default_args,
    description='🔄 Pipeline CVE : Scraping JSON → Réduction → MongoDB → Neo4j',
    schedule_interval=None,  # à déclencher manuellement ou selon cron si besoin
    start_date=datetime(2025, 6, 15),
    catchup=False,
    tags=['cve', 'cybersecurité', 'green4all']
) as dag:

    # Tâche 1 : Scraper les CVE
    scrape = PythonOperator(
        task_id="scrape_data",
        python_callable=scrape_task
    )

    # Tâche 2 : Réduire et nettoyer les données
    reduce = PythonOperator(
        task_id="reduce_data",
        python_callable=reduce_task
    )

    # Tâche 3 : Insertion dans MongoDB
    insert_mongo = PythonOperator(
        task_id="insert_into_mongo",
        python_callable=insert_mongo_task
    )

    # Tâche 4 : Insertion dans Neo4j
    insert_neo4j = PythonOperator(
        task_id="insert_into_neo4j",
        python_callable=insert_neo4j_task
    )

    # Dépendances entre les tâches
    scrape >> reduce >> insert_mongo >> insert_neo4j
