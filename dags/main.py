import sys
import os

# Ajouter le dossier script au path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../script')))

from scraper_multi import fetch_all
from reducer import mapreduce_cves
from neo4j_inserter import insert_into_neo4j
from mongo_inserter import insert_into_mongodb

def scrape_task():
    print("🧪 Étape 1 : Scraping multi-source...")
    data = fetch_all()
    print("✅ Scraping terminé.")
    return data

def reduce_task():
    print("🧹 Étape 2 : MapReduce & nettoyage des données...")
    data = mapreduce_cves()
    print("✅ Réduction terminée.")
    return data

def insert_mongo_task():
    print("📦 Étape 3 : Insertion dans MongoDB...")
    insert_into_mongodb()
    print("✅ Insertion MongoDB réussie.")

def insert_neo4j_task():
    print("🌐 Étape 4 : Insertion dans Neo4j...")
    insert_into_neo4j()
    print("✅ Insertion Neo4j réussie.")

def notify(context):
    task_id = context['task_instance'].task_id
    dag_id = context['dag'].dag_id
    execution_date = context['execution_date']
    state = context['task_instance'].state
    print(f"🚨 [NOTIFICATION] DAG: {dag_id} | Task: {task_id} | State: {state} | Execution date: {execution_date}")
