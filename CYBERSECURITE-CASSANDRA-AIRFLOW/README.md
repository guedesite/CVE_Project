# Projet CVE Data Pipeline : MinIO, Cassandra & Airflow

## Table des matières
- [Présentation du projet](#présentation-du-projet)  
- [Architecture](#architecture)  
- [Pré-requis](#pré-requis)  
- [Installation et configuration](#installation-et-configuration)  
- [Description du pipeline](#description-du-pipeline)  
  - [1. Récupération des données CVE](#1-récupération-des-données-cve)  
  - [2. Stockage dans MinIO](#2-stockage-dans-minio)  
  - [3. Insertion dans Cassandra](#3-insertion-dans-cassandra)  
  - [4. Orchestration avec Airflow](#4-orchestration-avec-airflow)  
- [Exécution du pipeline](#exécution-du-pipeline)   

---

## Présentation du projet

Ce projet vise à construire un pipeline automatisé pour collecter des données de vulnérabilités CVE (Common Vulnerabilities and Exposures), stocker ces données dans un système objet MinIO, puis les insérer dans une base de données Cassandra pour analyses ultérieures. Le pipeline est orchestré via Apache Airflow afin d'automatiser les différentes étapes de manière fiable et programmée.

---

## Architecture




## Pré-requis

- Python   
- Docker
- MinIO  
- Apache Cassandra (base NoSQL)  
- Apache Airflow (outil d’orchestration de workflow)   
- Clé API NVD valide  



## Installation et configuration

VOir fichier docker-compose.yml

## Description du pipeline

### 1. Récupération des données CVE

- Utilisation de la fonction `fetch_cve_json(cve_id)` qui interroge l’API NVD (via `requests`) avec une clé API pour récupérer les données JSON correspondant à un CVE donné.  
- Gestion des erreurs réseau, timeouts, et codes HTTP incorrects.

### 2. Stockage dans MinIO

- Sauvegarde locale temporaire de la réponse JSON via `save_temp_file()`, création d’un fichier `.json` dans un dossier temporaire.  
- Upload de ce fichier vers MinIO avec `upload_to_minio()`.  
- Le bucket MinIO `raw` est créé automatiquement s’il n’existe pas.  
- Nettoyage des fichiers temporaires après upload.

### 3. Insertion dans Cassandra

- Téléchargement des fichiers JSON depuis MinIO (fonction `download_from_minio`) dans une tâche Airflow distincte.  
- Parsing des données JSON pour extraire les champs pertinents via `parse_cve_fields()`.  
- Insertion dans Cassandra via `insert_into_cassandra()`.  
- Suppression locale des fichiers après traitement.

### 4. Orchestration avec Airflow

- DAG `upload_cve_to_minio` avec deux tâches principales :  
  - `fetch_and_upload_cve` : lit la liste de CVE dans `cves.txt`, récupère leurs données, puis upload dans MinIO.  
  - `process_cve_from_minio_to_cassandra` : télécharge, parse et insère les CVE dans Cassandra.  
- Dépendance Airflow : la seconde tâche ne démarre qu’après la réussite de la première.  
- Retry automatique en cas d’échec, avec délai configurable.

---

## Exécution du pipeline

1. Placer un fichier `cves.txt` dans le dossier où Airflow s’attend à le trouver, contenant une liste de CVE, une par ligne, 


2. Lancer Airflow Scheduler et Webserver.

3. Démarrer manuellement

4. Le DAG exécute la collecte, le stockage dans MinIO, puis le traitement et insertion dans Cassandra.

5. Vérifier les logs Airflow pour suivre le statut des tâches.

---

## Gestion des erreurs et logs

- Chaque étape imprime des messages détaillés sur la console et dans les logs Airflow.  
- En cas d’absence de fichier `cves.txt`, la tâche échoue avec une exception explicite.  
- Les erreurs réseau, API ou MinIO sont loguées avec détails pour faciliter le debug.  
- Les tentatives de retry sont gérées par Airflow.

