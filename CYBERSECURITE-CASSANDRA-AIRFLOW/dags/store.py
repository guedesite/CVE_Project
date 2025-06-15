import json
import os
from minio import Minio
from minio.error import S3Error
from cassandra.cluster import Cluster
from cassandra import AlreadyExists, InvalidRequest
from cassandra.query import SimpleStatement
from cassandra.auth import PlainTextAuthProvider

# Configuration MinIO
MINIO_ENDPOINT = "minio:9000"
MINIO_ACCESS_KEY = "minioadmin"
MINIO_SECRET_KEY = "minioadmin"
MINIO_BUCKET_NAME = "raw"
OBJECT_NAMES = ["CVE-2021-44228.json", "CVE-2021-45046.json", "CVE-2021-45105.json", "CVE-2021-44832.json"]

# Configuration Cassandra
CASSANDRA_HOST = "cassandra"
CASSANDRA_PORT = 9042
CASSANDRA_KEYSPACE = "cybersecurity"
CASSANDRA_TABLE = "vulnerabilities"

def download_from_minio(object_name):
    try:
        client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=False
        )
        local_file = f"/tmp/{object_name}"
        client.fget_object(MINIO_BUCKET_NAME, object_name, local_file)
        print(f"✅ Fichier téléchargé depuis MinIO : {local_file}")
        return local_file
    except S3Error as e:
        print(f"❌ Erreur lors du téléchargement depuis MinIO : {e}")
        return None


def parse_cve_fields(json_path):
    try:
        with open(json_path, "r") as f:
            data = json.load(f)

        vuln = data["vulnerabilities"][0]["cve"]

        cve_id = vuln.get("id", "")
        published = vuln.get("published", "")[:10]

        description = ""
        for desc in vuln.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        cvss_score = 0.0
        severity = "UNKNOWN"
        cvss_version = ""

        metrics = vuln.get("metrics", {})
        if "cvssMetricV31" in metrics:
            metric = metrics["cvssMetricV31"][0]
            cvss_data = metric.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
            cvss_version = cvss_data.get("version", "")
        elif "cvssMetricV30" in metrics:
            metric = metrics["cvssMetricV30"][0]
            cvss_data = metric.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
            cvss_version = cvss_data.get("version", "")
        elif "cvssMetricV2" in metrics:
            metric = metrics["cvssMetricV2"][0]
            cvss_score = metric.get("cvssData", {}).get("baseScore", 0.0)
            severity = metric.get("baseSeverity", "UNKNOWN")
            cvss_version = "2.0"

        vendor = product = version = ""
        configurations = vuln.get("configurations", [])
        if configurations:
            nodes = configurations[0].get("nodes", [])
            if nodes:
                cpes = nodes[0].get("cpeMatch", [])
                if cpes:
                    cpe_parts = cpes[0].get("criteria", "").split(":")
                    if len(cpe_parts) >= 6:
                        vendor = cpe_parts[3]
                        product = cpe_parts[4]
                        version = cpe_parts[5]

        return {
            "cve_id": cve_id,
            "vendor": vendor,
            "product": product,
            "version": version,
            "description": description,
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_version": cvss_version,
            "published_date": published
        }

    except (KeyError, json.JSONDecodeError, IndexError) as e:
        print(f"❌ Erreur d'extraction/parsing : {e}")
        return None

def insert_into_cassandra(data):
    try:
        cluster = Cluster([CASSANDRA_HOST], port=CASSANDRA_PORT)
        session = cluster.connect()

        try:
            session.execute(f"""
                CREATE KEYSPACE IF NOT EXISTS {CASSANDRA_KEYSPACE}
                WITH replication = {{'class': 'SimpleStrategy', 'replication_factor': 1}};
            """)
        except AlreadyExists:
            pass

        session.set_keyspace(CASSANDRA_KEYSPACE)

        try:
            session.execute(f"""
                CREATE TABLE IF NOT EXISTS {CASSANDRA_TABLE} (
                    cve_id TEXT PRIMARY KEY,
                    vendor TEXT,
                    product TEXT,
                    version TEXT,
                    description TEXT,
                    severity TEXT,
                    cvss_score FLOAT,
                    cvss_version TEXT,
                    published_date TEXT
                );
            """)
        except AlreadyExists:
            pass

        query = SimpleStatement(f"""
            INSERT INTO {CASSANDRA_TABLE} (cve_id, vendor, product, version, description,
            severity, cvss_score, cvss_version, published_date)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """)

        session.execute(query, (
            data['cve_id'], data['vendor'], data['product'], data['version'],
            data['description'], data['severity'], data['cvss_score'],
            data['cvss_version'], data['published_date']
        ))

        print(f"✅ CVE {data['cve_id']} inséré dans Cassandra")

    except Exception as e:
        print(f"❌ Erreur lors de l’insertion dans Cassandra : {e}")

if __name__ == "__main__":
    for obj_name in OBJECT_NAMES:
        json_file = download_from_minio(obj_name)
        if json_file:
            data = parse_cve_fields(json_file)
            if data:
                insert_into_cassandra(data)
            os.remove(json_file)



