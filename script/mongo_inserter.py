import json
from pymongo import MongoClient # type: ignore
from pymongo.errors import BulkWriteError # type: ignore


def insert_into_mongodb():
    client = MongoClient("mongodb://admin:adminpass@mongo:27017/")
    db = client["cybersec"]
    collection = db["vulnerabilites"]

    with open("/opt/airflow/script/cve_cleaned.json", "r") as f:
        data = json.load(f)

    # Optionnel : nettoyer la collection avant insertion
    # collection.delete_many({})

    try:
        if isinstance(data, list):
            collection.insert_many(data, ordered=False)
            print(f"✅ {len(data)} documents insérés dans MongoDB.")
        else:
            collection.insert_one(data)
            print("✅ 1 document inséré dans MongoDB.")
    except BulkWriteError as bwe:
        print("⚠️ Erreurs lors de l’insertion :")
        for error in bwe.details.get('writeErrors', []):
            print(f" - {error.get('errmsg')}")


if __name__ == "__main__":
    insert_into_mongodb()
