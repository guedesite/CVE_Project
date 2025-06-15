import json
from neo4j import GraphDatabase


def insert_into_neo4j():
    uri = "bolt://neo4j:7687"
    user = "neo4j"
    password = "password"  # 🔐 adapte si besoin

    driver = GraphDatabase.driver(uri, auth=(user, password))

    with open("/opt/airflow/script/cve_cleaned.json", "r") as f:
        data = json.load(f)

    def insert(tx, vuln):
        # Gestion des versions (liste de str)
        versions = vuln.get("Version", [])
        if not isinstance(versions, list):
            versions = [versions]

        # Gestion des URLs multiples
        urls = vuln.get("URL_Reference")
        if isinstance(urls, str):
            urls = [urls]
        elif not isinstance(urls, list):
            urls = []

        # Création du nœud CVE et des relations
        tx.run("""
            MERGE (c:CVE {id: $id})
            SET c.description = $description,
                c.score = $score,
                c.niveau = $niveau,
                c.date = $date,
                c.patch = $patch,
                c.statut = $statut,
                c.type = $type

            MERGE (p:Produit {nom: $produit})
            MERGE (p)-[:CONCERNE]->(c)

            FOREACH (v IN $versions |
                MERGE (ver:Version {valeur: v})
                MERGE (p)-[:A_VERSION]->(ver)
                MERGE (ver)-[:VULNERABLE_A]->(c)
            )

            FOREACH (u IN $urls |
                MERGE (r:Reference {url: u})
                MERGE (c)-[:A_POUR_REFERENCE]->(r)
            )
        """,
        id=vuln.get("ID_CVE"),
        description=vuln.get("Description"),
        score=vuln.get("Score_CVSS"),
        niveau=vuln.get("Niveau_Risque"),
        date=vuln.get("Date_Publication"),
        patch=vuln.get("Patch_Disponible"),
        statut=vuln.get("Statut_Analyse"),
        type=vuln.get("Type_Faille"),
        produit=vuln.get("Produit"),
        versions=versions,
        urls=urls
        )

    with driver.session() as session:
        count = 0
        for v in data:
            if not v.get("ID_CVE"):
                print(f"⚠️ CVE ignorée (ID manquant) : {v}")
                continue
            try:
                session.write_transaction(insert, v)
                count += 1
            except Exception as e:
                print(f"❌ Erreur insertion Neo4j pour {v.get('ID_CVE')}: {e}")

    driver.close()
    print(f"✅ {count} vulnérabilités insérées dans Neo4j.")


if __name__ == "__main__":
    insert_into_neo4j()
