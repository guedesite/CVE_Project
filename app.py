from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import mysql.connector
import requests
from requests.auth import HTTPBasicAuth
from config import Config
import json
from datetime import datetime, timezone

app = Flask(__name__)
CORS(app)
app.config.from_object(Config)

def get_db_connection():
    try:
        return mysql.connector.connect(
            host=Config.MYSQL_HOST,
            port=Config.MYSQL_PORT,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD,
            database=Config.MYSQL_DATABASE
        )
    except mysql.connector.Error:
        return None

@app.route('/api/search_cves', methods=['POST'])
def search_cves():
    try:
        data = request.json
        libs = data.get('libs', [])

        if not libs or not isinstance(libs, list):
            return jsonify({'error': 'Paramètre "libs" invalide'}), 400

        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Erreur de connexion à la base de données'}), 500

        cursor = conn.cursor(dictionary=True)
        results = []

        for lib in libs:
            name = lib.get('lib_name')
            version = lib.get('lib_version')

            if not name:
                continue

            if version:
                query = """
                    SELECT c.cve_id, c.description, c.published_date, c.cvss_v3_score, p.name, p.version
                    FROM cve c
                    JOIN cve_product cp ON c.id = cp.cve_id
                    JOIN product p ON cp.product_id = p.id
                    WHERE p.name LIKE %s AND p.version LIKE %s
                """
                cursor.execute(query, (f"%{name}%", f"%{version}%"))
            else:
                query = """
                    SELECT c.cve_id, c.description, c.published_date, c.cvss_v3_score, p.name, p.version
                    FROM cve c
                    JOIN cve_product cp ON c.id = cp.cve_id
                    JOIN product p ON cp.product_id = p.id
                    WHERE p.name LIKE %s
                """
                cursor.execute(query, (f"%{name}%",))

            for row in cursor.fetchall():
                results.append({
                    'lib_name': row['name'],
                    'lib_version': row['version'],
                    'cve_id': row['cve_id'],
                    'published_date': row['published_date'].strftime('%Y-%m-%d') if row['published_date'] else None,
                    'score': row['cvss_v3_score'],
                    'description': row['description']
                })

        cursor.close()
        conn.close()

        return jsonify(results)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/')
def form():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=Config.DEBUG)
