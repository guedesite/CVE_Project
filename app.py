from flask import Flask, request, jsonify, render_template, flash, send_file
from flask_cors import CORS
import mysql.connector
import requests
from requests.auth import HTTPBasicAuth
from config import Config
import json
from datetime import datetime, timezone
import os 

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

# serve builded vite app
@app.route('/')
def form():
    return render_template('index.html')

def index():
    index_path = "./web/dist/index.html"
    if os.path.exists(index_path):
        return send_file(os.path.abspath(index_path))
    else:
        return f"index.html not found in ./web/dist/index.html", 404
    #
    #try:
    #    conn = get_db_connection()
    #    if not conn:
    #        return "Error connecting to database"
    #        
    #    cursor = conn.cursor()
    #    cursor.execute("""
    #        SELECT s.id, s.url, COUNT(c.id) as cve_count
    #        FROM source s
    #        LEFT JOIN cve c ON s.id = c.source_id
    #        GROUP BY s.id, s.url
    #    """)
    #    sources = cursor.fetchall()
    #    cursor.close()
    #    conn.close()
    #    
    #    return render_template('index.html', sources=sources)
    #except Exception as e:
    #    return f"Error: {str(e)}"

# static route for builded vite app
@app.route('/<path:filename>')
def static_files(filename):
    file_path = os.path.join("./web/dist/", filename)
    if os.path.exists(file_path):
        return send_file(os.path.abspath(file_path))
    else:
        return f"File {filename} not found in ./web/dist/index.html", 404

@app.route('/cves')
def cves():
    try:
        conn = get_db_connection()
        if not conn:
            return "Error connecting to database"
            
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT c.*, s.url as source_url
            FROM cve c
            JOIN source s ON c.source_id = s.id
            ORDER BY c.published_date DESC
        """)

        cves = cursor.fetchall()
        
        # Log pour débogage
        print(f"Nombre de CVEs récupérées: {len(cves)}")
        if cves:
            print("Première CVE:", cves[0])
        
        cursor.close()
        conn.close()
        
        return render_template('cves.html', cves=cves)
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Erreur détaillée: {error_details}")
        return f"Error: {str(e)}\n\nDétails: {error_details}"



@app.route('/download')
def download_page():
    """Affiche la page de téléchargement des CVE"""
    return "<h1>Téléchargement des CVE</h1><button onclick='downloadCVEs()'>Télécharger les CVE</button><script>function downloadCVEs(){fetch('/download_cves',{method:'POST'}).then(r=>r.json()).then(d=>alert(d.message))}</script>"

@app.route('/download_cves', methods=['POST'])
def download_cves():
    """Endpoint pour télécharger les CVE depuis toutes les sources"""
    total_downloaded = 0
    
    for source_id, source_config in CVE_SOURCES.items():
        if not source_config.get('enabled', False):
            continue
            
        print(f"Téléchargement des CVE depuis {source_id}...")
        count, cves = fetch_cves_from_source(source_id, source_config)
        
        if cves:
            saved = save_cves_to_db(cves)
            total_downloaded += saved
            print(f"{saved} nouvelles CVE enregistrées depuis {source_id}")
    
    return jsonify({
        'status': 'success',
        'message': f'{total_downloaded} nouvelles CVE ont été téléchargées et enregistrées'
    })

if __name__ == '__main__':
    app.run(debug=Config.DEBUG)
