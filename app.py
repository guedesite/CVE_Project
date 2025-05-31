from flask import Flask, request, jsonify, render_template, flash, send_file
from flask_cors import CORS
import mysql.connector
from datetime import datetime, timedelta
import requests
from requests.auth import HTTPBasicAuth
from config import Config
import json
import os 
app = Flask(__name__)
CORS(app)
app.config.from_object(Config)

CVE_SOURCES = Config.CVE_SOURCES

def fetch_cves_from_source(source_id, source_config):
    """Récupère les CVE d'une source spécifique avec gestion de la pagination"""
    if not source_config.get('enabled', False):
        return 0, []
    
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    base_url = source_config['api_url'].rstrip('/')
    
    endpoint = source_config['endpoints']['cves'].lstrip('/')
    url = f"{base_url}/{endpoint}"
    
    params = {
        'start_date': today,
        'page': 1,
        'per_page': source_config['params'].get('per_page', 10)
    }

    auth = None
    if source_config.get('auth_required', False):
        auth = HTTPBasicAuth(
            source_config['username'],
            source_config['password']
        )
    
    all_cves = []
    total_processed = 0
    max_pages = 10
    
    try:
        current_page = 1
        while current_page <= max_pages:
            params['page'] = current_page
            
            response = requests.get(url, params=params, auth=auth)
            response.raise_for_status()
            data = response.json()
            
            if not data.get('results'):
                break
                
            page_cves = []
            for item in data['results']:
                cve = item
                cve_id = cve.get('id') or cve.get('cve_id')
            
                if not cve_id:
                    continue
                    
                description = cve.get('summary', '')
                
                cvss_v3_score = None
                cvss_v3_vector = None
                
                if 'cvss' in cve and 'v3' in cve['cvss']:
                    cvss_v3_score = cve['cvss']['v3'].get('base_score')
                    cvss_v3_vector = cve['cvss']['v3'].get('vector')
                
                vendors = set()
                products = set()

                if 'vulnerable_products' in cve:
                    for cpe in cve['vulnerable_products']:
                        parts = cpe.split(':')
                        if len(parts) > 3:
                            vendors.add(parts[3])
                        if len(parts) > 4:
                            products.add(parts[4])
                
                page_cves.append({
                    'cve_id': cve_id,
                    'source_id': 1,
                    'published_date': cve.get('created_at', datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%MZ')),
                    'last_modified_date': cve.get('updated_at', datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%MZ')),
                    'description': description,
                    'cvss_v3_score': cvss_v3_score,
                    'cvss_v3_vector': cvss_v3_vector,
                    'vendors': ','.join(vendors) if vendors else '',
                    'products': ','.join(products) if products else '',
                    'raw_data': json.dumps(cve)
                })
            
            all_cves.extend(page_cves)
            total_processed += len(page_cves)
            
            if not data.get('next'):
                break
                
            current_page += 1
            
        return total_processed, all_cves
        
    except Exception as e:
        print(f"Erreur lors de la récupération des CVE depuis {source_id}: {str(e)}")
        return 0, []

from datetime import datetime

def parse_iso_datetime(dt_str):
    """Convertit une chaîne de date ISO 8601 en format MySQL DATETIME"""
    if not dt_str:
        return None
    try:
        if '.' in dt_str and 'Z' in dt_str:
            dt_str = dt_str.split('.')[0] + 'Z'
        dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, AttributeError) as e:
        print(f"Erreur de conversion de date '{dt_str}': {str(e)}")
        return None

def save_cves_to_db(cves):
    """Enregistre les CVE dans la base de données"""
    if not cves:
        return 0
    
    conn = get_db_connection()
    if not conn:
        return 0
        
    cursor = conn.cursor()
    saved_count = 0
    
    for cve in cves:
        try:
            cursor.execute("SELECT id FROM cve WHERE cve_id = %s", (cve['cve_id'],))
            if cursor.fetchone():
                continue
                
            published_date = parse_iso_datetime(cve['published_date'])
            last_modified_date = parse_iso_datetime(cve['last_modified_date'])
            
            cursor.execute("""
                INSERT INTO cve (
                    cve_id, source_id, published_date, last_modified_date,
                    description, cvss_v3_score, cvss_v3_vector,
                    vendors, products, raw_data
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                cve['cve_id'], 
                cve['source_id'], 
                published_date or None,
                last_modified_date or None,
                cve['description'][:65535] if cve['description'] else None,
                cve['cvss_v3_score'], 
                cve['cvss_v3_vector'][:255] if cve['cvss_v3_vector'] else None,
                cve['vendors'][:255] if cve['vendors'] else None,
                cve['products'][:255] if cve['products'] else None,
                cve['raw_data']
            ))
            saved_count += 1
            
        except Exception as e:
            print(f"Erreur lors de l'enregistrement de la CVE {cve.get('cve_id')}: {str(e)}")
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return saved_count

def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=Config.MYSQL_HOST,
            port=Config.MYSQL_PORT,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD,
            database=Config.MYSQL_DATABASE
        )
        return connection
    except mysql.connector.Error as e:
        return None, str(e)

@app.route('/api/cve', methods=['POST'])
def create_cve():
    try:
        data = request.json
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection error'}), 500
            
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO cve (
                id, 
                cve_id, 
                source_id, 
                published_date, 
                last_modified_date, 
                description, 
                cvss_v3_score, 
                cvss_v3_vector, 
                vendors, 
                products, 
                raw_data
            )
            VALUES (NULL, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data.get('cve_id'),
            1,
            data.get('published_date'),
            data.get('last_modified_date'),
            data.get('description'),
            data.get('cvss_v3_score'),
            data.get('cvss_v3_vector'),
            ','.join(data.get('vendors', [])),
            ','.join(data.get('products', [])),
            str(data)
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'CVE created successfully'}), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# serve builded vite app
@app.route('/')
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
    app.secret_key = Config.SECRET_KEY
    app.run(debug=Config.DEBUG)
