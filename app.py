from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import mysql.connector
from datetime import datetime
from config import Config

app = Flask(__name__)
CORS(app)

app.config.from_object(Config)

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

@app.route('/')
def index():
    try:
        conn = get_db_connection()
        if not conn:
            return "Error connecting to database"
            
        cursor = conn.cursor()
        cursor.execute("""
            SELECT s.id, s.url, COUNT(c.id) as cve_count
            FROM source s
            LEFT JOIN cve c ON s.id = c.source_id
            GROUP BY s.id, s.url
        """)
        sources = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return render_template('index.html', sources=sources)
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/cves')
def cves():
    try:
        conn = get_db_connection()
        if not conn:
            return "Error connecting to database"
            
        cursor = conn.cursor()
        cursor.execute("""
            SELECT c.*, s.url as source_url
            FROM cve c
            JOIN source s ON c.source_id = s.id
            ORDER BY c.published_date DESC
        """)

        cves = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return render_template('cves.html', cves=cves)
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == '__main__':
    app.run(debug=Config.DEBUG)
