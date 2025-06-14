from flask import Flask, send_file, request, jsonify
from multiprocessing.synchronize import Lock as SyncLock
from flask_cors import CORS
import os
import duckdb

class HttpServer:
    def __init__(self, public_dir: str, listen_ip:str, listen_port:int, datalake_lock:SyncLock, data_path:str ):

        self.public_dir = public_dir
        self.listen_ip = listen_ip

        self.listen_port = listen_port

        self.datalake_lock = datalake_lock

        self.data_path = data_path

        # Initialize Flask app
        self.app = Flask(__name__)

        # Enable CORS
        CORS(self.app)

        # Set up routes
        self._setup_routes()

    def start_server(self):
        self.app.run(host=self.listen_ip, port=self.listen_port, debug=False, threaded=True)

    def _setup_routes(self):
        # Serve index.html at root
        @self.app.route('/')
        def index():
            index_path = os.path.join(self.public_dir, 'index.html')
            if os.path.exists(index_path):
                return send_file(os.path.abspath(index_path))
            else:
                return f"index.html not found in {self.public_dir}", 404

        @self.app.route('/getCve', methods=['POST'])
        def getCve():
            data = request.get_json()
            output = []
            cves = data['cve']
            with self.datalake_lock:
                for cve in cves:
                    query = f"""
                        SELECT * FROM read_parquet('{self.data_path}')
                        WHERE product ILIKE '%{cve['name']}%'
                        """
                    if 'version' in cve:
                        query += f" AND version ILIKE '%{cve['version']}%'"
                    result = duckdb.query(query).to_df()
                    output.append(result.to_dict(orient="records"))
            return jsonify(output)
        #
        # other route here
        #

        # Serve static files from public_dir (this should come last)
        @self.app.route('/<path:filename>')
        def static_files(filename):
            file_path = os.path.join(self.public_dir, filename)
            if os.path.exists(file_path):
                return send_file(os.path.abspath(file_path))
            else:
                return f"File {filename} not found in {self.public_dir}", 404