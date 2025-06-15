from flask import Flask, send_file, request, jsonify, Response
from multiprocessing.synchronize import Lock as SyncLock
from flask_cors import CORS
import os
import duckdb
from typing import Generator
import openai
import json

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
                        WHERE product ILIKE '%{cve['name']}%' ORDER BY published_date DESC
                        """
                    if 'version' in cve:
                        query += f" AND version ILIKE '%{cve['version']}%'"
                    result = duckdb.query(query).to_df()
                    output.append(result.to_dict(orient="records"))
            return jsonify(output)

        @self.app.route('/chat_cve', methods=['POST'])
        def chat_cve():
            """Endpoint to analyze CVE data with streaming response"""
            try:
                data = request.json


                search = data['search']
                cve_data = data['cve']
                user_question = data.get('question', None)

                # Create the prompt
                prompt = self.create_cve_prompt(search, cve_data)

                # Return streaming response
                return Response(
                    self.stream_openai_response(prompt, user_question),
                    mimetype='text/event-stream',
                    headers={
                        'Cache-Control': 'no-cache',
                        'Connection': 'keep-alive',
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Headers': 'Content-Type'
                    }
                )

            except Exception as e:
                return jsonify({'error': str(e)}), 500


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

    def create_cve_prompt(self, library_name: str, cve_data: dict) -> str:
        """Create the prompt for CVE analysis"""
        prompt = f"""You are a helpful assistant. The user wants to ask a question about CVE (Common Vulnerabilities and Exposures).

        Here is the information about the library we are talking about:
        Library Name (maybe with version): {library_name}

        CVE Data: {json.dumps(cve_data, indent=2)}

        Please analyze this CVE information and provide a comprehensive assessment including:
        1. Severity and impact analysis
        2. Affected components and attack vectors
        3. Mitigation strategies and recommendations
        4. Whether the current version is affected
        5. Upgrade recommendations if applicable

        Please be thorough and practical in your analysis."""

        return prompt

    def stream_openai_response(self, prompt: str, user_question: str = None) -> Generator[str, None, None]:
        """Stream response from OpenAI API"""
        try:
            # Combine the CVE prompt with any additional user question
            full_prompt = prompt
            full_prompt += f"\n\nAnswer the user Question: {user_question}"

            # Make streaming request to OpenAI
            # Note: For web research capabilities, you might want to use GPT-4 with browsing
            # or a model that supports web search. Adjust model name as needed.
            response = openai.ChatCompletion.create(
                model="gpt-4.1-nano",
                messages=[
                    {
                        "role": "user",
                        "content": full_prompt
                    }
                ],
                stream=True,
                max_tokens=2000,
                temperature=0.3
            )

            for chunk in response:
                if chunk.choices[0].delta.get("content"):
                    content = chunk.choices[0].delta.content
                    # Format as Server-Sent Events
                    yield f"data: {json.dumps({'content': content})}\n\n"

        except Exception as e:
            error_msg = f"Error: {str(e)}"
            yield f"data: {json.dumps({'error': error_msg})}\n\n"