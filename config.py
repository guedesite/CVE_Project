import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    MYSQL_HOST = 'localhost'
    MYSQL_PORT = 3306
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = 'azerty'
    MYSQL_DATABASE = 'cve_test'
    
    DEBUG = True
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'dev-key-please-change')
