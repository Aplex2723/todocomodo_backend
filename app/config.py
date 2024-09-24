import os
from dotenv import load_dotenv

# Cargar las variables de entorno desde el archivo .env
load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')
    AZURE_STORAGE_CONNECTION_STRING = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
    # CHAT_TABLE_CLIENT = os.getenv("")
    SESSIONS_TABLE_NAME = os.getenv("SESSIONS_TABLE_NAME")
    TABLE_NAME = os.getenv("TABLE_NAME")
    JWT_SECRET_KEY = SECRET_KEY
    FLOWISE_URL = os.getenv("FLOWISE_URL")