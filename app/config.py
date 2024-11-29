import os
from dotenv import load_dotenv

# Load environment variables from the .env file
if os.getenv('FLASK_ENV') != 'production':
    load_dotenv()

class Config:
    # Define required environment variables
    REQUIRED_ENV_VARS = [
        'SECRET_KEY',
        'AZURE_STORAGE_CONNECTION_STRING',
        'SESSIONS_TABLE_NAME',
        'TABLE_NAME',
        'FLOWISE_URL',
        'CHAT_TABLE_NAME'
    ]
    
    # Load environment variables
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')
    AZURE_STORAGE_CONNECTION_STRING = os.getenv('AZURE_STORAGE_CONNECTION_STRING')
    SESSIONS_TABLE_NAME = os.getenv("SESSIONS_TABLE_NAME")
    TABLE_NAME = os.getenv("TABLE_NAME")
    JWT_SECRET_KEY = SECRET_KEY
    FLOWISE_URL = os.getenv("FLOWISE_URL")
    CHAT_TABLE_NAME = os.getenv("CHAT_TABLE_NAME")
    
    @staticmethod
    def validate_env_vars():
        """Validate that all required environment variables are set and not empty."""
        missing_vars = [var for var in Config.REQUIRED_ENV_VARS if not os.getenv(var)]
        if missing_vars:
            raise EnvironmentError(
                f"The following environment variables are missing or empty: {', '.join(missing_vars)}"
            )

# Validate the environment variables at the time of configuration
try:
    Config.validate_env_vars()
except EnvironmentError as e:
    print(f"Configuration error: {e}")
    raise