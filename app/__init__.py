from flask import Flask
from flask_cors import CORS
from .config import Config
from .routes import register_routes
from flask_jwt_extended import JWTManager

def create_app():
    app = Flask(__name__)

    # Enabling cors
    CORS(app)
    app.config.from_object(Config)
    
    # Inicializar JWT
    jwt = JWTManager(app)
    
    # Registrar rutas
    register_routes(app)

    return app