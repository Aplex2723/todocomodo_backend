from flask import request, jsonify
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from .services import register_user, login_user, get_user_licence_key, save_user_licence_key, get_chatgpt_response, get_conversation_by_user, reset_chat

def register_routes(app):
    @app.route('/api/register', methods=['POST'])
    def register():
        data = request.get_json()
        response, status = register_user(data)
        return jsonify(response), status

    @app.route('/api/login', methods=['POST'])
    def login():
        data = request.get_json()
        response, status = login_user(data)
        return jsonify(response), status
    
    @app.route('/api/refresh-token', methods=['POST'])
    @jwt_required(refresh=True)
    def refresh_token():
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user)
        return jsonify({'token': new_token}), 200

    @app.route('/api/get_licence_key', methods=['GET'])
    @jwt_required()
    def get_licence_key():
        current_user = get_jwt_identity()
        response, status = get_user_licence_key(current_user)
        return jsonify(response), status

    @app.route('/api/save_licence_key', methods=['POST'])
    @jwt_required()
    def save_licence_key():
        current_user = get_jwt_identity()
        data = request.get_json()
        licence_key = data.get('licence_key')

        if not licence_key:
            return jsonify({'error': 'Falta la licencia'}), 400

        response, status = save_user_licence_key(current_user, licence_key)
        return jsonify(response), status

    @app.route('/api/chat', methods=['POST'])
    @jwt_required()
    def chat():
        current_user = get_jwt_identity()

        # Obtener la clave de API del usuario
        licence_key_response, status = get_user_licence_key(current_user)
        if status != 200:
            return jsonify(licence_key_response), status

        licence_key = licence_key_response.get('licence_key')
        if not licence_key:
            return jsonify({'error': 'No API key found for the user'}), 400

        # Obtener el mensaje del usuario
        data = request.get_json()
        user_message = data.get('message')

        if not user_message:
            return jsonify({'error': 'No message provided'}), 400

        # Generar respuesta del chat usando LangChain
        chat_response, status = get_chatgpt_response(licence_key, user_message)
        return jsonify(chat_response), status
    @app.route('/api/get_chat_history', methods=['GET'])
    @jwt_required()
    def get_chat_history():
        current_user = get_jwt_identity()
        response, status = get_conversation_by_user(current_user)
        return jsonify(response), status

    @app.route('/api/reset-chat', methods=['POST'])
    @jwt_required()
    def reset_chat_route():
        current_user = get_jwt_identity()
        response, status = reset_chat(current_user)
        return jsonify(response), status