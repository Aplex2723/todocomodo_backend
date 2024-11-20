import logging
import requests
from datetime import datetime, timedelta
import uuid
import json

from azure.data.tables import TableServiceClient
from flask_jwt_extended import create_access_token, create_refresh_token

from .utils import hash_password, verify_password
from .config import Config

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler()])  # Logs to console

# Create the Azure Table service client
table_service_client = TableServiceClient.from_connection_string(conn_str=Config.AZURE_STORAGE_CONNECTION_STRING)

# Create user and session tables if not exist
table_client = table_service_client.create_table_if_not_exists(Config.TABLE_NAME)
sessions_table_client = table_service_client.create_table_if_not_exists(Config.SESSIONS_TABLE_NAME)
chat_table_client = table_service_client.create_table_if_not_exists(Config.CHAT_TABLE_NAME)

def register_user(data):
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    if not username or not password or not email:
        logging.error('Registration failed: Missing username, password, or email')
        return {'error': 'Faltan campos de usuario, contraseña o correo electrónico'}, 400

    logging.info(f'Registering user: {username}')

    # Check if the username or email already exists
    table_client = table_service_client.get_table_client(Config.TABLE_NAME)

    try:
        existing_user = table_client.get_entity(partition_key='users', row_key=username)
        logging.warning(f'Username {username} is already in use')
        return {'error': 'El nombre de usuario ya está en uso'}, 409
    except Exception as e:
        logging.debug(f'Username {username} not found: {str(e)}')

    # Check if the email is already used
    users = list(table_client.query_entities(f"PartitionKey eq 'users' and email eq '{email}'"))
    if users:
        logging.warning(f'Email {email} is already in use')
        return {'error': 'El correo electrónico ya está en uso'}, 409

    # Hash the password
    hashed_password = hash_password(password)

    user_entity = {
        'PartitionKey': 'users',
        'RowKey': username,
        'password': hashed_password,
        'email': email
    }

    try:
        table_client.create_entity(entity=user_entity)
        logging.info(f'User {username} registered successfully')
        return {'message': 'Usuario registrado exitosamente'}, 201
    except Exception as e:
        logging.error(f'Error registering user {username}: {str(e)}')
        return {'error': f"Error al registrar el usuario: {str(e)}"}, 500

def login_user(data):
    identifier = data.get('identifier')
    password = data.get('password')
    logging.info(f"Getting the user by identifier {identifier}")

    if not identifier or not password:
        logging.error('Login failed: Missing identifier or password')
        return {'error': 'Faltan campos de identificación o contraseña'}, 400

    table_client = table_service_client.get_table_client(Config.TABLE_NAME)

    try:
        # Attempt to find by username
        user_entity = table_client.get_entity(partition_key='users', row_key=identifier)
        logging.info(f'User {identifier} found by username')
    except Exception:
        # Try finding by email if username not found
        users = list(table_client.query_entities(f"PartitionKey eq 'users' and email eq '{identifier}'"))
        if users:
            user_entity = users[0]
            logging.info(f'User {identifier} found by email')
        else:
            logging.warning(f'User {identifier} not found')
            return {'error': 'Usuario no encontrado'}, 404

    if verify_password(password, user_entity['password']):
        expiration_date = timedelta(days=30)
        access_token = create_access_token(identity=user_entity['RowKey'], expires_delta=expiration_date)
        refresh_token = create_refresh_token(identity=user_entity['RowKey'])  # Generate refresh token

        logging.info(f'User {identifier} login successful, tokens issued')
        return {'token': access_token, 'refreshToken': refresh_token}, 200
    else:
        logging.warning(f'Incorrect password for user {identifier}')
        return {'error': 'Contraseña incorrecta'}, 401   

def get_user_licence_key(username):
    table_client = table_service_client.get_table_client(Config.TABLE_NAME)
    
    try:
        user_entity = table_client.get_entity(partition_key='users', row_key=username)
        licence_key = user_entity.get('licence_key', '')
        logging.info(f'Licence key retrieved for user {username}')
        return {'licence_key': licence_key}, 200
    except Exception as e:
        logging.error(f'Error retrieving licence key for user {username}: {str(e)}')
        return {'error': f"No se pudo obtener la clave: {str(e)}"}, 500

def save_user_licence_key(username, licence_key):
    table_client = table_service_client.get_table_client(Config.TABLE_NAME)
    
    try:
        user_entity = table_client.get_entity(partition_key='users', row_key=username)
        user_entity['licence_key'] = licence_key
        table_client.update_entity(user_entity)
        logging.info(f'Licence key for user {username} saved successfully')
        return {'message': 'Clave API de OpenAI guardada exitosamente'}, 200
    except Exception as e:
        logging.error(f'Error saving licence key for user {username}: {str(e)}')
        return {'error': f"No se pudo guardar la clave: {str(e)}"}, 500

# Function to retrieve messages from Azure Table Storage by session ID
def get_conversation_by_user(username):
    table_client = table_service_client.get_table_client(Config.TABLE_NAME)
    try:
        user_entity = table_client.get_entity(partition_key='users', row_key=username)
        session_id = user_entity.get('last_session_id', '')
        table_client = table_service_client.get_table_client(table_name=Config.CHAT_TABLE_NAME)
        entities = table_client.query_entities(f"PartitionKey eq '{session_id}'")
        logging.info(f'We were able to get {username} user messages')
        return [{"user_message": e["UserMessage"], "bot_response": e["BotResponse"], "timestamp": e.get("Timestamp"), "metadata": e.get("metadata")}
                for e in entities], 200
    except Exception as e:
        logging.error(f'Error getting messages for {username}: {str(e)}')
        return {'error': f"No se pudo obteneer los mensajes: {str(e)}"}, 500


def save_message_to_table(session_id, user_message, bot_response, metadata = None):
    table_client = table_service_client.get_table_client(table_name=Config.CHAT_TABLE_NAME)
    entity = {}
    entity["PartitionKey"] = session_id  # Group by session ID
    entity["RowKey"] = str(uuid.uuid4())  # Unique identifier for each row
    entity["UserMessage"] = user_message
    entity["BotResponse"] = bot_response
    entity["metadata"] = metadata
    entity["Timestamp"] = datetime.utcnow()

    # Insert entity into table
    table_client.upsert_entity(entity)

def get_chatgpt_response(licence_key, user_message):
    try:
        API_URL = Config.FLOWISE_URL
        headers = {"Authorization": f"Bearer {licence_key}"}
        session_id = None

        table_client = table_service_client.get_table_client(Config.TABLE_NAME)

        query_filter = f"licence_key eq '{licence_key}'"
        user_entity = table_client.query_entities(query_filter=query_filter)

        if not user_entity:
            error_message = "Unable to find licence key, probably expired"
            logging.warning(error_message)
            return {'error': error_message}, 404
        
        logging.info(f'User entity found for licence key {licence_key}')

        user_entity = list(user_entity)[-1]  # Get the last entity
        session_id = user_entity.get("last_session_id")
        payload = {"question": user_message}
 
        if session_id:
            payload['overrideConfig'] = {"sessionId": session_id}

        def query(payload):
            logging.info(f"Sending data to Flowise: {payload}")
            response = requests.post(API_URL, headers=headers, json=payload)
            if response.status_code > 204:
                logging.error(f"Error while calling Flowise API - Response Code {response.status_code}\n\n{response.reason}")
            logging.info(f"Response from Flowise API: {response}")
            return response.json()

        logging.info('Sending request to Flowise API')
        response = query(payload)
        agent_response = response.get("text")
        session_id = response.get("sessionId")
        search_kb_tool_name = "Propertie_Link_manager"
        logging.info(f"Response text: {agent_response}; Session ID: {session_id}")

        # Safely extracting the metadata from sourceDocuments
        agent_reasoning = response.get("agentReasoning", [])
        logging.info(f"Agent Reasoning: {agent_reasoning}")

        # Initialize the metadata variable
        all_source_document_metadata = []

        # Iterate through each agent reasoning entry
        try:
            for tool in agent_reasoning:
                if tool.get("agentName") == search_kb_tool_name:
                    source_documents = tool.get("sourceDocuments", [])
                    for doc in source_documents:
                        metadata = doc.get("metadata")
                        if metadata:
                            all_source_document_metadata.append(metadata)
        except Exception as e:
            logging.error(f"Unable to get metadata from agent reasoning")

        if session_id:
            logging.info(f"Saving session ID {session_id} in data table and updating user")
            user_entity['last_session_id'] = session_id
            sessions_client = table_service_client.get_table_client(Config.SESSIONS_TABLE_NAME) 
            session_entity = {
                'PartitionKey': session_id,
                'RowKey': user_entity.get("PartitionKey"),
                'licence': licence_key
            }

            # Update both tables
            table_client.upsert_entity(user_entity)
            sessions_client.upsert_entity(session_entity)
            
            try:
                logging.info("Saving message into table with same session_id")
                save_message_to_table(session_id, user_message, agent_response, json.dumps(all_source_document_metadata) or None)
            except Exception as e:
                logging.error(f"Unable to save message in storage \n{e}")
            
        logging.info(f'ChatGPT response retrieved successfully for licence key {licence_key}')
        return {
            "response": agent_response,
            "metadata": all_source_document_metadata
                }, 202

    except Exception as e:
        logging.error(f'Failed to get response from ChatGPT: {str(e)}')
        return {'error': f"Failed to get response from ChatGPT: {str(e)}"}, 500