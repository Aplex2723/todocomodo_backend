import bcrypt
import jwt
import datetime
from .config import Config

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_token(user_id):
    return jwt.encode(
        {'user_id': user_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
        Config.SECRET_KEY,
        algorithm='HS256'
    )

def find_user(identifier, table_client):
    # Intentar buscar por nombre de usuario
    try:
        return table_client.get_entity(partition_key='users', row_key=identifier)
    except:
        # Intentar buscar por correo electrónico si no se encontró por nombre de usuario
        users = list(table_client.query_entities(f"PartitionKey eq 'users' and email eq '{identifier}'"))
        if users:
            return users[0]
        else:
            return None