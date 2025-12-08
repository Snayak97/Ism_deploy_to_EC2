import redis
from app.config import Config

JWT_ID_EXPIRY =Config.JWT_ID_EXPIRY

token_blocklist = redis.StrictRedis(
    host=Config.REDIS_HOST,
    port=Config.REDIS_PORT,
    db=Config.REDIS_DB,
    decode_responses=True
)

def add_jwt_id_to_blocklist(jwt_id:str)->None:
    token_blocklist.set(name = jwt_id, value="", ex = JWT_ID_EXPIRY)

def token_in_blocklist(jwt_id:str)->None:
    jwt_id= token_blocklist.get(jwt_id)
    return jwt_id is not None

