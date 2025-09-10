from jose import jwt
from datetime import datetime, timedelta,timezone
from passlib.context import CryptContext
from dotenv import load_dotenv
import os

load_dotenv()

Secret_Key = os.getenv("SECRET_KEY")
Algorithm = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(username:str):
    expire = datetime.now(timezone.utc) + timedelta(minutes=30)
    data = {"sub": username, "exp": int(expire.timestamp())}
    return jwt.encode(data, Secret_Key, algorithm=Algorithm)

def verify_token(token:str):
    try:
        return jwt.decode(token, Secret_Key, algorithms=Algorithm)
    except:
        return None
    
def hash_password(password:str):
    return pwd_context.hash(password)

def verify_password(password:str, hashed_password:str):
    return pwd_context.verify(password, hashed_password)