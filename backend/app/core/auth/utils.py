import hashlib

from app.core.config import settings

SECRET_KEY = settings.SECRET_KEY

def get_blind_index(data: str) -> str:
    return hashlib.sha256(f"{SECRET_KEY}{data}".encode()).hexdigest()