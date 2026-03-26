from app.core.auth.apikeys import get_user_by_api_key
from app.core.db import db_session
from app.models.Users import User
from app.core.config import settings
from app.core.auth.utils import get_blind_index
from fastapi import Depends, HTTPException, status
from jose import jwt, JWTError
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from typing import Annotated, Optional
from sqlmodel import select

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_user_by_username(session: db_session, username: str) -> User | None:
    result = await session.exec(select(User).where(User.username == username))
    user = result.one_or_none()
    return user

async def get_user_by_email(session: db_session, email: str) -> Optional[User]:
    blind_index = get_blind_index(email)
    result = await session.exec(select(User).where(User.email_blind_index == blind_index))
    return result.one_or_none()

async def get_current_active_user( session: db_session, token: Optional[str] = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, 
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
            
    if token:
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM], audience=settings.APP_NAME + "-api")
            username: str = payload.get("sub")
            if username is None:
                raise credentials_exception
            user = await get_user_by_username(session, username)
            if user:
                return user
        except JWTError:
            pass
            
    print(f"Exception! Token was {token}"); raise credentials_exception

async def get_current_user( session: db_session, token: Optional[str] = Depends(oauth2_scheme), api_key: Optional[str] = Depends(api_key_header)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, 
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if api_key:
        user = await get_user_by_api_key(session, api_key)
        if user:
            return user
            
    return await get_current_active_user(session, token)

async def get_current_admin_user(current_user: User = Depends(get_current_active_user)) -> User:
    if not current_user.is_superuser: 
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Brak wystarczających uprawnień (Wymagany Admin)"
        )
    return current_user


async def verify_user_ownership_or_admin(
    user_id: int, # FastAPI automatycznie wstrzygnie to z adresu URL (np. z /users/{user_id})!
    current_user: User = Depends(get_current_active_user)
) -> User:
    
    if current_user.id != user_id and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Możesz zarządzać tylko swoimi zasobami."
        )
    return current_user

current_user = Annotated[User, Depends(get_current_user)]
current_active_user = Annotated[User, Depends(get_current_active_user)]
current_admin_user = Annotated[User, Depends(get_current_admin_user)]
owner_or_admin = Annotated[User, Depends(verify_user_ownership_or_admin)]