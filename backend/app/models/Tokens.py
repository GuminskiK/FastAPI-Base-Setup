from sqlmodel import SQLModel
from pydantic import ConfigDict
from enum import Enum

class TokenTypes(str, Enum):
    ACCESS = "access"
    REFRESH = "refresh"
    ACTIVATE = "activate"
    CHANGE_PASSWORD = "change_password"

class Token(SQLModel):
    access_token: str
    token_type: str
    refresh_token: str | None = None

    model_config = ConfigDict(from_attributes=True)