from enum import Enum

from pydantic import ConfigDict
from sqlmodel import SQLModel


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