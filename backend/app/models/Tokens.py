from sqlmodel import SQLModel, Field
from app.models.Users import User
from datetime import datetime
from pydantic import ConfigDict

class Token(SQLModel):
    access_token: str
    token_type: str
    refresh_token: str | None = None

    model_config = ConfigDict(from_attributes=True)