from sqlmodel import SQLModel, Field, Column, Relationship
from app.models.Users import User
from datetime import datetime, timezone
from pydantic import ConfigDict

from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field, Relationship

class APIKey(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    
    name: str = Field(nullable=False)
    
    hashed_key: str = Field(unique=True, index=True, nullable=False)
    key_hint: str
    
    created_at: datetime = Field(default_factory=datetime.now(timezone.utc))
    last_used_at: Optional[datetime] = Field(default=None)
    
    user_id: int = Field(foreign_key="user.id")
    owner: Optional["User"] = Relationship(back_populates="api_keys")