from sqlmodel import SQLModel, Field, Column, Relationship, JSON
from typing import Optional, List

class UserBase(SQLModel):
    username: str = Field(index=True, unique=True)
    email: str = Field(unique=True)

class User(UserBase, table=True):
    id: int | None = Field(default= None, primary_key=True)
    hashed_password: str = Field()
    email_blind_index: str

    totp_secret: str | None = Field(default=None)
    is_totp_enabled: bool = Field(default=False)
    backup_codes: list[str] | None = Field(default=None, sa_column=Column(JSON))
    
    api_keys: List["APIKey"] = Relationship(back_populates="owner")

class UserCreate(UserBase):
    plain_password: str

class UserRead(UserBase):
    pass

class UserUpdate(SQLModel):
    username: Optional[str] = None
    plain_password: Optional[str] = None