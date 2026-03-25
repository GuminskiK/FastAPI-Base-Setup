from sqlmodel import SQLModel, Field
from typing import Optional

class UserBase(SQLModel):
    username: str = Field(index=True, unique=True)

class User(UserBase, table=True):
    id: int | None = Field(default= None, primary_key=True)
    plain_password: str = Field()

class UserCreate(UserBase):
    plain_password: str

class UserRead(UserBase):
    pass

class UserUpdate(SQLModel):
    username: Optional[str] = None
    plain_password: Optional[str] = None