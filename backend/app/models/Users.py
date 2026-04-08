from typing import TYPE_CHECKING, List, Optional

from pydantic import EmailStr, field_validator
from sqlmodel import JSON, Column, Field, Relationship, SQLModel

if TYPE_CHECKING:
    from .APIKeys import APIKey

USERNAME_PATTERN = r"^[a-zA-Z0-9_\-]+$"

def validate_password_strength(v: str) -> str:
    if not v:
        return v
    if len(v) < 8:
        raise ValueError("Hasło musi mieć co najmniej 8 znaków")
    if not any(c.isupper() for c in v):
        raise ValueError("Hasło musi posiadać przynajmniej jedną dużą literę")
    if not any(c.islower() for c in v):
        raise ValueError("Hasło musi posiadać przynajmniej jedną małą literę")
    if not any(c.isdigit() for c in v):
        raise ValueError("Hasło musi posiadać przynajmniej jedną cyfrę")
    if not any(not c.isalnum() for c in v):
        raise ValueError("Hasło musi posiadać przynajmniej jeden znak specjalny")
    return v

class UserBase(SQLModel):
    username: str = Field(index=True, unique=True, min_length=3, max_length=40, regex=USERNAME_PATTERN)
    email: EmailStr = Field(unique=True)

class User(UserBase, table=True):
    id: int | None = Field(default= None, primary_key=True)
    is_superuser: bool = Field(default = False)
    is_activated: bool = Field(default = False)
    
    hashed_password: str = Field()
    email_blind_index: str

    totp_secret: str | None = Field(default=None)
    is_totp_enabled: bool = Field(default=False)
    backup_codes: list[str] | None = Field(default=None, sa_column=Column(JSON))
    
    api_keys: List["APIKey"] = Relationship(back_populates="owner")

class UserCreate(UserBase):
    plain_password: str

    @field_validator("plain_password")
    @classmethod
    def check_password(cls, v):
        return validate_password_strength(v)

class UserRead(UserBase):
    id: int
    is_superuser: bool
    is_activated: bool
    is_totp_enabled: bool

class UserUpdate(SQLModel):
    username: Optional[str] = Field(default=None, min_length=3, max_length=40, regex=USERNAME_PATTERN)
    plain_password: Optional[str] = None

    @field_validator("plain_password")
    @classmethod
    def check_password(cls, v):
        if v is not None:
            return validate_password_strength(v)
        return v

class NewPasswordModel(SQLModel):
    plain_password: str

    @field_validator("plain_password")
    @classmethod
    def check_password(cls, v):
        return validate_password_strength(v)