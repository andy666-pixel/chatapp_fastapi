from typing import Optional
from fastapi import APIRouter
from sqlmodel import Field, SQLModel

router = APIRouter()



class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)  
    email: str = Field(index=True, unique=True)
    hashed_password: str
    disabled: bool = Field(default=False)
    is_online: bool = Field(default=False)


