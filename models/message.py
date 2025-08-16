from datetime import datetime
from fastapi import APIRouter
from sqlmodel import Field, SQLModel
from fastapi import APIRouter

router = APIRouter()


class Message(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    content: str
    sender_id: int 
    receiver_id: int 
    timestamp: datetime.date
